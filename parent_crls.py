"""Discover and retrieve authenticated full parent CRLs from certificate CDPs."""
from __future__ import annotations

import time

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

import monitoring_transports


MAX_PARENTS = 8
MAX_SOURCES_PER_PARENT = 3
MAX_FETCH_SECONDS = 120
_REVOKED = "The CA or an ancestor is revoked in its issuer's CRL."


class ParentCRLError(ValueError):
    """A safe diagnostic without remote response content or embedded URLs."""


def _chain(authority):
    try:
        certificates = x509.load_pem_x509_certificates(authority["certificate_pem"].encode())
        parents = x509.load_pem_x509_certificates(authority["parent_chain_pem"].encode())
    except (KeyError, TypeError, AttributeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ParentCRLError("Import a signed CA certificate and its parent chain before retrieving parent CRLs.") from exc
    if len(certificates) != 1 or not parents:
        raise ParentCRLError("Parent CRL retrieval requires one local CA certificate and its parent chain.")
    if len(parents) > MAX_PARENTS:
        raise ParentCRLError("Parent CRL retrieval supports at most eight parent CAs.")
    return certificates + parents


def _sources(sources, parent_count):
    if not isinstance(sources, list) or len(sources) != parent_count:
        raise ParentCRLError("Provide one parent CRL source group per issuer, ordered immediate issuer to root.")
    result = []
    for index, alternatives in enumerate(sources, 1):
        if not isinstance(alternatives, list) or not alternatives:
            raise ParentCRLError(f"Parent CRL {index} needs at least one HTTP(S) source.")
        unique = []
        for url in alternatives:
            if not isinstance(url, str):
                raise ParentCRLError(f"Parent CRL {index} sources must be HTTP(S) URLs without credentials or fragments.")
            try:
                monitoring_transports.validate_url(url)
            except monitoring_transports.MonitoringError as exc:
                raise ParentCRLError(f"Parent CRL {index} sources must be HTTP(S) URLs without credentials or fragments.") from exc
            if url not in unique:
                unique.append(url)
            if len(unique) > MAX_SOURCES_PER_PARENT:
                raise ParentCRLError(f"Parent CRL {index} has more than three alternative sources.")
        result.append(unique)
    return result


def parent_crl_sources(authority) -> list[list[str]]:
    """Read each child's CDP for its issuer's CRL; discovery never uses the network.

    Only full, direct distribution points are usable. Other mechanisms (such as
    LDAP), reason partitions and indirect points are ignored if a supported
    HTTP(S) point is available. The root certificate's own CDP is not relevant.
    """
    chain = _chain(authority)
    sources = []
    for index, child in enumerate(chain[:-1], 1):
        try:
            points = child.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        except x509.ExtensionNotFound as exc:
            raise ParentCRLError(f"The certificate for parent CRL {index} has no CRL distribution points. Configure an explicit URL or import a CRL bundle.") from exc
        except (ValueError, x509.DuplicateExtension, UnsupportedAlgorithm) as exc:
            raise ParentCRLError(f"The certificate for parent CRL {index} has invalid CRL distribution points.") from exc
        urls = []
        for point in points:
            if point.reasons is not None or point.crl_issuer is not None or point.relative_name is not None or not point.full_name:
                continue
            for name in point.full_name:
                if not isinstance(name, x509.UniformResourceIdentifier):
                    continue
                try:
                    monitoring_transports.validate_url(name.value)
                except monitoring_transports.MonitoringError:
                    continue
                if name.value not in urls:
                    urls.append(name.value)
                if len(urls) > MAX_SOURCES_PER_PARENT:
                    raise ParentCRLError(f"Parent CRL {index} has more than three alternative sources. Configure explicit URLs or import a CRL bundle.")
        if not urls:
            raise ParentCRLError(f"The certificate for parent CRL {index} has no supported full, direct HTTP(S) CRL distribution point. Configure an explicit URL or import a CRL bundle.")
        sources.append(urls)
    return sources


def _pem_crl(content):
    from app import split_pem_crl_blocks

    if not isinstance(content, bytes) or not content or len(content) > monitoring_transports.MAX_DOWNLOAD:
        raise ParentCRLError("A parent CRL download is empty or exceeds the 4 MiB limit.")
    try:
        if content.lstrip().startswith(b"-----BEGIN"):
            blocks = split_pem_crl_blocks(content.decode("ascii"))
            if len(blocks) != 1:
                raise ValueError
            crl = x509.load_pem_x509_crl(blocks[0].encode("ascii"))
        else:
            crl = x509.load_der_x509_crl(content)
            if crl.public_bytes(serialization.Encoding.DER) != content:
                raise ValueError
        return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ParentCRLError("A parent CRL source must return exactly one DER- or PEM-encoded CRL.") from exc


def _validate(authority, pem):
    from app import validate_parent_crls

    try:
        return validate_parent_crls(authority, pem)
    except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension, UnsupportedAlgorithm) as exc:
        # The validator raises this only after authenticating the complete bundle.
        # Retain authenticated revocations so apply_parent_crls can disable the CA;
        # trying a different mirror here could hide a known revocation.
        if str(exc) == _REVOKED:
            return pem
        raise ParentCRLError("The downloaded parent CRL bundle failed validation. Check parent CA validity and provide current, signed full CRLs.") from exc


def fetch_parent_crls(authority, sources: list[list[str]] | None = None) -> str:
    """Fetch a complete, canonical PEM bundle without changing persisted state.

    Explicit source groups may be used for certificates without CDPs. Every
    candidate is verified against its immediate issuer before a fallback is
    selected; the complete bundle is checked again before being returned.
    """
    deadline = time.monotonic() + MAX_FETCH_SECONDS
    chain = _chain(authority)
    groups = _sources(parent_crl_sources(authority) if sources is None else sources, len(chain) - 1)
    crls = []
    for index, (child, parent, alternatives) in enumerate(zip(chain, chain[1:], groups), 1):
        pair = {"certificate_pem": child.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "parent_chain_pem": parent.public_bytes(serialization.Encoding.PEM).decode("ascii")}
        for url in alternatives:
            if time.monotonic() >= deadline:
                raise ParentCRLError("Parent CRL retrieval exceeded its overall time limit. Retry later or import a CRL bundle.")
            try:
                content = monitoring_transports.http_request(url, limit=monitoring_transports.MAX_DOWNLOAD)
            except monitoring_transports.MonitoringError as exc:
                last_error = exc
                continue
            if time.monotonic() >= deadline:
                raise ParentCRLError("Parent CRL retrieval exceeded its overall time limit. Retry later or import a CRL bundle.")
            try:
                crls.append(_validate(pair, _pem_crl(content)))
                break
            except (ParentCRLError, UnsupportedAlgorithm) as exc:
                last_error = exc
        else:
            raise ParentCRLError(f"No current, correctly signed full CRL could be retrieved for parent {index}. Check its sources and published CRL.") from last_error
    return _validate(authority, "".join(crls))
