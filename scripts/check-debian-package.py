"""Check the freshly built Debian artifact without installing or extracting it."""

from email.parser import Parser
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    repository = Path(__file__).resolve().parent.parent
    distribution = repository / "dist"
    artifacts = []
    for suffix in ("deb", "buildinfo", "changes"):
        candidates = sorted(distribution.glob(f"pkimaster_*.{suffix}"))
        require(len(candidates) == 1, f"Expected exactly one .{suffix} artifact in dist; found {len(candidates)}.")
        artifacts.extend(candidates)
    package = artifacts[0]
    version = subprocess.check_output(["dpkg-parsechangelog", "--show-field", "Version"], cwd=repository, text=True).strip()
    require(package.name == f"pkimaster_{version}_all.deb", "Package filename does not match the Debian changelog.")
    metadata = Parser().parsestr(subprocess.check_output(["dpkg-deb", "--field", str(package)], text=True))
    for name, expected in {
        "Package": "pkimaster",
        "Version": version,
        "Architecture": "all",
        "Maintainer": "PKIMaster maintainers <maintainers@pkimaster.de>",
    }.items():
        require(metadata.get(name) == expected, f"Unexpected {name} field: {metadata.get(name)!r}.")
        print(f"{name}: {metadata[name]}")

    archive_bytes = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
    with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as archive:
        members = {str(PurePosixPath(member.name)): member for member in archive.getmembers()}
    required_files = {
        "usr/lib/pkimaster/app.py", "usr/lib/pkimaster/enterprise.py", "usr/lib/pkimaster/mfa.py",
        "usr/lib/pkimaster/pki.py", "usr/lib/pkimaster/pkimaster_server.py",
        "usr/lib/pkimaster/identity.py", "usr/lib/pkimaster/key_backends.py",
        "usr/lib/pkimaster/key_storage.py", "usr/lib/pkimaster/audit_integrity.py", "usr/lib/pkimaster/security.py",
        "usr/lib/pkimaster/static/css/console.css",
        "usr/lib/pkimaster/static/js/console.js",
        "usr/lib/pkimaster/templates/base.html", "usr/lib/pkimaster/templates/index.html",
        "usr/lib/pkimaster/templates/setup.html", "usr/lib/pkimaster/templates/login.html",
        "usr/lib/pkimaster/templates/settings.html", "usr/lib/systemd/system/pkimaster.service",
    }
    for name in required_files:
        require(name in members, f"Required package file is missing: {name}.")
        member = members[name]
        require(member.isfile() and member.mode == 0o644, f"Unexpected file type or permissions: {name}.")
    for name, member in members.items():
        require(member.uid == 0 and member.gid == 0, f"Package member must be owned by root: {name}.")
        parts = PurePosixPath(name).parts
        require(".." not in parts and not PurePosixPath(name).is_absolute(), f"Invalid package path: {name}.")
        require(not {"instance", ".git", ".venv", "__pycache__"}.intersection(parts), f"Local development state must not be packaged: {name}.")
        require(not name.startswith("var/lib/pkimaster/"), "An installation must never ship pre-generated PKI state.")
        require(not name.endswith((".pem", ".sqlite", "runtime-secrets.json")), f"Key material or runtime data must not be packaged: {name}.")

    checksums = []
    for artifact in artifacts:
        checksums.append(f"{hashlib.sha256(artifact.read_bytes()).hexdigest()}  {artifact.name}\n")
    (distribution / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    print("Required files, root ownership, file permissions and absence of runtime secrets verified.")
    print("SHA256SUMS covers the package, buildinfo and changes artifacts.")
    if output_path := os.environ.get("GITHUB_OUTPUT"):
        with Path(output_path).open("a", encoding="utf-8") as output:
            output.write(f"package={package}\nversion={version}\n")


if __name__ == "__main__":
    main()
