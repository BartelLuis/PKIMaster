#!/usr/bin/env python3
"""Check built archives and smoke-test a normal wheel installation outside checkout.

Run after ``python -m build``. The helper uses the standard library, creates a
disposable virtual environment, and installs the wheel's declared dependencies
there with pip. Network access may be required. For offline local checks,
--reuse-dependencies reuses dependencies already installed in the base Python;
the application wheel is still installed into its own disposable environment.
"""

from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile


ROOT = Path(__file__).resolve().parent.parent
APPLICATION_MODULES = {"app", "enterprise", "identity", "mfa", "pki", "key_backends", "key_storage", "audit_integrity", "security", "publication", "publication_transports", "publication_worker", "pkimaster_server", "wsgi"}
APPLICATION_MODULES |= {"backup", "renewal", "monitoring", "monitoring_transports", "monitoring_worker"}
APPLICATION_MODULES |= {"certificate_profiles", "inventory", "tls_monitoring", "automation", "automation_worker", "acme_service"}
PUBLICATION_SOURCE_FILES = {"docs/PUBLICATION.md", "debian/pkimaster-publication.service", "debian/pkimaster-publication.timer"}
PUBLICATION_SOURCE_FILES |= {"docs/BACKUP.md", "docs/MONITORING.md", "debian/pkimaster-monitoring.service", "debian/pkimaster-monitoring.timer"}
PUBLICATION_SOURCE_FILES |= {"docs/AUTOMATION.md", "docs/ACME.md", "debian/pkimaster-automation.service", "debian/pkimaster-automation.timer"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def one_artifact(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    require(len(matches) == 1, f"Expected one {pattern} in {directory}; found {len(matches)}. Build into a clean artifact directory.")
    return matches[0].resolve()


def check_metadata(raw: bytes, project: dict, artifact: str) -> None:
    metadata = BytesParser(policy=policy.default).parsebytes(raw)
    for field in ("Name", "Version", "Requires-Python"):
        expected = project[{"Name": "name", "Version": "version", "Requires-Python": "requires-python"}[field]]
        require(metadata.get(field) == expected, f"{artifact}: {field} does not match pyproject.toml.")
    expected_emails = {item["email"] for item in project.get("maintainers", []) if "email" in item}
    actual_emails = {email for _, email in getaddresses(metadata.get_all("Maintainer-email", []))}
    require(expected_emails <= actual_emails, f"{artifact}: maintainer email metadata is incomplete.")
    project_urls = set(metadata.get_all("Project-URL", []))
    for label, url in project.get("urls", {}).items():
        require(f"{label}, {url}" in project_urls, f"{artifact}: missing project URL {label}.")


def check_archives(wheel: Path, sdist: Path, configuration: dict) -> tuple[list[str], list[str]]:
    modules = set(configuration["tool"]["setuptools"].get("py-modules", []))
    require(APPLICATION_MODULES <= modules, "The packaging configuration omits an application module.")
    template_paths = sorted((ROOT / "templates").rglob("*.html"))
    require(bool(template_paths), "No source templates found.")
    templates = [path.relative_to(ROOT / "templates").as_posix() for path in template_paths]
    require("publication.html" in templates, "The publication configuration template is missing.")
    module_files = {module.replace(".", "/") + ".py" for module in modules}
    expected_files = module_files | {"templates/" + name for name in templates}
    expected_files |= {path.relative_to(ROOT).as_posix() for path in (ROOT / "static").rglob("*") if path.is_file()}

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata_files = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata_files) == 1, f"{wheel.name}: expected one distribution metadata file.")
        check_metadata(archive.read(metadata_files[0]), configuration["project"], wheel.name)
        distribution_prefix = metadata_files[0].removesuffix(".dist-info/METADATA")
        for source_name in sorted(expected_files):
            archive_name = source_name
            if source_name.startswith(("templates/", "static/")):
                archive_name = distribution_prefix + ".data/data/share/pkimaster/" + source_name
            require(archive_name in names, f"{wheel.name}: missing {source_name}.")
            require(archive.read(archive_name) == (ROOT / source_name).read_bytes(),
                    f"{wheel.name}: {source_name} differs from the current source; rebuild the artifacts.")

    with tarfile.open(sdist, "r:gz") as archive:
        files = {member.name: member for member in archive.getmembers() if member.isfile()}
        roots = {Path(name).parts[0] for name in files}
        require(len(roots) == 1, f"{sdist.name}: source files must share one archive root.")
        prefix = next(iter(roots)) + "/"
        metadata_file = files.get(prefix + "PKG-INFO")
        require(metadata_file is not None, f"{sdist.name}: missing top-level PKG-INFO.")
        with archive.extractfile(metadata_file) as source:
            check_metadata(source.read(), configuration["project"], sdist.name)
        for source_name in sorted(expected_files | PUBLICATION_SOURCE_FILES | {"pyproject.toml", "MANIFEST.in", "README.md", "scripts/check-python-artifacts.py"}):
            member = files.get(prefix + source_name)
            require(member is not None, f"{sdist.name}: missing {source_name}.")
            with archive.extractfile(member) as source:
                require(source.read() == (ROOT / source_name).read_bytes(),
                        f"{sdist.name}: {source_name} differs from the current source; rebuild the artifacts.")
    print(f"Verified modules, templates, and metadata in {wheel.name} and {sdist.name}.", flush=True)
    return sorted(modules), templates


INSTALLED_SMOKE = r'''
import importlib.metadata
import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
import sys
import sysconfig

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

source_root = Path(sys.argv[1]).resolve()
instance_path = Path(sys.argv[2]).resolve()
expected_version = sys.argv[3]
modules = json.loads(sys.argv[4])
templates = json.loads(sys.argv[5])
prefix = Path(sys.prefix).resolve()
site_packages = Path(sysconfig.get_paths()["purelib"]).resolve()
require(not Path.cwd().resolve().is_relative_to(source_root), "Smoke-test directory is inside the checkout.")
require(sys.prefix != sys.base_prefix, "The smoke test is not running in a virtual environment.")
for name in modules:
    # Locate wsgi without importing it: its module-level app uses a default state directory.
    spec = importlib.util.find_spec(name)
    require(spec is not None and spec.origin is not None, "Installed module missing: " + name)
    location = Path(spec.origin).resolve()
    require(location.is_relative_to(site_packages), "Module did not load from the new installation: " + name)
    require(not location.is_relative_to(source_root), "Module resolved to the checkout: " + name)

distribution = importlib.metadata.distribution("pkimaster")
require(distribution.version == expected_version, "Installed distribution version is incorrect.")
require(any(entry.group == "console_scripts" and entry.name == "pkimaster-dev" and entry.value == "app:main"
            for entry in distribution.entry_points), "Installed developer command is missing.")

from app import create_app
application = create_app({"TESTING": True, "INSTANCE_PATH": str(instance_path)})
template_root = Path(application.template_folder).resolve()
require(template_root == prefix / "share" / "pkimaster" / "templates", "Application did not use its installed templates.")
for name in templates:
    with application.app_context():
        application.jinja_env.get_template(name)

class SetupForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.form = False
        self.fields = set()
        self.csrf = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("method", "").lower() == "post" and attrs.get("action") == "/setup":
            self.form = True
        if tag == "input":
            self.fields.add(attrs.get("name"))
            if attrs.get("name") == "csrf_token" and attrs.get("value"):
                self.csrf = True

response = application.test_client().get("/setup", base_url="https://localhost")
require(response.status_code == 200, "Installed setup page did not return HTTP 200.")
for asset in ("css/console.css", "js/console.js"):
    asset_response = application.test_client().get("/static/" + asset, base_url="https://localhost")
    require(asset_response.status_code == 200 and asset_response.data, "Installed console asset missing: " + asset)
form = SetupForm()
form.feed(response.get_data(as_text=True))
require(form.form and form.csrf and {"organization", "username", "password", "password_confirm"} <= form.fields,
        "Installed setup page is missing its administrator form or CSRF token.")
secrets_path = instance_path / "runtime-secrets.json"
require(secrets_path.is_file(), "Installation secrets were not provisioned.")
secrets = json.loads(secrets_path.read_text(encoding="utf-8"))
require(all(isinstance(secrets.get(key), str) and len(secrets[key]) >= 32
            for key in ("SECRET_KEY", "KEY_ENCRYPTION_SECRET")), "Generated installation secrets are incomplete.")
require(secrets["SECRET_KEY"] != secrets["KEY_ENCRYPTION_SECRET"], "Installation secrets must be independent.")
require((instance_path / "pkimaster.sqlite").is_file(), "Installed application database was not created.")
require(not (site_packages / "instance").exists(), "Application created state in site-packages instead of the supplied instance directory.")
print("Installed wheel imports, templates, setup form, and secret provisioning passed.", flush=True)
'''


def smoke_installed_wheel(wheel: Path, version: str, modules: list[str], templates: list[str], *, reuse_dependencies: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="pkimaster-python-artifacts-") as temporary:
        directory = Path(temporary).resolve()
        require(not directory.is_relative_to(ROOT), "The temporary directory must be outside the source checkout.")
        environment = directory / "venv"
        print("Creating a disposable environment for the wheel installation.", flush=True)
        venv.EnvBuilder(with_pip=True, system_site_packages=reuse_dependencies).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        # Ignore installer configuration and environment overrides that could
        # redirect package installation away from this disposable environment.
        subprocess_environment = {key: value for key, value in os.environ.items()
                                  if not key.upper().startswith(("PIP_", "PYTHON"))}
        subprocess_environment["PIP_CONFIG_FILE"] = os.devnull
        install_options = ["--no-index", "--no-deps", "--ignore-installed"] if reuse_dependencies else []
        subprocess.run([
            str(python), "-I", "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
            "--no-cache-dir", "--prefix", str(environment), *install_options, str(wheel),
        ], cwd=directory, env=subprocess_environment, check=True, timeout=300)
        subprocess.run([
            str(python), "-I", "-c", INSTALLED_SMOKE, str(ROOT), str(directory / "instance"), version,
            json.dumps(modules), json.dumps(templates),
        ], cwd=directory, env=subprocess_environment, check=True, timeout=60)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist", help="Directory containing one wheel and source archive.")
    parser.add_argument("--reuse-dependencies", action="store_true",
                        help="Reuse base Python dependencies for an offline smoke test; the wheel remains installed in a temporary venv.")
    arguments = parser.parse_args()
    try:
        configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        wheel = one_artifact(arguments.dist, "pkimaster-*.whl")
        sdist = one_artifact(arguments.dist, "pkimaster-*.tar.gz")
        modules, templates = check_archives(wheel, sdist, configuration)
        smoke_installed_wheel(wheel, configuration["project"]["version"], modules, templates,
                              reuse_dependencies=arguments.reuse_dependencies)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, tarfile.TarError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"Python artifact verification failed: {error}", file=sys.stderr)
        return 1
    print("Python distribution verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
