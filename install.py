#!/usr/bin/env python3
"""Verify and install broker code into a new prefix; never provision or restart services."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
VERSION = "0.6.0"
FILES = frozenset({"broker.py", "client.py", "generic_api.py", "google_client.py",
                   "google_migration.py", "google_search_console.py", "workspace_google.py"})


def capture(root=ROOT):
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("version") != VERSION or set(manifest.get("files", {})) != FILES:
        raise ValueError("Unexpected installation manifest.")
    payloads = {}
    for name in sorted(FILES):
        source = root / "src" / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("Source differs from the reviewed manifest.")
        payload = source.read_bytes()
        if hashlib.sha256(payload).hexdigest() != manifest["files"][name]:
            raise ValueError("Source differs from the reviewed manifest.")
        compile(payload, name, "exec")
        payloads[name] = payload
    return payloads


def verify(prefix, root=ROOT):
    # A fresh prefix prevents an accidental upgrade or shared-service restart.
    # Versioned prefixes allow an operator-controlled rollback.
    if not prefix.is_absolute() or prefix.exists() or prefix.is_symlink():
        raise ValueError("Choose a new absolute installation prefix.")
    if not prefix.parent.is_dir() or prefix.parent.resolve() != prefix.parent:
        raise ValueError("Use an existing canonical parent directory.")
    return capture(root)


def launcher(module):
    return ("#!/usr/bin/env python3\n"
            "from pathlib import Path\nimport sys\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib' / 'openbao-project-broker'))\n"
            f"from {module} import main\n"
            "sys.exit(main())\n").encode()


def install(prefix, root=ROOT):
    payloads = verify(prefix, root)
    prefix.mkdir(mode=0o755)  # Exclusive: never take over an existing directory.
    directories, files = [prefix], []
    try:
        prefix.chmod(0o755)
        for relative in ("lib", "lib/openbao-project-broker", "bin"):
            path = prefix / relative
            path.mkdir(mode=0o755)
            directories.append(path)
            path.chmod(0o755)
        output = {"lib/openbao-project-broker/" + name: (payload, 0o644)
                  for name, payload in payloads.items()}
        output.update({"bin/project-access": (launcher("client"), 0o755),
                       "bin/project-broker": (launcher("broker"), 0o755)})
        for relative, (payload, mode) in output.items():
            path = prefix / relative
            with path.open("xb") as stream:
                files.append(path)
                stream.write(payload)
                os.fchmod(stream.fileno(), mode)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for path in reversed(files):
            path.unlink()
        for path in reversed(directories):
            path.rmdir()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--install", action="store_true", help="Write code after verification; default is read-only")
    args = parser.parse_args(argv)
    try:
        if args.install:
            install(args.prefix)
            print("Broker code installed. Configure OpenBao enrollment and the service before use.")
        else:
            verify(args.prefix)
            print("Source verified; new installation prefix available. No changes made.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, SyntaxError):
        print("Installation stopped: check the source manifest and new prefix; existing installs are never overwritten.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
