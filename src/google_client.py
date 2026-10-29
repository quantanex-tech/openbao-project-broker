"""Client-side Google data transport; receives no OAuth or OpenBao credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

SOCKET = os.environ.get("PROJECT_ACCESS_SOCKET", "")
MAX_BODY = 210 * 1024 * 1024


class GoogleError(Exception):
    def __init__(self, error):
        self.error = error
        super().__init__(error.get("message", "Google broker operation failed."))


def call(project, credential, operation, params=None, body=b"", socket_path=SOCKET):
    """Never retry a write: callers must durably journal then reconcile uncertainty."""
    if not socket_path:
        raise GoogleError({"code": "configuration_required", "message": "Set PROJECT_ACCESS_SOCKET to the operator-provided broker socket."})
    request = {"action": "google_transfer", "project": project, "credential": credential,
               "operation": operation, "params": params or {}, "body_bytes": len(body)}
    encoded = json.dumps(request).encode() + b"\n"
    if len(encoded) > 1024 * 1024 or len(body) > MAX_BODY:
        raise GoogleError({"code": "request_too_large", "message": "The Google request exceeded the transport limit."})
    def header(stream):
        line = stream.readline(65537)
        if not line.endswith(b"\n") or len(line) > 65536:
            raise ValueError()
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError()
        if not value.get("ok"):
            raise GoogleError(value.get("error", {}))
        return value
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(300)
            connection.connect(socket_path)
            connection.sendall(encoded)
            with connection.makefile("rb") as stream:
                ready = header(stream)
                if ready.get("ready") is not True:
                    raise ValueError()
                if body:
                    connection.sendall(body)
                result = header(stream)["result"]
                size = result.get("body_bytes")
                if type(size) is not int or not 0 <= size <= MAX_BODY:
                    raise ValueError()
                payload = stream.read(size)
                if len(payload) != size or hashlib.sha256(payload).hexdigest() != result.get("sha256"):
                    raise ValueError()
                return result, payload
    except GoogleError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise GoogleError({"code": "google_transport_uncertain", "message": "The broker transfer did not complete reliably. Reconcile writes before retrying."}) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--credential", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--params", type=json.loads, default={})
    parser.add_argument("--body-file", type=Path)
    parser.add_argument("--output", type=Path, help="Save response bytes privately; only metadata is printed.")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        output = args.output.open("xb") if args.output else None
        try:
            if args.body_file and args.body_file.stat().st_size > MAX_BODY:
                raise GoogleError({"code": "request_too_large", "message": "The request file is too large."})
            body = args.body_file.read_bytes() if args.body_file else b""
            meta, payload = call(args.project, args.credential, args.operation, args.params, body)
            if output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
                result = {"ok": True, "result": meta, "output": str(args.output)}
            elif len(payload) <= 2 * 1024 * 1024 and args.operation != "storage_download":
                result = {"ok": True, "result": {**meta, "data": json.loads(payload)}}
            else:
                result = {"ok": True, "result": meta, "notice": "Use --output to preserve the response payload."}
        finally:
            if output:
                output.close()
    except GoogleError as error:
        result = {"ok": False, "error": error.error}
    except (OSError, ValueError):
        result = {"ok": False, "error": {"code": "local_io_error", "message": "The local input/output operation failed. Reconcile writes before retrying."}}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
