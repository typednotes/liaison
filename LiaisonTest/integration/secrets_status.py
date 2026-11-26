#!/usr/bin/env python3
"""Exercise the credential dashboard using local store fixtures."""

import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from threading import Thread
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from connectors import port


PASSWORD = "dashboard-fixture-password"
CREDENTIAL_PATH = "thirdparty/github/owner/connection"
DUE_PATH = "thirdparty/github/owner/oauth"
STORE_TOKEN = "store-fixture-token"
SECRET_VALUE = "private-provider-fixture-value"


class Store(BaseHTTPRequestHandler):
    """Serve the list and read responses from either HTTP backend."""

    def do_GET(self):
        if self.headers.get("Authorization") == f"Bearer {STORE_TOKEN}":
            path = self.path.removeprefix("/v1/secret/")
            if path == "metadata/thirdparty/":
                return self.reply({"keys": [CREDENTIAL_PATH, CREDENTIAL_PATH, DUE_PATH,
                                            CREDENTIAL_PATH + "/permissions"]})
            if path.startswith("data/"):
                credential = self.credential(path.removeprefix("data/"))
                if credential is not None:
                    return self.reply({"data": credential})
        if self.headers.get("X-Vault-Token") == STORE_TOKEN:
            path = self.path.removeprefix("/v1/fixture/")
            listing = {
                "metadata/thirdparty/?list=true": ["github/"],
                "metadata/thirdparty/github/?list=true": ["owner/"],
                "metadata/thirdparty/github/owner/?list=true": ["connection", "connection/", "oauth"],
            }
            if path in listing:
                return self.reply({"data": {"keys": listing[path]}})
            if path.startswith("data/"):
                credential = self.credential(path.removeprefix("data/"))
                if credential is not None:
                    return self.reply({"data": {"data": credential, "metadata": {"version": 7}}})
        self.reply({}, status=404)

    @staticmethod
    def credential(path):
        if path == CREDENTIAL_PATH:
            return {"kind": "bearer", "base_url": "https://fixture.invalid", "token": SECRET_VALUE}
        if path == DUE_PATH:
            return {"kind": "gitlab_oauth", "base_url": "https://fixture.invalid",
                    "access_token": SECRET_VALUE, "refresh_token": SECRET_VALUE, "expires_at": "1"}
        return None

    def reply(self, value, status=200):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def dashboard(url, password=None):
    request = Request(url + "/_secrets")
    if password is not None:
        value = base64.b64encode(f"liaison:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {value}")
    try:
        with urlopen(request, timeout=2) as response:
            return response.status, response.headers, response.read().decode()
    except HTTPError as response:
        return response.code, response.headers, response.read().decode()


def check_backend(broker, store, backend, directory):
    index = directory / "index.json"
    index.write_text(json.dumps([CREDENTIAL_PATH]))
    env = {
        name: value for name, value in os.environ.items()
        if not name.startswith("SECRETS_") and not name.endswith(("_CLIENT_ID", "_CLIENT_SECRET"))
    }
    broker_port = port()
    env.update(
        LIAISON_PORT=str(broker_port),
        LIAISON_ROOT_KEY=secrets.token_hex(32),
        DATABASE_URL="postgresql://fixture@127.0.0.1/fixture",
        SECRETS_BACKEND=backend,
        SECRETS_HOST="127.0.0.1",
        SECRETS_PORT=str(store.server_port),
        SECRETS_TOKEN=STORE_TOKEN,
        SECRETS_INSECURE="1",
        SECRETS_MOUNT="fixture",
        SECRETS_KEYCHAIN_INDEX=str(index),
        SECRETS_KEYCHAIN_SERVICE=f"liaison-fixture-{secrets.token_hex(8)}",
        SECRETS_REFRESH_INTERVAL_SECONDS="1",
        SECRETS_STATUS_PASSWORD=PASSWORD,
    )
    url = f"http://127.0.0.1:{broker_port}"
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen([str(broker)], env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    status, headers, page = dashboard(url, PASSWORD)
                except (OSError, URLError):
                    time.sleep(.1)
                    continue
                if "Last completed scan" in page:
                    break
                time.sleep(.1)
            else:
                log.seek(0)
                raise AssertionError(f"{backend} scan did not complete: {log.read().decode()}")
            assert status == 200 and headers["Cache-Control"] == "no-store"
            assert "owner/connection" in page and "Credential status" in page
            assert SECRET_VALUE not in page and STORE_TOKEN not in page and PASSWORD not in page
            if backend == "keychain":
                assert "Unavailable" in page
            else:
                assert "Static" in page and "owner/oauth" in page and "Expired" in page
                assert "refresh failed" in page and "permissions" not in page.lower()
                assert "<dt>Credentials</dt><dd>2</dd>" in page
            for password in (None, "wrong"):
                status, headers, page = dashboard(url, password)
                assert status == 401 and "Basic" in headers["WWW-Authenticate"]
                assert "owner/connection" not in page
            print(f"PASS {backend}: private inventory, status and counts")
        finally:
            process.terminate()
            process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--broker", type=Path,
                        default=Path(__file__).resolve().parents[2] / ".lake/build/bin/liaison")
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", 0), Store) as store:
        thread = Thread(target=store.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="liaison-secrets-", dir=args.temp_root) as base:
                for backend in ("typednotes", "openbao", "keychain"):
                    check_backend(args.broker, store, backend, Path(base))
        finally:
            store.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
