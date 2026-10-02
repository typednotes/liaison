#!/usr/bin/env python3
"""Real broker/Postgres tests; all credentials, upstreams and warrants are local.

Requires initdb, pg_ctl, psql, and the built .lake/build/bin/liaison executable.
Creates its private scratch cluster only beneath --temp-root; cleans it on exit.
No dependency installation, Docker, external network, or live provider calls.
"""
import argparse
import base64
import copy
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import native_writer


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}): {result.stderr}\n{result.stdout}")
    return result.stdout


def exchange(url, value=None):
    data = None if value is None else value.encode() if isinstance(value, str) else json.dumps(value).encode()
    request = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as response:
        return response.code, json.loads(response.read())


class Mock(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def handle_call(self):
        state = self.server.state
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not state["vault"] and state.get("native"):
            state["native"](self, body)
            return
        if state["vault"]:
            state["reads"].append(self.path)
            assert self.headers["Authorization"] == "Bearer local-vault-fixture"
            if state.get("status"):
                self.reply(state["status"], {})
            elif self.path not in state["documents"]:
                self.reply(404, {})
            else:
                self.reply(200, {"data": state["documents"][self.path]})
            return
        if state.get("auth") == "s3":
            verify_sigv4(self.command, self.path, self.headers, body)
        elif state.get("auth") == "sas":
            assert self.headers.get("Authorization") is None
            assert urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)["sig"] == ["local-signature"]
        else:
            assert self.headers["Authorization"] == "Bearer local-provider-fixture"
        state["calls"].append((self.command, self.path, dict(self.headers), body))
        if state.get("provider") == "github" and not self.headers.get("User-Agent", "").strip():
            self.reply(403, {"message": "Request forbidden by administrative rules. User-Agent required."})
            return
        parsed = urllib.parse.urlparse(self.path)
        if state.get("raw") is not None:
            self.reply_bytes(200, state["raw"].encode())
        elif parsed.path == "/base/user/repos":
            self.reply(200, [{"full_name":"owner/repo","html_url":"https://github.com/owner/repo","default_branch":"main","private":True}])
        elif parsed.path == "/base/projects":
            self.reply(200, [{"path_with_namespace":"owner/repo","web_url":"https://gitlab.com/owner/repo","default_branch":"main","visibility":"private"}])
        elif parsed.path == "/base/repos/owner/repo":
            self.reply(200, {"full_name":state.get("repo_identity","owner/repo"),"html_url":"https://github.com/owner/repo","default_branch":"main"})
        elif urllib.parse.unquote(parsed.path) == "/base/projects/owner/repo":
            self.reply(200, {"path_with_namespace":state.get("repo_identity","owner/repo"),"web_url":"https://gitlab.com/owner/repo","default_branch":"main"})
        elif parsed.path.startswith("/base/gmail/v1/users/me/messages/") and self.command == "GET" and "/attachments/" not in parsed.path:
            self.reply(200, {"id": "m", "labelIds": state.get("labels", ["inbox"])})
        elif parsed.path.startswith("/base/drive/v3/files/") and parsed.query.startswith("fields="):
            self.reply(200, {"id": "file", "parents": state.get("parents", ["folder"]), "mimeType": state.get("mime", "text/plain")})
        elif self.command == "GET" and parsed.path.endswith("/events/event"):
            self.reply(200, {"attendees": state.get("attendees", [])})
        elif self.command == "GET" and parsed.path.endswith("/event.ics"):
            self.reply_bytes(200, b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:event.ics\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
        elif self.command == "GET" and "/git/trees/" in parsed.path:
            self.reply(200, {"truncated": False, "tree": [{"path": "src/file", "type": "blob", "sha": "a" * 40, "mode": "120000"}]})
        elif self.command == "GET" and "/git/blobs/" in parsed.path:
            self.reply(200, {"content": base64.b64encode(b"symlink-target-text").decode(), "encoding": "base64"})
        elif self.command == "GET" and parsed.path == "/base/databases/db":
            self.reply(200, {"id": "db", "data_sources": state.get("sources", [{"id": "source"}])})
        elif parsed.path.endswith("/2/files/get_metadata"):
            self.reply(200, {".tag": state.get("dropbox_type", "file"), "id": "id:original-file", "rev": "a123", "path_lower": "/folder/file"})
        elif self.command == "POST" and parsed.path == "/base" and b"methodCalls" in body:
            request = json.loads(body)
            method, args, ident = request["methodCalls"][0]
            if method == "Email/get":
                result = {"accountId": args["accountId"], "state": "one", "list": [{"id": "m", "mailboxIds": state.get("mailboxes", {"inbox": True}),
                    "to": [{"email": "a@example.com"}], "cc": [], "bcc": [], "attachments": [{"blobId": "blob"}]}]}
            elif method == "Mailbox/get" and args["ids"] is not None:
                result = {"accountId": args["accountId"], "list": [{"id": "drafts", "role": "drafts"}]}
            elif method == "Identity/get":
                result = {"accountId": args["accountId"], "list": [{"id": "identity", "email": "sender@example.com"}]}
            else:
                result = {"accountId": args["accountId"], "list": []}
            self.reply(200, {"methodResponses": [[method, result, ident]]})
        elif state.get("oversize"):
            self.reply(200, {"text": "x" * 4096})
        elif state.get("redirect"):
            self.reply(302, {}, {"Location": "http://127.0.0.1:1/must-not-follow"})
        else:
            self.reply(200, {"ok": True})

    def reply(self, status, data, extra=None):
        body = json.dumps(data).encode()
        self.reply_bytes(status, body, extra)

    def reply_bytes(self, status, body, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if self.server.state.get("etag", '"one"') is not None:
            self.send_header("ETag", self.server.state.get("etag", '"one"'))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_PROPFIND = handle_call


def serve(vault=False):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    server.state = {"vault": vault, "documents": {}, "calls": [], "reads": []}
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def verify_sigv4(method, path, headers, body):
    """Independent verifier for the actual native signer, with fixture keys."""
    authorization = headers["Authorization"]
    assert authorization.startswith("AWS4-HMAC-SHA256 Credential=fixture-key/")
    match = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=fixture-key/([^,]+), SignedHeaders=([^,]+), Signature=([a-f0-9]{64})", authorization)
    assert match, authorization
    scope, names, signature = match.groups()
    date, region, service, ending = scope.split("/")
    assert (region, service, ending) == ("us-east-1", "s3", "aws4_request")
    parsed = urllib.parse.urlsplit(path)
    quote = lambda text: urllib.parse.quote(text, safe="-_.~")
    query = "&".join(f"{key}={value}" for key, value in sorted((quote(k), quote(v)) for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in names.split(";"))
    payload_hash = hashlib.sha256(body).hexdigest()
    assert headers["x-amz-content-sha256"] == payload_hash
    canonical = "\n".join((method, parsed.path, query, canonical_headers, names, payload_hash))
    to_sign = "\n".join(("AWS4-HMAC-SHA256", headers["x-amz-date"], scope, hashlib.sha256(canonical.encode()).hexdigest()))
    key = b"AWS4fixture-secret"
    for value in (date, region, service, ending):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    assert hmac.compare_digest(hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest(), signature)


def check_catalog(path):
    """Compare the sibling Rust catalog to independently exercised broker cases.

    Explicit gaps are release-blocking recommendations, not silent coverage.
    A new provider/operation must gain a fixture or change the documented set.
    """
    source = path.read_text()
    ids = dict(re.findall(r'Provider::(\w+)\s*=>\s*"([a-z0-9-]+)"', (path.parent / "model.rs").read_text()))
    ai_ids = dict(re.findall(r'ai!\(\s*(\w+),\s*"([a-z0-9-]+)"', (path.parent / "ai.rs").read_text()))
    ids.update(ai_ids)
    operation_ids = lambda body: set(re.findall(r'"([a-z_]+\.[a-z_]+)"\s*=>', body))
    ai_body = re.search(r'if provider\.is_ai\(\)\s*\{\s*return operations!\[(.*?)\]', source, re.S)
    assert ai_body, "unrecognized AI permission catalog shape"
    expected = {provider: operation_ids(ai_body.group(1)) for provider in ai_ids.values()}
    for name, body in re.findall(r'if provider == Provider::(\w+)\s*\{\s*return operations!\[(.*?)\]', source, re.S):
        expected[ids[name]] = operation_ids(body)
    for names, operations in re.findall(r'((?:Provider::\w+\s*(?:\|\s*)?)+)=>\s*operations!\[(.*?)\]', source, re.S):
        ops = operation_ids(operations)
        for name in re.findall(r'Provider::(\w+)', names):
            expected[ids[name]] = ops
    actual = {}
    for provider, operation, _, _ in fixtures():
        actual.setdefault(provider, set()).add(operation)
    for provider, operations in native_writer.PAIRS.items(): actual[provider].update(operations)
    gaps = {"caldav": {"events.invite"}, "slack": {"files.read"},
        **{provider: {"channels.list", "messages.read", "messages.update", "messages.delete", "files.read"} for provider in ("signal", "whatsapp")}}
    extras = {"opencode": {"classification.evaluate"}, **native_writer.PAIRS}
    assert expected.keys() == actual.keys(), (expected.keys() - actual.keys(), actual.keys() - expected.keys())
    for provider in expected:
        assert expected[provider] - actual[provider] == gaps.get(provider, set()) & expected[provider], (provider, expected[provider] - actual[provider])
        assert actual[provider] - expected[provider] <= extras.get(provider, set()), (provider, actual[provider] - expected[provider])
    unresolved = sum(len(expected[provider] - actual[provider]) for provider in expected)
    print(f"Catalog drift checked: {len(actual)} providers; {sum(len(ops) for ops in actual.values())} supported operation/provider pairs; {unresolved} explicit unsupported catalog pairs")


def fixtures():
    for provider in ("s3", "azure"):
        for op, payload in (("list", {}), ("read", {}), ("write", {"contents": "hello"}), ("delete", {})):
            yield provider, "objects." + op, ["reports"] if op == "list" else ["reports", "file"], payload
    for provider in ("gdrive", "dropbox"):
        for op, resource, payload in (
            ("list", ["folder"], {}), ("read", ["folder", "file"], {}),
            ("create", ["folder"] if provider == "gdrive" else ["folder", "file"], {"name": "hello"} if provider == "gdrive" else {"contents": "hello"}),
            ("update", ["folder", "file"], {"name": "new"} if provider == "gdrive" else {"contents": "new", "revision": "rev"}),
            ("delete", ["folder", "file"], {}), ("share", ["folder", "file", "a@example.com"], {})):
            yield provider, "files." + op, resource, payload
    for provider in ("google-calendar", "microsoft-calendar"):
        yield provider, "calendars.list", [], {}
        for op in ("read", "create", "update", "delete", "invite"):
            payload = {"event": {"start": {"dateTime": "2026-09-30T12:00:00Z"}, "end": {"dateTime": "2026-09-30T13:00:00Z"}}} if op == "create" else {"event": {}} if op == "update" else {}
            yield provider, "events." + op, ["cal"] if op == "create" else ["cal", "event", "a@example.com"] if op == "invite" else ["cal", "event"], payload
    yield "caldav", "calendars.list", [], {}
    for op in ("read", "create", "update", "delete"):
        payload = {"summary": "hello", "start": "20260930T120000Z", "end": "20260930T130000Z"} if op in ("create", "update") else {}
        if op in ("update", "delete"):
            payload["etag"] = '"one"'
        yield "caldav", "events." + op, ["cal", "event.ics"], payload
    for provider in ("gmail", "outlook", "jmap"):
        yield provider, "mailboxes.list", ["me"], {}
        yield provider, "messages.read", ["me", "inbox", "m"], {}
        yield provider, "messages.search", ["me", "inbox"], {"query": "hello"}
        yield provider, "drafts.create", ["me", "DRAFT" if provider == "gmail" else "drafts"], {"subject": "hi", "text": "hello"}
        yield provider, "messages.send", ["me", "inbox", "m", "a@example.com", "identity"] if provider == "jmap" else ["me", "SENT" if provider == "gmail" else "sentitems", "a@example.com"], {} if provider == "jmap" else {"subject": "hi", "text": "hello"}
        yield provider, "messages.update", ["me", "inbox", "m", "archive"], {}
        yield provider, "messages.delete", ["me", "inbox", "m"], {}
        yield provider, "attachments.read", ["me", "inbox", "m", "blob"], {}
    for op, resource, payload in (("pages.read", "page", {}), ("databases.query", "db", {}), ("pages.create", "parent", {"title": "hi"}),
                                  ("pages.update", "page", {"title": "new"}), ("pages.delete", "page", {}), ("comments.create", "page", {"text": "hello"})):
        yield "notion", op, [resource], payload
    for op, resource, payload in (("channels.list", [], {}), ("messages.read", ["C123"], {}), ("messages.send", ["C123"], {"text": "hi"}),
                                  ("messages.update", ["C123", "123.456"], {"text": "hi"}), ("messages.delete", ["C123", "123.456"], {})):
        yield "slack", op, resource, payload
    for provider in ("signal", "whatsapp"):
        yield provider, "messages.send", ["number", "+1234"], {"text": "hello"}
    for provider in ("github", "gitlab"):
        yield provider, "repositories.list", [], {}
        yield provider, "repositories.read", ["owner", "repo", "src", "file"], {"ref": "main"}
        yield provider, "repositories.write", ["owner", "repo", "src", "file"], {"branch": "main", "message": "update", "contents": "hello"}
        yield provider, "issues.read", ["owner", "repo", "1"], {}
        for op in ("issues.write", "pull_requests.write"):
            yield provider, op, ["owner", "repo", "1"], {"title": "hi", "text": "hello"}
    ai = ("anthropic mistral openai openai-compatible ant-ling baseten cerebras deepseek fireworks github-copilot gemini groq huggingface kimi-coding meta minimax minimax-cn moonshotai moonshotai-cn nvidia opencode-go opencode openrouter qwen-token-plan qwen-token-plan-cn qwen-token-plan-individual radius scaleway together typesafe vercel-ai-gateway xiaomi xiaomi-token-plan-ams xiaomi-token-plan-cn xiaomi-token-plan-sgp zai-coding-cn zai xai").split()
    for provider in ai:
        yield provider, "models.list", [], {}
        if provider == "radius":
            continue
        if provider in ("typesafe", "opencode"):
            yield provider, "classification.evaluate", ["jev-latest"], {"state": {}, "questions": {"ready": "bool"}}
        if provider != "typesafe":
            yield provider, "inference.generate", ["model"], {"contents": []} if provider == "gemini" else {"input": "hi"} if provider in ("xai", "meta") else {"messages": []}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", type=Path, default=Path(__file__).resolve().parents[2] / ".lake/build/bin/liaison")
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=Path(__file__).resolve().parents[2].parent / "typednotes/packages/api/src/permissions.rs")
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parent / "client")
    options = parser.parse_args()
    assert options.temp_root.is_dir() and options.broker.is_file()
    check_catalog(options.catalog)
    org, run_id = str(uuid.uuid4()), str(uuid.uuid4())
    root_key = secrets.token_bytes(32)
    vault, upstream = serve(True), serve()
    broker_port, pg_port = port(), port()
    checks = 0
    with tempfile.TemporaryDirectory(prefix="liaison-connectors-", dir=options.temp_root) as tmp:
        directory = Path(tmp)
        pg = directory / "postgres"
        run("initdb", "-D", str(pg), "-A", "trust", "--no-locale", "-U", "fixture")
        run("pg_ctl", "-D", str(pg), "-l", str(directory / "postgres.log"), "-o", f"-h 127.0.0.1 -p {pg_port} -c unix_socket_directories=", "-w", "start")
        process = None
        try:
            database = f"postgresql://fixture@127.0.0.1:{pg_port}/postgres"
            def sql(statement):
                return run("psql", database, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", statement).strip()
            sql("create table credit_holds (id uuid primary key default gen_random_uuid(), org_id uuid, run_id uuid, amount bigint, state text, expires_at timestamptz); create table credit_ledger (id uuid default gen_random_uuid(), org_id uuid, run_id uuid, delta bigint, reason text);" + (Path(__file__).resolve().parents[2] / "sql/0001_audit_log.sql").read_text())
            sql(f"insert into credit_ledger (org_id,run_id,delta,reason) values ('{org}','{run_id}',10000,'fixture')")
            env = dict(os.environ, LIAISON_ROOT_KEY=root_key.hex(), DATABASE_URL=database, SECRETS_HOST="127.0.0.1", SECRETS_PORT=str(vault.server_port), SECRETS_INSECURE="1", SECRETS_TOKEN="local-vault-fixture", LIAISON_PORT=str(broker_port))
            for name in list(env):
                if name.endswith(("_CLIENT_ID", "_CLIENT_SECRET")) or name in ("SECRETS_USERNAME", "SECRETS_PASSWORD"):
                    del env[name]
            with (directory / "broker.log").open("w") as log:
                process = subprocess.Popen([str(options.broker)], env=env, stdout=log, stderr=log)
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{broker_port}/_health", timeout=1) as response:
                            assert response.read() == b"ok"
                        break
                    except (OSError, urllib.error.URLError):
                        if process.poll() is not None:
                            raise AssertionError((directory / "broker.log").read_text())
                        time.sleep(0.05)
                else:
                    raise AssertionError("broker did not start")

                def setup(provider="s3", operation="objects.read", resource=None, payload=None, expires=None):
                    resource = resource if resource is not None else ["reports", "file"]
                    warrant_id = str(uuid.uuid4())
                    expires = int(time.time()) + 300 if expires is None else expires
                    caves = [
                        ({"kind": "expiresAt", "value": str(expires)}, b"\x00" + struct.pack(">Q", expires)),
                        ({"kind": "capability", "provider": provider, "action": operation}, b"\x01" + lp(provider) + lp(operation)),
                        ({"kind": "resource", "value": "connection"}, b"\x02" + lp("connection")),
                        ({"kind": "budget", "value": "1"}, b"\x03" + struct.pack(">Q", 1)),
                        ({"kind": "runId", "value": run_id}, b"\x04" + lp(run_id))]
                    tag = hmac.new(root_key, lp(warrant_id) + lp(org), hashlib.sha256).digest()
                    for _, encoded in caves:
                        tag = hmac.new(tag, encoded, hashlib.sha256).digest()
                    request = {"warrant": {"id": warrant_id, "orgId": org, "tag": tag.hex(), "caveats": [c for c, _ in reversed(caves)]},
                        "now": "0", "cost": "1", "provider": provider, "action": operation, "resource": "connection", "runId": run_id, "orgId": org,
                        "call": {"kind": "connector", "account": "user/connection", "operation": operation, "resource": resource, "payload": json.dumps(payload or {})}}
                    permissions = {"scopes": [{"operation": operation, "root": [], "descendants": True}], "maxRequestBytes": 1048576, "maxResponseBytes": 16777216}
                    capability = dict(copy.deepcopy(permissions), provider=provider, connection="connection")
                    credential_path = f"/v1/secret/data/thirdparty/{provider}/user/connection"
                    org_path = f"/v1/secret/data/connector-policy/{org}/{provider}/connection"
                    run_path = f"/v1/secret/data/connector-authority/{org}/{run_id}/{warrant_id}"
                    vault.state["documents"] = {credential_path: {"kind": "bearer", "base_url": f"http://127.0.0.1:{upstream.server_port}/base", "token": "local-provider-fixture"},
                        credential_path + "/permissions": copy.deepcopy(permissions), org_path: copy.deepcopy(permissions),
                        run_path: {"account": "user/connection", "cell": copy.deepcopy(capability), "warrant": copy.deepcopy(capability)}}
                    upstream.state = {"vault": False, "provider": provider, "calls": [], "reads": [], "documents": {}}
                    vault.state["reads"] = []
                    return request, (credential_path, org_path, run_path)

                def check(request, expected=200, error=None, sends=None):
                    nonlocal checks
                    status, reply = exchange(f"http://127.0.0.1:{broker_port}/v0/egress", request)
                    assert status == expected, (request if isinstance(request, str) else (request["provider"], request["action"]), status, reply)
                    if error:
                        assert reply == {"error": error}, reply
                    if sends is not None:
                        assert len(upstream.state["calls"]) == sends, upstream.state["calls"]
                    audit = sql("select outcome from audit_log order by id desc limit 1")
                    assert audit == (error or "ok"), audit
                    assert sql("select count(*) from credit_holds where state='held'") == "0"
                    checks += 1
                    return reply

                def resign(request):
                    warrant = request["warrant"]
                    tag = hmac.new(root_key, lp(warrant["id"]) + lp(warrant["orgId"]), hashlib.sha256).digest()
                    for caveat in reversed(warrant["caveats"]):
                        kind = caveat["kind"]
                        encoded = (b"\x00" + struct.pack(">Q", int(caveat["value"])) if kind == "expiresAt" else
                            b"\x01" + lp(caveat["provider"]) + lp(caveat["action"]) if kind == "capability" else
                            b"\x02" + lp(caveat["value"]) if kind == "resource" else
                            b"\x03" + struct.pack(">Q", int(caveat["value"])) if kind == "budget" else
                            b"\x04" + lp(caveat["value"]))
                        tag = hmac.new(tag, encoded, hashlib.sha256).digest()
                    warrant["tag"] = tag.hex()

                for provider, operation, resource, payload in fixtures():
                    request, paths = setup(provider, operation, resource, payload)
                    reply = check(request)
                    if provider == "github":
                        assert reply["status"] == 200, "GitHub rejected a request without User-Agent"
                        for _, _, headers, _ in upstream.state["calls"]:
                            agents = [value for name, value in headers.items() if name.lower() == "user-agent"]
                            assert agents == ["typednotes-liaison"], (operation, headers)
                    assert upstream.state["calls"], (provider, operation)
                    assert vault.state["reads"].count(paths[0]) == 1, "credential was refetched"
                    method, path, _, body = upstream.state["calls"][-1]
                    assert path.startswith("/base")
                    assert "local-provider-fixture" not in sql("select string_agg(row(audit_log.*)::text,',') from audit_log")
                    if provider in ("gmail", "outlook") and operation == "messages.send":
                        message = json.loads(body)
                        if provider == "gmail":
                            raw = base64.urlsafe_b64decode(message["raw"] + "=" * (-len(message["raw"]) % 4)).decode()
                            assert "To: a@example.com\r\n" in raw and "Bcc:" not in raw
                        else:
                            assert message["message"]["toRecipients"] == [{"emailAddress": {"address": "a@example.com"}}]
                    if provider == "jmap" and operation in ("messages.update", "messages.delete"):
                        assert json.loads(body)["methodCalls"][0][1]["ifInState"] == "one"
                    if provider == "github" and operation == "repositories.read":
                        assert "/git/blobs/" in path and "/contents/" not in path
                    if provider == "dropbox" and operation == "files.delete":
                        assert json.loads(body) == {"path": "/folder/file", "parent_rev": "a123"}
                    if provider == "jmap" and operation == "messages.send":
                        assert json.loads(body)["methodCalls"][0][1]["create"]["send"]["envelope"] == {
                            "mailFrom": {"email": "sender@example.com"}, "rcptTo": [{"email": "a@example.com"}]}
                    if provider == "notion" and operation == "databases.query":
                        assert path == "/base/data_sources/source/query"
                    if provider in ("google-calendar", "microsoft-calendar") and operation in ("events.update", "events.delete", "events.invite"):
                        assert upstream.state["calls"][-1][2]["if-match"] == '"one"'

                # Exercise each supported operation with explicit narrow grants
                for provider in ("github", "gitlab"):
                    request, paths = setup(provider, "repositories.list", [], {"page":"2"})
                    assert check(request)["status"] == 200
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(upstream.state["calls"][-1][1]).query)
                    assert query["page"] == ["2"] and query["per_page"] == ["100"]
                    for value in ["0", "101", "01", "-1", "1.5", 2]:
                        request, _ = setup(provider, "repositories.list", [], {"page":value})
                        check(request, 403, "capability_denied", 0)
                    request, paths = setup(provider, "repositories.read", ["owner","repo"], {"view":"metadata"})
                    for path in [paths[0]+"/permissions",paths[1]]:
                        vault.state["documents"][path]["scopes"] = [{"operation":"repositories.read","root":["owner","repo"],"descendants":False}]
                    for name in ("cell","warrant"):
                        vault.state["documents"][paths[2]][name]["scopes"] = [{"operation":"repositories.read","root":["owner","repo"],"descendants":False}]
                    assert check(request)["status"] == 200
                    upstream.state["repo_identity"] = "other/repo"
                    check(request, 403, "resource_denied")
                    request, _ = setup(provider, "repositories.list", [], {})
                    upstream.state["raw"] = json.dumps([{}]*101)
                    check(request, 403, "resource_denied")

                # Exercise each supported operation with explicit narrow grants
                # at all four ceilings, not just account-wide test defaults.
                for provider, operation, resource, payload in fixtures():
                    requires_tree = (provider == "gmail" and operation in ("messages.update", "messages.delete", "attachments.read")) or (provider == "dropbox" and operation == "files.share") or (provider == "notion" and operation == "pages.delete")
                    if requires_tree:
                        continue  # separately tested recursive-account restriction
                    request, paths = setup(provider, operation, resource, payload)
                    scopes = [{"operation": operation, "root": resource, "descendants": False}]
                    if provider in ("outlook", "jmap") and operation == "messages.update":
                        scopes.append({"operation": operation, "root": [resource[0], resource[3]], "descendants": False})
                    for path in (paths[0] + "/permissions", paths[1]):
                        vault.state["documents"][path]["scopes"] = copy.deepcopy(scopes)
                    for ceiling in ("cell", "warrant"):
                        vault.state["documents"][paths[2]][ceiling]["scopes"] = copy.deepcopy(scopes)
                    check(request)
                    upstream.state["calls"] = []
                    request["call"]["resource"] = resource + ["outside"]
                    check(request, 403, "resource_denied", 0)

                for ceiling in ("organization", "connection", "cell", "warrant"):
                    request, (credential, organization, authority) = setup()
                    doc = vault.state["documents"][organization if ceiling == "organization" else credential + "/permissions" if ceiling == "connection" else authority]
                    (doc if ceiling in ("organization", "connection") else doc[ceiling])["scopes"] = []
                    check(request, 403, "resource_denied", 0)
                # Real HMAC failures and bound caveats fail before vault/hold.
                for tamper in ("tag", "org", "id", "caveat"):
                    request, _ = setup()
                    if tamper == "tag":
                        request["warrant"]["tag"] = "00" * 32
                    elif tamper == "caveat":
                        request["warrant"]["caveats"][1]["value"] = "999"
                    else:
                        request["warrant"]["orgId" if tamper == "org" else "id"] = str(uuid.uuid4())
                    check(request, 403, "tag_invalid", 0)
                    assert not vault.state["reads"]
                for field, value, error in (("runId", str(uuid.uuid4()), "wrong_run"), ("resource", "wrong", "resource_denied"),
                        ("provider", "azure", "capability_denied"), ("action", "objects.delete", "capability_denied"), ("cost", "2", "budget_exceeded")):
                    request, _ = setup()
                    request[field] = value
                    check(request, 403, error, 0)
                    assert not vault.state["reads"]
                for missing in ("capability", "runId", "resource", "budget", "expiresAt"):
                    request, _ = setup()
                    request["warrant"]["caveats"] = [c for c in request["warrant"]["caveats"] if c["kind"] != missing]
                    resign(request)
                    check(request, 400, "malformed_warrant", 0)
                    assert not vault.state["reads"]
                request, _ = setup(expires=int(time.time()) - 10)
                assert request["now"] == "0"
                check(request, 403, "expired", 0)
                for missing in ("organization", "run"):
                    request, (_, organization, authority) = setup()
                    del vault.state["documents"][organization if missing == "organization" else authority]
                    check(request, 403, "capability_denied", 0)
                for bad in ([".."], ["%2e%2e"], ["reports/other"]):
                    request, _ = setup(resource=bad)
                    check(request, 400, "malformed_warrant", 0)
                request, paths = setup()
                vault.state["documents"][paths[0] + "/permissions"]["scopes"][0]["root"] = [".."]
                check(request, 403, "capability_denied", 0)
                request, paths = setup()
                vault.state["documents"][paths[0] + "/permissions"]["scopes"][0]["operation"] = "unknown"
                check(request, 403, "capability_denied", 0)
                for mutation in ("missing_descendants", "unknown_field", "fractional", "no_scopes", "zero_limit", "too_many_scopes"):
                    request, paths = setup()
                    permissions = vault.state["documents"][paths[0] + "/permissions"]
                    if mutation == "missing_descendants":
                        del permissions["scopes"][0]["descendants"]
                    elif mutation == "unknown_field":
                        permissions["allowAll"] = True
                    elif mutation == "fractional":
                        permissions["maxRequestBytes"] = 1.00000001
                    elif mutation == "no_scopes":
                        del permissions["scopes"]
                    elif mutation == "zero_limit":
                        permissions["maxRequestBytes"] = 0
                    else:
                        permissions["scopes"] *= 129
                    check(request, 403, "capability_denied", 0)
                for ceiling in ("cell", "warrant"):
                    request, paths = setup()
                    del vault.state["documents"][paths[2]][ceiling]["maxResponseBytes"]
                    check(request, 403, "capability_denied", 0)
                request, _ = setup()
                vault.state["status"] = 403
                check(request, 502, "credential_unavailable", 0)
                del vault.state["status"]
                request, paths = setup()
                vault.state["documents"][paths[2]]["account"] = "other/connection"
                check(request, 403, "capability_denied", 0)
                request, _ = setup()
                request["orgId"] = str(uuid.uuid4())
                check(request, 403, "resource_denied", 0)
                request, _ = setup()
                request["call"]["account"] = "other/connection"
                check(request, 403, "capability_denied", 0)
                request, _ = setup()
                request["call"]["operation"] = "objects.delete"
                check(request, 403, "capability_denied", 0)
                request, _ = setup()
                request["call"] = {"kind": "provider", "account": "user/connection", "method": "DELETE", "url": f"http://127.0.0.1:{upstream.server_port}/base/reports/file"}
                check(request, 403, "capability_denied", 0)
                request, paths = setup()
                del vault.state["documents"][paths[0] + "/permissions"]
                request["call"] = {"kind": "provider", "account": "user/connection", "method": "GET", "url": f"http://127.0.0.1:{upstream.server_port}/base/reports/file"}
                check(request, 403, "capability_denied", 0)
                request, _ = setup()
                request["call"] = {"kind": "inference"}
                check(request, 501, "inference_not_implemented", 0)
                request, paths = setup(payload={"url": "https://other.invalid"})
                check(request, 403, "capability_denied", 0)
                for override in ("method", "headers", "body", "resource", "operation", "account"):
                    request, _ = setup(payload={override: "caller-selected"})
                    check(request, 403, "capability_denied", 0)
                request, _ = setup()
                request["call"]["url"] = "https://other.invalid"
                check(request, 400, "malformed_warrant", 0)
                request, _ = setup()
                request["call"]["payload"] = '{"url":"one","url":"two"}'
                check(request, 403, "capability_denied", 0)
                request, _ = setup()
                encoded = json.dumps(request).replace('"operation": "objects.read"', '"operation": "objects.read", "operation": "objects.delete"')
                check(encoded, 400, "malformed_warrant", 0)
                request, paths = setup()
                vault.state["documents"][paths[2]]["cell"]["maxRequestBytes"] = 1
                check(request, 403, "capability_denied", 0)
                request, paths = setup()
                vault.state["documents"][paths[2]]["warrant"]["maxResponseBytes"] = 16
                upstream.state["oversize"] = True
                check(request, 403, "capability_denied", 1)
                request, _ = setup()
                upstream.state["redirect"] = True
                reply = check(request, sends=1)
                assert reply["status"] == 302
                request, _ = setup("gmail", "messages.read", ["me", "inbox", "m"])
                upstream.state["labels"] = ["other"]
                check(request, 403, "resource_denied", 1)
                request, _ = setup("gdrive", "files.read", ["folder", "file"])
                upstream.state["parents"] = ["other"]
                check(request, 403, "resource_denied", 1)
                for operation in ("files.delete", "files.share"):
                    request, _ = setup("gdrive", operation, ["folder", "file"] + (["a@example.com"] if operation == "files.share" else []))
                    upstream.state["mime"] = "application/vnd.google-apps.folder"
                    check(request, 403, "resource_denied", 1)
                request, _ = setup("gdrive", "files.read", ["folder", "file"])
                upstream.state["etag"] = None
                check(request, 403, "resource_denied", 1)
                for etag in ("*", 'W/"one"', '"one","two"'):
                    request, _ = setup("google-calendar", "events.update", ["cal", "event"], {"event": {}})
                    upstream.state["etag"] = etag
                    check(request, 403, "resource_denied", 1)
                request, _ = setup("gdrive", "files.read", ["root", "folder", "file"])
                check(request, 403, "resource_denied", 0)
                request, _ = setup("dropbox", "files.delete", ["folder", "file"])
                upstream.state["dropbox_type"] = "folder"
                check(request, 403, "resource_denied", 1)
                request, _ = setup("notion", "databases.query", ["db", "outside"])
                check(request, 403, "resource_denied", 1)
                request, _ = setup("notion", "databases.query", ["db"])
                upstream.state["sources"] = [{"id": "one"}, {"id": "two"}]
                check(request, 403, "resource_denied", 1)
                request, _ = setup("notion", "databases.query", ["db", "two"])
                upstream.state["sources"] = [{"id": "one"}, {"id": "two"}]
                check(request, sends=2)
                assert upstream.state["calls"][-1][1] == "/base/data_sources/two/query"
                for provider in ("gmail", "outlook", "jmap"):
                    request, paths = setup(provider, "messages.update", ["me", "inbox", "m", "outside"])
                    for path in (paths[0] + "/permissions", paths[1]):
                        vault.state["documents"][path]["scopes"][0]["root"] = ["me", "inbox"]
                    for ceiling in ("cell", "warrant"):
                        vault.state["documents"][paths[2]][ceiling]["scopes"][0]["root"] = ["me", "inbox"]
                    check(request, 403, "capability_denied", 0)
                request, _ = setup("google-calendar", "events.invite", ["cal", "event", "a@example.com"])
                upstream.state["attendees"] = [{"email": "other@example.com"}]
                # Broad invitation authority explicitly allows both recipients;
                # verify the merge rather than silently replacing attendees.
                check(request)
                assert len(json.loads(upstream.state["calls"][-1][3])["attendees"]) == 2
                request, paths = setup("google-calendar", "events.invite", ["cal", "event", "a@example.com"])
                vault.state["documents"][paths[2]]["cell"]["scopes"][0].update(root=["cal", "event", "a@example.com"], descendants=False)
                upstream.state["attendees"] = [{"email": "other@example.com"}]
                check(request, 403, "resource_denied", 1)
                request, _ = setup("google-calendar", "events.update", ["cal", "event"], {"event": {}})
                upstream.state["attendees"] = [{"email": "other@example.com"}]
                check(request, 403, "resource_denied", 1)
                request, _ = setup("jmap", "attachments.read", ["me", "inbox", "m", "outside"])
                check(request, 403, "resource_denied", 1)
                request, paths = setup("jmap", "messages.delete", ["me", "inbox", "m"])
                vault.state["documents"][paths[2]]["cell"]["scopes"][0]["root"] = ["me", "inbox"]
                upstream.state["mailboxes"] = {"inbox": True, "outside": True}
                check(request, 403, "resource_denied", 1)
                request, _ = setup("jmap", "messages.read", ["me", "inbox", "m"])
                upstream.state["mailboxes"] = {"outside": True}
                check(request, 403, "resource_denied", 1)
                # Account-level exact grants cannot masquerade as recursive
                # authority for effects requiring an account subtree.
                for provider, operation, resource in (("gmail", "messages.delete", ["me", "inbox", "m"]),
                        ("dropbox", "files.share", ["folder", "file", "a@example.com"]), ("notion", "pages.delete", ["page"])):
                    request, paths = setup(provider, operation, resource)
                    for path in (paths[0] + "/permissions", paths[1]):
                        vault.state["documents"][path]["scopes"] = [
                            {"operation": operation, "root": resource, "descendants": False},
                            {"operation": operation, "root": ["me"] if provider == "gmail" else [], "descendants": False}]
                    check(request, 403, "capability_denied", 0)
                request, paths = setup()
                vault.state["documents"][paths[0] + "/permissions"]["scopes"][0]["root"] = ["reports"]
                request["call"]["resource"] = ["reports-private", "file"]
                check(request, 403, "resource_denied", 0)
                # A missing connection policy retains read-only defaults only
                # after all the independent policies have authorized the call.
                request, paths = setup()
                del vault.state["documents"][paths[0] + "/permissions"]
                check(request, sends=1)
                request, paths = setup("s3", "objects.write", ["reports", "file"], {"contents": "hello"})
                del vault.state["documents"][paths[0] + "/permissions"]
                check(request, 403, "resource_denied", 0)
                # Hot permission updates apply to the same verified warrant.
                for ceiling in ("connection", "organization", "cell", "warrant"):
                    request, paths = setup()
                    check(request, sends=1)
                    upstream.state["calls"] = []
                    if ceiling in ("cell", "warrant"):
                        doc = vault.state["documents"][paths[2]][ceiling]
                    else:
                        doc = vault.state["documents"][paths[0] + "/permissions" if ceiling == "connection" else paths[1]]
                    doc["scopes"] = []
                    check(request, 403, "resource_denied", 0)
                for provider, credential in (("s3", {"kind": "s3", "region": "us-east-1", "access_key_id": "fixture-key", "secret_access_key": "fixture-secret"}),
                        ("azure", {"kind": "azure_sas", "sas": "sv=2025-01-01&sig=local-signature"})):
                    request, paths = setup(provider, "objects.write", ["reports", "é?x=1"], {"contents": "signed fixture"})
                    credential["base_url"] = vault.state["documents"][paths[0]]["base_url"]
                    vault.state["documents"][paths[0]] = credential
                    upstream.state["auth"] = "s3" if provider == "s3" else "sas"
                    check(request, sends=1)
                    assert upstream.state["calls"][-1][1].startswith("/base/reports/%C3%A9%3Fx%3D1")
                request, _ = setup()
                sdk_calls = native_writer.run(setup, check, vault, upstream, directory, f"http://127.0.0.1:{broker_port}", options.workspace, sql)
                checks += sdk_calls
                request, _ = setup()
                sql(f"insert into credit_ledger (org_id,run_id,delta,reason) select '{org}','{run_id}',-sum(delta),'empty fixture' from credit_ledger where org_id='{org}'")
                check(request, 402, "budget_unavailable", 0)
                assert not vault.state["reads"]
                assert sql("select count(*) from audit_log") == str(checks)
                print(f"PASS: {checks} real broker HTTP cases; native requests, four ceilings, audit and settled/released holds verified")
        finally:
            if process:
                process.terminate()
                process.wait(timeout=10)
            run("pg_ctl", "-D", str(pg), "-m", "immediate", "-w", "stop")
            vault.shutdown()
            upstream.shutdown()


def lp(value):
    data = value.encode()
    return struct.pack(">Q", len(data)) + data


if __name__ == "__main__":
    main()
