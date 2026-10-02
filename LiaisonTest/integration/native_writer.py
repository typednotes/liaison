"""Additional real-broker/native-writer cases, imported by connectors.py.

Repository fixtures run actual local git object/ref/receive-pack commands;
there is deliberately no git-push command or external network here.
"""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import uuid


PAIRS = {"github": {"repositories.delete"}, "gitlab": {"repositories.delete"}, "radius": {"inference.generate"}}


def git(repo, *args, data=None, env=None, check=True):
    process = subprocess.run(["git", "--git-dir", str(repo), *args], input=data, capture_output=True,
        env=dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
            GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid", **(env or {})))
    if check and process.returncode:
        raise AssertionError(process.stderr.decode())
    return process


def packet(value):
    return f"{len(value) + 4:04x}".encode() + value


class Repository:
    def __init__(self, directory, provider):
        self.directory, self.provider = Path(directory), provider
        self.repo = self.directory / "fixture.git"
        subprocess.run(["git", "init", "--bare", "-q", str(self.repo)], check=True)
        self.root = self.make_tree({"Outside.txt": ("100644", b"outside base\n"), "typednotes/graph/Main.lean": ("100644", b"seed\n"),
            "typednotes/graph/keep.sh": ("100755", b"keep\n")})
        self.ancestor = self.make_commit(self.root, [], "base")
        tree = self.make_tree({"Outside.txt": ("100644", b"published outside\n"), "typednotes/graph/Main.lean": ("100644", b"seed\n"),
            "typednotes/graph/keep.sh": ("100755", b"keep\n")})
        self.initial = self.make_commit(tree, [self.ancestor], "published base")
        git(self.repo, "update-ref", "refs/heads/main", self.initial)
        self.race = False
        self.unsafe = None
        self.paginate = False
        self.published = 0

    def make_tree(self, files, base=None):
        index = str(self.directory / ("index-" + str(uuid.uuid4())))
        env = {"GIT_INDEX_FILE": index}
        git(self.repo, "read-tree", base or "--empty", env=env)
        for path, (mode, value) in files.items():
            if value is None:
                git(self.repo, "update-index", "--index-info", data=("0 " + "0" * 40 + "\t" + path + "\n").encode(), env=env)
            else:
                sha = git(self.repo, "hash-object", "-w", "--stdin", data=value).stdout.decode().strip()
                git(self.repo, "update-index", "--add", "--cacheinfo", f"{mode},{sha},{path}", env=env)
        return git(self.repo, "write-tree", env=env).stdout.decode().strip()

    def make_commit(self, tree, parents, message):
        args = ["commit-tree", tree]
        for parent in parents:
            args += ["-p", parent]
        return git(self.repo, *args, data=(message + "\n").encode()).stdout.decode().strip()

    def head(self):
        return git(self.repo, "rev-parse", "refs/heads/main").stdout.decode().strip()

    def tree(self, ref):
        values = git(self.repo, "ls-tree", "-r", "-t", "-z", ref).stdout.split(b"\0")
        entries = []
        for value in values:
            if not value:
                continue
            header, path = value.decode().split("\t", 1)
            mode, kind, sha = header.split(" ")
            entries.append({"path": path, "mode": mode, "type": kind, "sha": sha})
        if self.unsafe:
            entries.append({"path": "unsafe", "mode": self.unsafe, "type": "blob", "sha": "a" * 40})
        return entries

    def handle(self, handler, body):
        state = handler.server.state
        state["calls"].append((handler.command, handler.path, dict(handler.headers), body))
        if self.provider == "github":
            assert handler.headers.get_all("User-Agent") == ["typednotes-liaison"], handler.path
        parsed = urllib.parse.urlsplit(handler.path)
        query = urllib.parse.parse_qs(parsed.query)
        path = urllib.parse.unquote(parsed.path)
        if ".git/" in path:
            assert self.provider == "gitlab"
            assert handler.headers["Authorization"] == "Basic " + base64.b64encode(b"oauth2:local-provider-fixture").decode()
            assert path.startswith("/base/owner/repo.git/")
            if handler.command == "GET":
                advertisement = git(self.repo, "receive-pack", "--stateless-rpc", "--advertise-refs", str(self.repo)).stdout
                handler.reply_bytes(200, packet(b"# service=git-receive-pack\n") + b"0000" + advertisement)
            else:
                if self.race:
                    git(self.repo, "update-ref", "refs/heads/main", self.ancestor, self.initial)
                before = self.head()
                result = git(self.repo, "receive-pack", "--stateless-rpc", str(self.repo), data=body, check=False)
                self.published += self.head() != before
                handler.reply_bytes(200, result.stdout)
            return
        assert handler.headers["Authorization"] == "Bearer local-provider-fixture"
        prefix = "/base/repos/owner/repo" if self.provider == "github" else "/base/projects/owner/repo"
        if path == "/base/graphql":
            value = json.loads(body)
            assert value["query"] == "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}"
            payload = value["variables"]["input"]
            assert payload["repositoryId"] == "fixture-repository"
            [change] = payload["refUpdates"]
            assert change["name"] == "refs/heads/main" and change["force"] is False
            if self.race:
                git(self.repo, "update-ref", "refs/heads/main", self.ancestor, self.initial)
            result = git(self.repo, "update-ref", "refs/heads/main", change["afterOid"], change["beforeOid"], check=False)
            self.published += result.returncode == 0
            handler.reply(200, {"errors": [{"message": "head changed"}]} if result.returncode else {"data": {"updateRefs": {"clientMutationId": None}}})
            return
        assert path.startswith(prefix), path
        suffix = path[len(prefix):]
        if suffix.startswith(("/branches/", "/repository/branches/")):
            handler.reply(200, {"name": "main", "commit": {"sha" if self.provider == "github" else "id": self.head()}})
        elif suffix.startswith("/git/commits/"):
            sha = suffix.rsplit("/", 1)[1]
            handler.reply(200, {"sha": sha, "tree": {"sha": git(self.repo, "rev-parse", sha + "^{tree}").stdout.decode().strip()}})
        elif suffix.startswith("/git/trees/"):
            handler.reply(200, {"truncated": False, "tree": self.tree(suffix.rsplit("/", 1)[1])})
        elif suffix == "/repository/tree":
            entries = [{"id": item["sha"], **{k: v for k, v in item.items() if k != "sha"}} for item in self.tree(query["ref"][0])]
            handler.reply(200, entries, {"X-Next-Page": ""})
        elif suffix.startswith("/git/blobs/"):
            contents = git(self.repo, "cat-file", "blob", suffix.rsplit("/", 1)[1]).stdout
            handler.reply(200, {"encoding": "base64", "content": base64.b64encode(contents).decode()})
        elif suffix.startswith("/repository/files/"):
            file = suffix[len("/repository/files/"):]
            contents = git(self.repo, "show", query["ref"][0] + ":" + file).stdout
            handler.reply(200, {"encoding": "base64", "content": base64.b64encode(contents).decode()})
        elif suffix == "" and self.provider == "github":
            handler.reply(200, {"node_id": "fixture-repository", "full_name": "owner/repo", "html_url":"https://github.com/owner/repo", "default_branch":"main"})
        elif suffix == "/git/trees" and handler.command == "POST":
            request = json.loads(body)
            files = {item["path"]: (item["mode"], None if item.get("sha", "not-null") is None else item["content"].encode()) for item in request["tree"]}
            tree = self.make_tree(files, request["base_tree"])
            handler.reply(201, {"sha": tree})
        elif suffix == "/git/commits" and handler.command == "POST":
            request = json.loads(body)
            sha = self.make_commit(request["tree"], request["parents"], request["message"])
            handler.reply(201, {"sha": sha, "tree": {"sha": request["tree"]}, "parents": [{"sha": sha} for sha in request["parents"]]})
        elif suffix.startswith("/compare/"):
            revision = suffix.split("...")[1]
            result = git(self.repo, "merge-base", self.head(), revision, check=False).stdout.decode().strip()
            ancestor = git(self.repo, "merge-base", "--is-ancestor", revision, self.head(), check=False).returncode == 0
            status = "identical" if self.head() == revision else "behind" if ancestor else "diverged"
            handler.reply(200, {"status": status, "merge_base_commit": {"sha": result}})
        elif suffix == "/repository/merge_base":
            refs = query["refs[]"]
            handler.reply(200, {"id": git(self.repo, "merge-base", *refs, check=False).stdout.decode().strip()})
        else:
            raise AssertionError((handler.command, path))


class Model:
    def __init__(self, api, provider=None, model=None):
        self.api, self.step, self.provider, self.model = api, 0, provider, model

    def handle(self, handler, body):
        handler.server.state["calls"].append((handler.command, handler.path, dict(handler.headers), body))
        assert handler.headers["Authorization"] == "Bearer local-provider-fixture"
        assert handler.headers["Content-Type"] == "application/json"
        request = json.loads(body)
        assert request.get("model") in (None, self.model)
        if self.provider in ("opencode", "opencode-go"):
            assert handler.headers["User-Agent"] == "typednotes-lode" and handler.headers["X-Opencode-Session"] == "fixture-session"
        if self.provider == "github-copilot":
            assert handler.headers["User-Agent"] == "typednotes-lode" and handler.headers["X-Initiator"] == ("user" if self.step == 0 else "agent")
            assert handler.headers["X-Intent"] == "conversation-panel"
        calls = self.step < 2
        cid, text = f"call-{self.step}", "thinking" if calls else "writer finished"
        if self.step:
            assert "opaque-signature" in body.decode() if self.api in ("messages", "gemini") else "reasoning" in body.decode() if self.api in ("chat", "responses") else "pi-signature" in body.decode()
            assert "local metadata result" in body.decode()
        self.step += 1
        if self.api == "chat":
            message = {"role": "assistant", "content": text, "reasoning_content": "reasoning"}
            if calls:
                message["tool_calls"] = [{"id": cid, "type": "function", "function": {"name": "todo", "arguments": "{}"}}]
            handler.reply(200, {"choices": [{"message": message, "finish_reason": "tool_calls" if calls else "stop"}]})
        elif self.api == "messages":
            blocks = [{"type": "thinking", "thinking": "reasoning", "signature": "opaque-signature"}, {"type": "text", "text": text}]
            if calls:
                blocks.append({"type": "tool_use", "id": cid, "name": "todo", "input": {}})
            handler.reply(200, {"content": blocks, "stop_reason": "tool_use" if calls else "end_turn"})
        elif self.api == "responses":
            assert request["store"] is False and request["include"] == ["reasoning.encrypted_content"]
            output = [{"type": "reasoning", "id": "inline-reasoning", "summary": [], "encrypted_content": "reasoning"},
                {"type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": text, "annotations": []}]}]
            if calls:
                output.append({"type": "function_call", "id": "inline-fn-" + cid, "call_id": cid, "name": "todo", "arguments": "{}", "status": "completed"})
            handler.reply(200, {"status": "completed", "output": output})
        elif self.api == "gemini":
            parts = [{"text": text, "thoughtSignature": "opaque-signature"}]
            if calls:
                parts.append({"functionCall": {"name": "todo", "args": {}}, "thoughtSignature": "opaque-signature"})
            handler.reply(200, {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}]})
        else:
            assert handler.headers["Accept"] == "text/event-stream" and request["options"]["sessionId"] == "fixture-session"
            events = [{"type": "start"}, {"type": "thinking_start", "contentIndex": 0},
                {"type": "thinking_end", "contentIndex": 0, "content": "reasoning", "contentSignature": "pi-signature"},
                {"type": "text_start", "contentIndex": 1}, {"type": "text_end", "contentIndex": 1, "content": text}]
            if calls:
                events += [{"type": "toolcall_start", "contentIndex": 2, "id": cid, "toolName": "todo"},
                    {"type": "toolcall_end", "contentIndex": 2, "toolCall": {"type": "toolCall", "id": cid, "name": "todo", "arguments": {}, "thoughtSignature": "pi-signature"}}]
            events.append({"type": "done", "reason": "toolUse" if calls else "stop", "usage": {"input": 1, "output": 1}})
            handler.reply_bytes(200, "".join("data: " + json.dumps(event) + "\n\n" for event in events).encode())


def run(setup, check, vault, upstream, directory, broker, workspace, sql):
    sdk_calls = 0
    client = Path(__file__).parent / "client/.lake/build/bin/writerClient"
    assert client.is_file(), "build LiaisonTest/integration/client's writerClient first"
    def invoke(value):
        nonlocal sdk_calls
        before = int(sql("select count(*) from audit_log"))
        result = subprocess.run([str(client)], cwd=workspace,
            input=json.dumps(dict(value, broker=broker)) + "\n", capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, (value["provider"], value.get("api", value["mode"]), len(upstream.state["calls"]), result.stderr + result.stdout,
            [call[3].decode(errors="replace") for call in upstream.state["calls"] if call[3]])
        sdk_calls += int(sql("select count(*) from audit_log")) - before
        assert "PASS:" in result.stdout, result.stdout
        assert sql("select count(*) from credit_holds where state='held'") == "0"

    for provider, model, api in (("openai", "gpt-4o-mini", "chat"), ("anthropic", "claude-fixture", "messages"),
            ("openai", "gpt-5", "responses"), ("gemini", "gemini-fixture", "gemini"), ("radius", "radius-fixture", "pi"),
            ("opencode-go", "claude-fixture", "messages"), ("opencode-go", "gpt-5", "responses"),
            ("opencode", "gemini-fixture", "gemini"), ("github-copilot", "gpt-5", "responses")):
        request, paths = setup(provider, "inference.generate", [model])
        vault.state["documents"][paths[2]]["conversation"] = {"sessionId": "fixture-session", "allowedTools": ["todo"]}
        fixture = Model(api, provider, model)
        upstream.state["native"] = fixture.handle
        invoke({"mode": "model", "provider": provider, "model": model, "api": api,
            "credentials": {"warrant": request["warrant"], "account": "user/connection", "cost": 1}})
        assert fixture.step == 3

    tool = {"type": "function", "function": {"name": "todo", "parameters": {"type": "object"}}}
    for failure in ("no_policy", "wrong_session", "unlisted", "remote_tool", "orphan", "limit", "override"):
        payload = {"messages": [{"role": "user", "content": "hello"}], "tools": [tool]}
        request, paths = setup("openai", "inference.generate", ["gpt-4o-mini"], payload)
        request["call"]["context"] = {"sessionId": "fixture-session", "initiator": "agent", "client": "typednotes-lode"}
        policy = {"sessionId": "fixture-session", "allowedTools": ["todo"]}
        vault.state["documents"][paths[2]]["conversation"] = policy
        if failure == "no_policy": del vault.state["documents"][paths[2]]["conversation"]
        elif failure == "wrong_session": policy["sessionId"] = "other"
        elif failure == "unlisted": policy["allowedTools"] = []
        elif failure == "remote_tool": payload["tools"] = [{"type": "web_search"}]
        elif failure == "orphan": payload["messages"] = [{"role": "tool", "tool_call_id": "missing", "content": "result"}]
        elif failure == "limit": vault.state["documents"][paths[2]]["cell"]["maxRequestBytes"] = 10
        else: payload["model"] = "other"
        request["call"]["payload"] = json.dumps(payload)
        check(request, 403, "capability_denied", 0)
    for provider, operation, resource, payload in (("postgres", "rows.select", ["bound_schema", "table"], {"sql": "select * from other.schema"}),
            ("vault", "secrets.read", ["compute", "other-user"], {})):
        request, _ = setup(provider, operation, resource, payload)
        check(request, 403, "capability_denied", 0)
        assert not vault.state["reads"], "local-effect policy groups must not expose credentialed raw egress"

    uses = [{"type": "tool_use", "id": f"ref-{i}", "name": "todo", "input": {}} for i in range(4097)]
    results = [{"type": "tool_result", "tool_use_id": f"ref-{i}", "content": "done"} for i in range(4097)]
    request, paths = setup("anthropic", "inference.generate", ["claude-fixture"], {
        "messages": [{"role": "assistant", "content": uses}, {"role": "user", "content": results}]})
    vault.state["documents"][paths[2]]["conversation"] = {"sessionId": "fixture-session", "allowedTools": ["todo"]}
    check(request, 403, "capability_denied", 0)

    pi_payload = {"options": {"maxTokens": 1024, "sessionId": "fixture-session"}, "context": {"messages": [
        {"role": "system", "content": "fixture", "timestamp": 0, "toolsAdded": []}]}}
    for stream in ('data: {"type":"start"}\n\n',
            'data: {"type":"toolcall_start","contentIndex":0,"id":"one","toolName":"unlisted"}\n\n',
            'data: {"type":"done","reason":"unknown","usage":{"input":0,"output":0}}\n\n',
            'data: {"type":"text_start","contentIndex":0}\n\ndata: {"type":"done","reason":"stop","usage":{"input":0,"output":0}}\n\n'):
        request, paths = setup("radius", "inference.generate", ["radius-fixture"], pi_payload)
        request["call"]["context"] = {"sessionId": "fixture-session", "initiator": "agent", "client": "typednotes-lode"}
        vault.state["documents"][paths[2]]["conversation"] = {"sessionId": "fixture-session", "allowedTools": []}
        upstream.state["raw"] = stream
        check(request, 403, "resource_denied", 1)

    for provider in ("github", "gitlab"):
        repo_dir = Path(directory) / (provider + "-native")
        repo_dir.mkdir()
        fixture = Repository(repo_dir, provider)
        read, paths = setup(provider, "repositories.read", ["owner", "repo"])
        saved = copy.deepcopy(vault.state["documents"])
        write, wpaths = setup(provider, "repositories.write", ["owner", "repo", "typednotes", "graph"])
        vault.state["documents"].update(saved)
        parent = vault.state["documents"][wpaths[0] + "/permissions"]
        parent["scopes"] = [{"operation": "repositories.read", "root": ["owner", "repo"], "descendants": True},
            {"operation": "repositories.write", "root": ["owner", "repo", "typednotes", "graph"], "descendants": True}]
        vault.state["documents"][wpaths[1]] = copy.deepcopy(parent)
        vault.state["documents"][wpaths[2]]["publication"] = {"branch": "main", "root": ["typednotes", "graph"]}
        upstream.state["native"] = fixture.handle
        invoke({"mode": "workspace", "provider": provider, "directory": str(repo_dir / "checkout"),
            "credentials": {"warrant": read["warrant"], "account": "user/connection", "cost": 1,
                "operations": [{"operation": "repositories.write", "warrant": write["warrant"]}]}})
        assert fixture.published == 1
        assert git(fixture.repo, "show", "main:typednotes/graph/Main.lean").stdout == b"writer changed\n"
        assert git(fixture.repo, "show", "main:Outside.txt").stdout == b"published outside\n"
        assert "100755" in git(fixture.repo, "ls-tree", "main", "typednotes/graph/keep.sh").stdout.decode()
        git(fixture.repo, "fsck", "--strict")

        for operation, changes in (("repositories.delete", [{"resource": ["Main.lean"], "contents": None, "mode": "000000", "delete": True}]),
                ("repositories.write", [{"resource": ["Main.lean"], "contents": "new text", "mode": "100755", "delete": False},
                    {"resource": ["keep.sh"], "contents": None, "mode": "000000", "delete": True}])):
            git(fixture.repo, "update-ref", "refs/heads/main", fixture.initial)
            payload = {"view": "commit", "branch": "main", "expectedHead": fixture.initial, "message": "independent deletes", "changes": changes}
            request, paths = setup(provider, operation, ["owner", "repo", "typednotes", "graph"], payload)
            vault.state["documents"][paths[2]]["publication"] = {"branch": "main", "root": ["typednotes", "graph"]}
            if operation == "repositories.write":
                grant = {"operation": "repositories.delete", "root": ["owner", "repo", "typednotes", "graph", "keep.sh"], "descendants": False}
                for path in (paths[0] + "/permissions", paths[1]): vault.state["documents"][path]["scopes"].append(copy.deepcopy(grant))
                for ceiling in ("cell", "warrant"): vault.state["documents"][paths[2]][ceiling]["scopes"].append(copy.deepcopy(grant))
            upstream.state["native"] = fixture.handle
            check(request)
            assert git(fixture.repo, "show", "main:Outside.txt").stdout == b"published outside\n"
            if operation == "repositories.delete":
                assert git(fixture.repo, "cat-file", "-e", "main:typednotes/graph/Main.lean", check=False).returncode != 0
            else:
                assert "100755" in git(fixture.repo, "ls-tree", "main", "typednotes/graph/Main.lean").stdout.decode()
                assert git(fixture.repo, "cat-file", "-e", "main:typednotes/graph/keep.sh", check=False).returncode != 0
            git(fixture.repo, "fsck", "--strict")

        for view in ("branch", "tree", "ancestry"):
            git(fixture.repo, "update-ref", "refs/heads/main", fixture.initial)
            payload = {"view": view, "ref": "main" if view == "branch" else fixture.initial}
            if view == "ancestry": payload["branch"] = "main"
            request, _ = setup(provider, "repositories.read", ["owner", "repo"], payload)
            upstream.state["native"] = fixture.handle
            reply = check(request)
            result = json.loads(bytes.fromhex(reply["body"]))
            if view == "tree": assert result["truncated"] is False and result["tree"]
            elif view == "ancestry": assert result.get("status") == "identical" if provider == "github" else result["id"] == fixture.initial
        unrelated = fixture.make_commit(fixture.root, [], "unrelated history")
        request, _ = setup(provider, "repositories.read", ["owner", "repo"], {"view": "ancestry", "ref": unrelated, "branch": "main"})
        upstream.state["native"] = fixture.handle
        check(request, 403, "resource_denied", 1)

        for failure in ("wrong_branch", "outside", "delete", "mode", "race", "exact_tree", "unsafe_tree", "overflow", "traversal", "wrong_head"):
            git(fixture.repo, "update-ref", "refs/heads/main", fixture.initial)
            payload = {"view": "commit", "branch": "main", "expectedHead": fixture.initial, "message": "scoped writer", "changes": [
                {"resource": ["Main.lean"], "contents": "changed", "mode": "100644", "delete": False}]}
            request, paths = setup(provider, "repositories.write", ["owner", "repo", "typednotes", "graph"], payload)
            vault.state["documents"][paths[2]]["publication"] = {"branch": "main", "root": ["typednotes", "graph"]}
            upstream.state["native"] = fixture.handle
            fixture.race = False
            fixture.unsafe = None
            if failure == "wrong_branch": payload["branch"] = "other"
            elif failure == "outside": request["call"]["resource"] = ["owner", "repo", "outside"]
            elif failure == "delete": payload["changes"][0].update(contents=None, mode="000000", delete=True)
            elif failure == "mode": payload["changes"][0]["mode"] = "120000"
            elif failure == "race": fixture.race = True
            elif failure == "overflow": vault.state["documents"][paths[2]]["cell"]["maxRequestBytes"] = 8
            elif failure == "traversal": payload["changes"][0]["resource"] = ["..", "Outside.txt"]
            elif failure == "wrong_head": payload["expectedHead"] = fixture.ancestor
            else:
                request, paths = setup(provider, "repositories.read", ["owner", "repo"], {"view": "tree", "ref": fixture.initial})
                upstream.state["native"] = fixture.handle
                if failure == "exact_tree":
                    for path in (paths[0] + "/permissions", paths[1]):
                        vault.state["documents"][path]["scopes"] = [{"operation": "repositories.read", "root": ["owner", "repo"], "descendants": False}]
                else: fixture.unsafe = "120000"
            if failure not in ("exact_tree", "unsafe_tree"):
                request["call"]["payload"] = json.dumps(payload)
            before = fixture.published
            error = "resource_denied" if failure in ("race", "unsafe_tree", "wrong_head") else "capability_denied"
            check(request, 403, error, 0 if failure not in ("race", "unsafe_tree", "wrong_head") else None)
            assert fixture.published == before
            if failure == "race": assert fixture.head() == fixture.ancestor
    print("PASS: real writer protocol/replay and authenticated GitHub/GitLab checkout/publication fixtures")
    return sdk_calls
