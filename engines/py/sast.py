#!/usr/bin/env python3
"""KESTREL Python taint and misconfiguration analyzer.

Reads a JSON request from stdin: {"root": "...", "files": [{"abs": "...", "rel": "..."}]}
Writes one JSON object per line to stdout.
"""
import ast
import json
import os
import sys

SOURCES = {
    "request.args", "request.form", "request.json", "request.data", "request.body",
    "request.headers", "request.cookies", "request.files", "request.GET", "request.POST",
    "request.query_params", "request.path_params", "request.values", "request.get_json",
    "flask.request", "sys.argv", "input", "event.body", "event.queryStringParameters",
    "self.request", "req",
}
SANITIZERS = {
    "int", "float", "bool", "escape", "markupsafe.escape", "html.escape", "bleach.clean",
    "secure_filename", "quote", "shlex.quote", "url_for", "basename", "os.path.basename",
    "Path.resolve", "resolve", "uuid.UUID", "json.loads", "ast.literal_eval",
}
STRING_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "replace", "format", "split", "join",
    "encode", "decode", "title", "capitalize", "casefold",
}

ROUTE_DECORATORS = ("route", "get", "post", "put", "patch", "delete", "api_route", "websocket")

SEV = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:N",
}

REMEDIATION = {
    "code-injection": "Avoid eval/exec for untrusted data; use ast.literal_eval or a restricted namespace.",
    "command-injection": "Pass an argument list with shell=False, or quote with shlex.quote and allow-list the binary.",
    "sql-injection": "Use bound parameters (`execute(sql, params)`) instead of f-strings or % formatting.",
    "path-traversal": "Resolve against a fixed root with realpath and verify the prefix; reject `..`.",
    "ssrf": "Allow-list schemes and hosts, resolve DNS, reject private/metadata IPs and re-check redirects.",
    "open-redirect": "Only allow relative paths or compare against a fixed host allow-list.",
    "insecure-deserialization": "Use yaml.safe_load, JSON, or a signed pickle protocol with integrity checks.",
    "ssti": "Render with a sandboxed environment or pass only simple values to the template.",
    "weak-hash": "Use SHA-256+ for integrity and Argon2id/scrypt/bcrypt for passwords.",
    "insecure-random": "Use the `secrets` module for tokens and nonces.",
    "tls-verify": "Enable certificate verification or pin the expected CA bundle.",
    "xxe": "Disable entity resolution / network access in the XML parser.",
    "debug": "Disable debug mode in production and set a strong SECRET_KEY.",
    "assert-auth": "Do not rely on assert for security checks; assertions disappear under `python -O`.",
}


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    return ""


def is_source(node):
    name = dotted(node)
    if not name:
        return False
    if name in SOURCES:
        return True
    return any(name.startswith(s + ".") or name.startswith(s + "[") for s in SOURCES)


def is_sanitized(node):
    name = dotted(node)
    if name in SANITIZERS or name.split(".")[-1] in SANITIZERS:
        return True
    if isinstance(node, ast.Call) and (dotted(node.func) in SANITIZERS or dotted(node.func).split(".")[-1] in SANITIZERS):
        return True
    return False


def src(node, source):
    try:
        return ast.get_source_segment(source, node) or ""
    except Exception:
        return ""


def make_taint(node, source):
    return {
        "source": {"line": getattr(node, "lineno", 1), "code": src(node, source)[:240], "name": dotted(node)},
        "sink": None,
        "steps": [],
    }


def merge(a, b):
    if not a:
        return b
    if not b:
        return a
    return {**a, "steps": (a.get("steps", []) + b.get("steps", []))[:8]}


def taint_of(node, scope, source, seen=None):
    if node is None:
        return None
    if seen is None:
        seen = set()
    key = id(node)
    if key in seen:
        return None
    seen.add(key)
    if is_sanitized(node):
        return None
    if is_source(node):
        return make_taint(node, source)
    if isinstance(node, ast.Name):
        return scope.get(node.id)
    if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred, ast.Await)):
        return taint_of(node.value, scope, source, seen)
    if isinstance(node, ast.Call):
        name = dotted(node.func)
        last = name.split(".")[-1]
        if last in STRING_METHODS or name in ("json.loads", "str", "bytes"):
            return taint_of(node.args[0], scope, source, seen) if node.args else None
        result = taint_of(node.func, scope, source, seen)
        for arg in node.args:
            result = merge(result, taint_of(arg, scope, source, seen))
        for kw in node.keywords:
            result = merge(result, taint_of(kw.value, scope, source, seen))
        return result
    if isinstance(node, ast.JoinedStr):
        result = None
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                result = merge(result, taint_of(value.value, scope, source, seen))
        return result
    if isinstance(node, ast.BinOp):
        return merge(taint_of(node.left, scope, source, seen), taint_of(node.right, scope, source, seen))
    if isinstance(node, ast.BoolOp):
        result = None
        for value in node.values:
            result = merge(result, taint_of(value, scope, source, seen))
        return result
    if isinstance(node, ast.IfExp):
        return merge(taint_of(node.body, scope, source, seen), taint_of(node.orelse, scope, source, seen))
    if isinstance(node, (ast.NamedExpr, ast.Assign)):
        return taint_of(node.value, scope, source, seen)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        result = None
        for elt in node.elts:
            result = merge(result, taint_of(elt, scope, source, seen))
        return result
    if isinstance(node, ast.Dict):
        result = None
        for value in node.values:
            result = merge(result, taint_of(value, scope, source, seen))
        return result
    return None


def bind_target(target, taint, scope):
    if not taint:
        return
    if isinstance(target, ast.Name):
        scope[target.id] = taint
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            bind_target(elt, taint, scope)
    elif isinstance(target, ast.Subscript):
        if isinstance(target.value, ast.Name):
            scope[target.value.id] = taint


def route_decorated(node):
    for deco in getattr(node, "decorator_list", []):
        target = deco.func if isinstance(deco, ast.Call) else deco
        name = dotted(target)
        if name.split(".")[-1] in ROUTE_DECORATORS:
            return True
    return False


class Analyzer(ast.NodeVisitor):
    def __init__(self, path, rel, source, emit):
        self.path = path
        self.rel = rel
        self.source = source
        self.emit = emit
        self.scopes = [{}]
        self.seen = set()
        self.function_stack = []

    @property
    def scope(self):
        return self.scopes[-1]

    def report(self, rule, node, title, description, severity, confidence, cwe, owasp, tags, remediation, taint=None, evidence=None):
        line = getattr(node, "lineno", 1)
        key = f"{rule}:{line}"
        if key in self.seen:
            return
        self.seen.add(key)
        lines = self.source.splitlines()
        start = max(0, line - 4)
        end = min(len(lines), line + 3)
        snippet = "\n".join(f"{i + 1:5d} | {lines[i]}" for i in range(start, end))
        self.emit({
            "engine": "sast-python",
            "ruleId": rule,
            "file": self.rel,
            "line": line,
            "column": getattr(node, "col_offset", 0) + 1,
            "snippet": snippet,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "cwe": cwe,
            "owasp": owasp,
            "cvssVector": SEV.get(severity, SEV["medium"]),
            "tags": tags,
            "remediation": remediation,
            "references": [f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"],
            "evidence": evidence or {"code": src(node, self.source)[:500]},
            "taint": taint,
        })

    def visit_FunctionDef(self, node):
        scope = dict(self.scope)
        if route_decorated(node) or (node.col_offset == 0 and not node.name.startswith("_")):
            for arg in node.args.args + node.args.kwonlyargs:
                scope[arg.arg] = {
                    "source": {"line": node.lineno, "code": f"request parameter {arg.arg}", "name": arg.arg},
                    "sink": None,
                    "steps": [],
                }
        self.scopes.append(scope)
        self.function_stack.append(node)
        self.generic_visit(node)
        self.function_stack.pop()
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        taint = taint_of(node.value, self.scope, self.source)
        for target in node.targets:
            bind_target(target, taint, self.scope)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            bind_target(node.target, taint_of(node.value, self.scope, self.source), self.scope)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = dotted(node.func)
        last = name.split(".")[-1]
        taint = None
        arg0 = node.args[0] if node.args else None

        def t0():
            return taint_of(arg0, self.scope, self.source) if arg0 is not None else None

        if last in ("eval", "exec", "compile") and arg0 is not None:
            taint = t0()
            if taint:
                self.report("code-injection", node, "Dynamic code execution with tainted input",
                            f"Tainted data from `{taint['source']['code']}` reaches `{name}()`.", "high", "high",
                            "CWE-95", "A03:2021", ["execution"], REMEDIATION["code-injection"], taint)

        if last in ("system", "popen") and arg0 is not None:
            taint = t0()
            if taint:
                self.report("command-injection", node, "OS command injection",
                            "Tainted input is passed to a shell. Shell metacharacters can break out of the command.",
                            "critical", "high", "CWE-78", "A03:2021", ["execution", "entry"],
                            REMEDIATION["command-injection"], taint)

        if last in ("run", "call", "Popen", "check_output", "check_call") and arg0 is not None:
            shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
            taint = t0()
            if taint and (shell or isinstance(arg0, (ast.JoinedStr, ast.BinOp))):
                self.report("command-injection", node, "Subprocess with shell interpretation",
                            "A tainted command string is executed with shell semantics.", "high", "high",
                            "CWE-78", "A03:2021", ["execution"], REMEDIATION["command-injection"], taint)

        if last in ("execute", "executemany", "text", "raw") and arg0 is not None:
            taint = t0()
            parameterized = len(node.args) > 1 and isinstance(arg0, (ast.Constant, ast.JoinedStr))
            if isinstance(arg0, ast.JoinedStr) or (isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Mod)):
                taint = taint or t0()
                parameterized = False
            if taint and not parameterized:
                self.report("sql-injection", node, "SQL query built from tainted input",
                            "Request data is interpolated into SQL text instead of bound as a parameter.",
                            "critical", "high", "CWE-89", "A03:2021", ["database", "entry"],
                            REMEDIATION["sql-injection"], taint)

        if last in ("open", "read_text", "read_bytes", "send_file", "send_from_directory") and arg0 is not None:
            taint = t0()
            if taint:
                self.report("path-traversal", node, "File access with tainted path",
                            "A user-controlled path reaches the filesystem without a proven root confinement.",
                            "high", "medium", "CWE-22", "A01:2021", ["filesystem"],
                            REMEDIATION["path-traversal"], taint)

        if last in ("get", "post", "put", "request", "urlopen", "head", "patch", "delete") and arg0 is not None:
            if any(x in name for x in ("requests", "httpx", "urllib", "aiohttp", "http")):
                taint = t0()
                if taint:
                    self.report("ssrf", node, "Server-side request with tainted URL",
                                "A user-controlled URL is fetched server-side without host validation.",
                                "high", "high", "CWE-918", "A10:2021", ["network"],
                                REMEDIATION["ssrf"], taint)

        if last == "redirect" and arg0 is not None:
            taint = t0()
            if taint:
                self.report("open-redirect", node, "Open redirect",
                            "A tainted value is used as a redirect target.", "medium", "medium",
                            "CWE-601", "A01:2021", ["network"], REMEDIATION["open-redirect"], taint)

        if last == "load" and "yaml" in name:
            loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not loader:
                self.report("unsafe-yaml", node, "yaml.load without SafeLoader",
                            "PyYAML can construct arbitrary Python objects from untrusted documents.",
                            "high", "high", "CWE-502", "A08:2021", ["deserialization"],
                            "Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader`.", None)

        if last in ("loads", "load") and ("pickle" in name or "marshal" in name):
            self.report("insecure-deserialization", node, "Insecure deserialization",
                        f"`{name}` executes object reconstruction logic and can lead to RCE on hostile data.",
                        "high", "high", "CWE-502", "A08:2021", ["deserialization"],
                        REMEDIATION["insecure-deserialization"], None)

        if last == "render_template_string" and arg0 is not None:
            taint = t0()
            if taint:
                self.report("ssti", node, "Server-side template injection",
                            "A tainted string is compiled as a Jinja template.", "high", "high",
                            "CWE-1336", "A03:2021", ["execution"], REMEDIATION["ssti"], taint)

        if last in ("md5", "sha1") and "hashlib" in name:
            self.report("weak-hash", node, f"Weak hash algorithm ({last})",
                        f"`{last}` is collision-prone and unsuitable for signatures or integrity.",
                        "low", "high", "CWE-328", "A02:2021", ["crypto"],
                        REMEDIATION["weak-hash"], None)

        if last in ("random", "choice", "randint") and name.split(".")[0] == "random":
            parent = self.function_stack[-1] if self.function_stack else None
            context = (parent.name if parent else "") + src(node, self.source)
            if any(x in context.lower() for x in ("token", "secret", "nonce", "session", "reset")):
                self.report("insecure-random", node, "Non-cryptographic random for security value",
                            "The `random` module is predictable and not suitable for tokens.",
                            "medium", "medium", "CWE-338", "A02:2021", ["crypto"],
                            REMEDIATION["insecure-random"], None)

        if last in ("parse", "fromstring") and ("lxml" in name or "etree" in name):
            self.report("xxe", node, "XML parser with potential entity expansion",
                        "lxml resolves entities by default. Hostile XML can read local files or trigger SSRF.",
                        "medium", "medium", "CWE-611", "A05:2021", ["xml"],
                        REMEDIATION["xxe"], None)

        if last == "mktemp":
            self.report("mktemp-race", node, "tempfile.mktemp race",
                        "mktemp only returns a name; another process can create the file before use.",
                        "low", "high", "CWE-377", "A01:2021", ["filesystem"],
                        "Use `tempfile.NamedTemporaryFile` or `mkstemp`.", None)

        if last == "mark_safe" and arg0 is not None:
            taint = t0()
            if taint:
                self.report("xss", node, "mark_safe with tainted HTML",
                            "Django will not escape the value.", "medium", "medium",
                            "CWE-79", "A03:2021", ["xss"], "Escape the value or sanitize with bleach.", taint)

        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr == "safe" and isinstance(node.value, ast.Name):
            pass
        self.generic_visit(node)

    def visit_Assert(self, node):
        self.report("assert-auth", node, "Security check implemented with assert",
                    "Assertions are stripped when Python runs with `-O`, silently removing the check.",
                    "low", "low", "CWE-617", "A04:2021", ["logic"],
                    REMEDIATION["assert-auth"], None)
        self.generic_visit(node)


def analyze_file(path, rel, emit):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            source = handle.read()
    except OSError:
        return
    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError as exc:
        emit({"engine": "sast-python", "ruleId": "parse-error", "file": rel, "line": exc.lineno or 1,
              "title": "Python parse error", "description": str(exc), "severity": "info", "confidence": "high",
              "cwe": "CWE-1104", "owasp": "A06:2021", "tags": ["parse"], "snippet": ""})
        return
    analyzer = Analyzer(path, rel, source, emit)
    analyzer.visit(tree)

    text = source
    if "debug=True" in text:
        emit({"engine": "sast-python", "ruleId": "flask-debug", "file": rel, "line": 1,
              "title": "Flask debug mode enabled", "description": "Debug mode exposes the Werkzeug console, which can lead to RCE if reachable.",
              "severity": "medium", "confidence": "high", "cwe": "CWE-489", "owasp": "A05:2021",
              "cvssVector": SEV["medium"], "tags": ["config"], "snippet": "",
              "remediation": REMEDIATION["debug"], "references": ["https://cwe.mitre.org/data/definitions/489.html"]})
    if "verify=False" in text:
        emit({"engine": "sast-python", "ruleId": "tls-verify", "file": rel, "line": 1,
              "title": "TLS verification disabled", "description": "requests/httpx call uses verify=False.",
              "severity": "medium", "confidence": "high", "cwe": "CWE-295", "owasp": "A02:2021",
              "cvssVector": SEV["medium"], "tags": ["tls"], "snippet": "",
              "remediation": REMEDIATION["tls-verify"], "references": ["https://cwe.mitre.org/data/definitions/295.html"]})
    if "CORS(" in text and "origins" not in text:
        emit({"engine": "sast-python", "ruleId": "cors-wildcard", "file": rel, "line": 1,
              "title": "CORS enabled without origin restriction", "description": "flask-cors defaults to all origins.",
              "severity": "low", "confidence": "medium", "cwe": "CWE-942", "owasp": "A05:2021",
              "cvssVector": SEV["low"], "tags": ["config", "cors"], "snippet": "",
              "remediation": "Pass an explicit `origins=[...]` allow-list.",
              "references": ["https://cwe.mitre.org/data/definitions/942.html"]})


def main():
    request = json.load(sys.stdin)
    for item in request.get("files", []):
        analyze_file(item["abs"], item["rel"], lambda obj: print(json.dumps(obj, ensure_ascii=False), flush=True))


if __name__ == "__main__":
    main()
