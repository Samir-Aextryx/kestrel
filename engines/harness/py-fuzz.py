#!/usr/bin/env python3
"""KESTREL Python fuzzing harness. Reads JSONL on stdin, writes JSONL on stdout."""
import builtins
import importlib.util
import io
import json
import os
import subprocess
import sys
import time
import traceback
import urllib.request
import socket
import shutil

MODULE_PATH = sys.argv[1]
FUNC_NAME = sys.argv[2]
effects = []
active = False


def record(effect):
    if active and len(effects) < 40:
        effects.append(effect)


_open = builtins.open
_subprocess_run = subprocess.run
_check_output = subprocess.check_output
_popen = subprocess.Popen
_system = os.system
_urlopen = urllib.request.urlopen
_create_connection = socket.create_connection


def patched_open(file, *args, **kwargs):
    mode = args[0] if args else kwargs.get("mode", "r")
    record({"type": "fs", "op": "write" if any(c in str(mode) for c in "wax+") else "read", "path": str(file)})
    return _open(file, *args, **kwargs)


def patched_run(*args, **kwargs):
    record({"type": "exec", "command": str(args[0] if args else kwargs.get("args"))[:300]})
    return _subprocess_run(*args, **kwargs)


def patched_check_output(*args, **kwargs):
    record({"type": "exec", "command": str(args[0] if args else kwargs.get("args"))[:300]})
    return _check_output(*args, **kwargs)


def patched_popen(*args, **kwargs):
    record({"type": "exec", "command": str(args[0] if args else kwargs.get("args"))[:300]})
    return _popen(*args, **kwargs)


def patched_remove(path, *args, **kwargs):
    record({"type": "fs", "op": "unlink", "path": str(path)})
    return os.remove(path, *args, **kwargs)


def patched_rename(a, b, *args, **kwargs):
    record({"type": "fs", "op": "rename", "path": f"{a} -> {b}"})
    return os.rename(a, b, *args, **kwargs)


def patched_system(cmd):
    record({"type": "exec", "command": str(cmd)[:300]})
    return _system(cmd)


def patched_urlopen(url, *args, **kwargs):
    record({"type": "network", "url": str(getattr(url, "full_url", url))[:300]})
    return _urlopen(url, *args, **kwargs)


def patched_connect(address, *args, **kwargs):
    record({"type": "network", "url": f"{address[0]}:{address[1]}" if isinstance(address, tuple) else str(address)})
    return _create_connection(address, *args, **kwargs)


builtins.open = patched_open
subprocess.run = patched_run
subprocess.check_output = patched_check_output
subprocess.Popen = patched_popen
os.remove = patched_remove
os.rename = patched_rename
os.system = patched_system
urllib.request.urlopen = patched_urlopen
socket.create_connection = patched_connect

spec = importlib.util.spec_from_file_location("kestrel_target", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules["kestrel_target"] = module
spec.loader.exec_module(module)
fn = getattr(module, FUNC_NAME, None)
if not callable(fn):
    print(json.dumps({"fatal": f"function {FUNC_NAME} not found"}), flush=True)
    sys.exit(2)

covered = set()


def tracer(frame, event, arg):
    if event == "line":
        covered.add((frame.f_code.co_filename, frame.f_lineno))
    return tracer


def safe(value, depth=0):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, bytes):
        return {"__type": "bytes", "length": len(value)}
    if depth > 3:
        return {"__type": "object"}
    if isinstance(value, (list, tuple)):
        return [safe(v, depth + 1) for v in value[:20]]
    if isinstance(value, dict):
        return {str(k): safe(v, depth + 1) for k, v in list(value.items())[:20]}
    return {"__type": type(value).__name__, "repr": repr(value)[:300]}


for line in sys.stdin:
    if not line.strip():
        continue
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    active = True
    effects.clear()
    covered.clear()
    started = time.perf_counter()
    result = None
    error = None
    try:
        sys.settrace(tracer)
        result = fn(*(item.get("args") or []))
        if hasattr(result, "__await__"):
            import asyncio
            result = asyncio.run(result)
    except BaseException as exc:  # noqa: BLE001
        error = {"name": type(exc).__name__, "message": str(exc)[:1000]}
        error["trace"] = traceback.format_exc(limit=4)[-1500:]
    finally:
        sys.settrace(None)
        active = False
    elapsed = (time.perf_counter() - started) * 1_000_000
    print(json.dumps({
        "id": item.get("id"),
        "result": safe(result),
        "error": error,
        "effects": list(effects),
        "elapsedUs": elapsed,
        "coverage": {"offsets": [f"{f}:{l}" for f, l in sorted(covered)], "total": len(covered)},
    }, default=str), flush=True)
