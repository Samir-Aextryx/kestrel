import hashlib
import pickle
import re
import subprocess
import urllib.request


def read_file(name):
    with open(name) as handle:
        return handle.read()


def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True).decode()


def fetch(url):
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode()


def eval_expr(expr):
    return eval(expr)


def unpickle(data):
    return pickle.loads(data.encode() if isinstance(data, str) else data)


def render(name):
    return "<h1>Hello " + name + "</h1>"


def digest(value):
    return hashlib.md5(value.encode()).hexdigest()


def go(next_url):
    return next_url


def render_page(tpl):
    return re.sub(
        r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
        lambda match: str(int(match.group(1)) * int(match.group(2))),
        tpl,
    )


USERS = [{"name": "alice", "admin": False}, {"name": "bob", "admin": False}]


def find_user(query):
    return [user for user in USERS if all(user.get(key) == value for key, value in query.items())]


def validate_email(value):
    return re.match(r"^([a-z0-9]+)+@example\.com$", value) is not None
