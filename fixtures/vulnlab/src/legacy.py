import hashlib
import pickle
import subprocess

import yaml


class _Args:
    def get(self, key, default=None):
        return default


class _Request:
    args = _Args()


class _App:
    def run(self, debug=False):
        return debug


request = _Request()
app = _App()


def route(path):
    def decorator(fn):
        return fn
    return decorator


def redirect(url):
    return url


def render_template_string(value):
    return value


@route("/run")
def run():
    cmd = request.args.get("cmd")
    return subprocess.check_output(cmd, shell=True)


@route("/eval")
def evaluate():
    expr = request.args.get("expr")
    return str(eval(expr))


@route("/load")
def load():
    raw = request.args.get("yaml")
    return str(yaml.load(raw))


@route("/pickle")
def unpickle():
    raw = request.args.get("data")
    return str(pickle.loads(raw.encode()))


@route("/read")
def read():
    name = request.args.get("name")
    with open(name) as handle:
        return handle.read()


@route("/tpl")
def tpl():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")


@route("/go")
def go():
    return redirect(request.args.get("next"))


@route("/hash")
def hash_value():
    return hashlib.md5(request.args.get("v").encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
