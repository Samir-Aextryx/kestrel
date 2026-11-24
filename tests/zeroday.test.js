import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

process.env.KESTREL_DATA_DIR = await mkdtemp(path.join(os.tmpdir(), "kestrel-zeroday-"));

const { jsFunctions, pyFunctions, familiesForParam, ORACLES } = await import(
  "../server/engines/zeroday.js"
);

function familyIds(fn, index) {
  return familiesForParam(fn, index).map((family) => family.id);
}

test("sink inference catches generically named parameters", () => {
  const source = `
import fs from "node:fs";
export function readIt(x) {
  return fs.readFileSync(x, "utf8");
}
`;
  const [fn] = jsFunctions(source, "src/a.js");
  assert.equal(fn.name, "readIt");
  assert.deepEqual(fn.params, ["x"]);
  assert.ok(familyIds(fn, 0).includes("path-traversal"));
  assert.ok(!familyIds(fn, 0).includes("command-injection"));
});

test("taint follows local variables into sinks", () => {
  const source = `
import { exec } from "node:child_process";
module.exports = {
  runAlias(input) {
    const command = "echo " + input;
    return exec(command);
  },
};
`;
  const [fn] = jsFunctions(source, "src/b.js");
  assert.equal(fn.name, "runAlias");
  assert.ok(familyIds(fn, 0).includes("command-injection"));
});

test("CommonJS object and property exports are discovered", () => {
  const source = `
function first(a) { return a; }
const second = (b) => b;
module.exports = { first, alias: second };
module.exports.third = function (c) { return c; };
`;
  const names = jsFunctions(source, "src/c.js").map((fn) => fn.name);
  assert.deepEqual(names.sort(), ["alias", "first", "third"]);
});

test("Python methods with multi-line signatures are discovered", () => {
  const source = `import urllib.request

class Client:
    async def fetch(self, q,
                    retries=2):
        return urllib.request.urlopen(q)
`;
  const [fn] = pyFunctions(source, "client.py");
  assert.equal(fn.name, "fetch");
  assert.deepEqual(fn.params, ["q", "retries"]);
  assert.ok(familyIds(fn, 0).includes("ssrf"));
});

test("SQL oracle treats a hostile-only database error as a signal", () => {
  const hostile = { error: { name: "Error", message: "SQLITE_ERROR: near \"OR\": syntax error" } };
  const benign = { error: null };
  assert.ok(ORACLES["sql-error-diff"](hostile, benign));

  const identical = { error: { name: "Error", message: "SQLITE_ERROR: no such table" } };
  assert.equal(ORACLES["sql-error-diff"](identical, identical), null);
  assert.equal(ORACLES["sql-error-diff"]({ error: null }, benign), null);
});

test("template and NoSQL oracles separate hostile output from benign output", () => {
  assert.ok(ORACLES["template-eval"]({ result: "49" }, { result: "hello" }));
  assert.equal(ORACLES["template-eval"]({ result: "49" }, { result: "49" }), null);

  assert.ok(ORACLES["nosql-match"]({ result: [{ name: "alice" }] }, { result: [] }));
  assert.equal(ORACLES["nosql-match"]({ result: [{ name: "alice" }] }, { result: [{ name: "bob" }] }), null);
});

test("name hints still select families when no sink is found", () => {
  const [fn] = jsFunctions("export function redirectTo(next) { return next; }", "src/d.js");
  assert.ok(familyIds(fn, 0).includes("open-redirect"));
});
