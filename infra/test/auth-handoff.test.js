// Unit tests for the CloudFront Function. Run: node --test infra/test
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Load the function the way CloudFront does: a script that defines handler().
const code = fs.readFileSync(path.join(__dirname, "..", "functions", "auth-handoff.js"), "utf8");
const sandbox = { Date };
vm.createContext(sandbox);
vm.runInContext(code, sandbox);
const handler = sandbox.handler;

const inOneHour = () => String(Math.floor(Date.now() / 1000) + 3600);
const qs = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, { value: v }]));
const call = (uri, query = {}, method = "GET") => handler({ request: { method, uri, querystring: qs(query) } });
const good = () => ({ p: "eyJTdGF0ZW1lbnQ-", s: "abc_DEF~123-", k: "K2ABCDEF", e: inOneHour(), n: "/docs/a.html" });

test("set: stores the four cookies on this host and redirects to n", () => {
  const r = call("/_auth/set", good());
  assert.strictEqual(r.statusCode, 303);
  assert.strictEqual(r.headers.location.value, "/docs/a.html");
  assert.deepStrictEqual(Object.keys(r.cookies).sort(), [
    "CloudFront-Hash-Algorithm", "CloudFront-Key-Pair-Id", "CloudFront-Policy", "CloudFront-Signature",
  ]);
  assert.strictEqual(r.cookies["CloudFront-Hash-Algorithm"].value, "SHA256");
  assert.strictEqual(r.cookies["CloudFront-Policy"].value, "eyJTdGF0ZW1lbnQ-");
  for (const c of Object.values(r.cookies)) {
    for (const a of ["Path=/", "Secure", "HttpOnly", "SameSite=Lax", "Expires="]) assert.ok(c.attributes.includes(a), a);
    assert.ok(!/domain=/i.test(c.attributes), "must stay host-only");
  }
  assert.strictEqual(r.headers["cache-control"].value, "no-store");
  assert.strictEqual(r.headers["referrer-policy"].value, "no-referrer");
});

test("set: expiry attribute matches e", () => {
  const g = good();
  const r = call("/_auth/set", g);
  const want = new Date(Number(g.e) * 1000).toUTCString();
  assert.ok(r.cookies["CloudFront-Policy"].attributes.endsWith("Expires=" + want));
});

test("set: unsafe or off-site n falls back to the default page", () => {
  for (const n of ["//evil.example/x", "https://evil.example/", "/\\evil", "/a\r\nSet-Cookie: x=1", "evil", "", "/a b", "/_auth/set", "/_public/x.html"]) {
    const r = call("/_auth/set", { ...good(), n });
    assert.strictEqual(r.statusCode, 303, JSON.stringify(n));
    assert.strictEqual(r.headers.location.value, "/index.html", JSON.stringify(n));
  }
});

test("set: missing n uses the default page", () => {
  const { n, ...rest } = good();
  assert.strictEqual(call("/_auth/set", rest).headers.location.value, "/index.html");
});

test("set: malformed or missing parameters are rejected without cookies", () => {
  const bads = [
    { p: "a;b" }, { p: "a b" }, { p: "a\r\nX: y" }, { p: "" }, { p: "a".repeat(2049) },
    { s: "a=b" }, { s: "a+b" }, { s: "a/b" }, { k: "K 1" }, { k: "K;Domain=evil" }, { k: "" },
    { e: "abc" }, { e: "-1" }, { e: "1.5" }, { e: "" },
  ];
  for (const patch of bads) {
    const r = call("/_auth/set", { ...good(), ...patch });
    assert.strictEqual(r.statusCode, 400, JSON.stringify(patch));
    assert.strictEqual(r.cookies, undefined, JSON.stringify(patch));
  }
  for (const k of ["p", "s", "k", "e"]) {
    const g = good();
    delete g[k];
    assert.strictEqual(call("/_auth/set", g).statusCode, 400, "missing " + k);
  }
});

test("set: expiry in the past or beyond seven days is rejected", () => {
  const now = Math.floor(Date.now() / 1000);
  assert.strictEqual(call("/_auth/set", { ...good(), e: String(now - 1) }).statusCode, 400);
  assert.strictEqual(call("/_auth/set", { ...good(), e: String(now + 8 * 24 * 3600) }).statusCode, 400);
  assert.strictEqual(call("/_auth/set", { ...good(), e: String(now + 7 * 24 * 3600 - 5) }).statusCode, 303);
});

test("set: repeated parameters are ambiguous and rejected", () => {
  const request = { method: "GET", uri: "/_auth/set", querystring: qs(good()) };
  request.querystring.p = { value: "aaa", multiValue: [{ value: "aaa" }, { value: "bbb" }] };
  assert.strictEqual(handler({ request }).statusCode, 400);
});

test("clear: expires all four cookies and redirects to the signed-out page", () => {
  const r = call("/_auth/clear");
  assert.strictEqual(r.statusCode, 303);
  assert.strictEqual(r.headers.location.value, "/_public/signed-out.html");
  assert.strictEqual(Object.keys(r.cookies).length, 4);
  for (const c of Object.values(r.cookies)) {
    assert.ok(c.attributes.includes("Max-Age=0") && c.attributes.includes("Path=/") && c.attributes.includes("1970"));
  }
});

test("other paths and methods", () => {
  assert.strictEqual(call("/_auth/other").statusCode, 404);
  assert.strictEqual(call("/_auth/set", good(), "POST").statusCode, 405);
  assert.strictEqual(call("/_auth/clear", {}, "DELETE").statusCode, 405);
});
