import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("ws upgrade handler authenticates upgrades before proxying", () => {
  const src = fs.readFileSync(new URL("../src/server.js", import.meta.url), "utf8");
  const idx = src.indexOf('server.on("upgrade"');
  assert.ok(idx >= 0);
  const window = src.slice(idx, idx + 700);

  assert.match(window, /authorizeDashboardUpgrade\(req, socket\)/);
  assert.doesNotMatch(window, /Do not enforce dashboard Basic auth/);
});
