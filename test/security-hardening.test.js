import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("import extraction only allows regular files and directories", () => {
  const src = fs.readFileSync(new URL("../src/server.js", import.meta.url), "utf8");
  assert.match(src, /function looksSafeTarEntry\(p, entry\)/);
  assert.match(src, /entry\?\.type === "File"/);
  assert.match(src, /entry\?\.type === "OldFile"/);
  assert.match(src, /entry\?\.type === "Directory"/);
});

test("pairing approval validates channel and code server-side", () => {
  const src = fs.readFileSync(new URL("../src/server.js", import.meta.url), "utf8");
  assert.match(src, /function validatePairingApprovalInput\(channel, code\)/);
  assert.match(src, /normalizedChannel !== "telegram" && normalizedChannel !== "discord"/);
  assert.ok(src.includes('/^[A-Za-z0-9_-]{4,128}$/.test(normalizedCode)'));
});
