import test from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

function basicAuth(password) {
  return `Basic ${Buffer.from(`user:${password}`, "utf8").toString("base64")}`;
}

async function getFreePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", resolve);
    server.on("error", reject);
  });
  const address = server.address();
  server.close();
  await once(server, "close");
  return address.port;
}

async function startServer(envOverrides = {}) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-auth-test-"));
  const stateDir = path.join(tmpRoot, "state");
  const workspaceDir = path.join(tmpRoot, "workspace");
  const port = await getFreePort();
  const proc = childProcess.spawn(process.execPath, ["src/server.js"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PORT: String(port),
      SETUP_PASSWORD: "test-password",
      OPENCLAW_STATE_DIR: stateDir,
      OPENCLAW_WORKSPACE_DIR: workspaceDir,
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let logs = "";
  const onData = (chunk) => {
    logs += chunk.toString("utf8");
  };
  proc.stdout.on("data", onData);
  proc.stderr.on("data", onData);

  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`server did not start\n${logs}`));
    }, 15_000);

    const checkReady = () => {
      if (logs.includes("[wrapper] listening on")) {
        clearTimeout(timeout);
        cleanup();
        resolve();
      }
    };
    const onExit = (code, signal) => {
      clearTimeout(timeout);
      cleanup();
      reject(new Error(`server exited early code=${code} signal=${signal}\n${logs}`));
    };
    const cleanup = () => {
      proc.off("exit", onExit);
      proc.stdout.off("data", checkReady);
      proc.stderr.off("data", checkReady);
    };

    proc.on("exit", onExit);
    proc.stdout.on("data", checkReady);
    proc.stderr.on("data", checkReady);
    checkReady();
  });

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    workspaceDir,
    async close() {
      if (proc.exitCode !== null) {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
        return;
      }
      proc.kill("SIGTERM");
      await Promise.race([
        once(proc, "exit"),
        new Promise((resolve) => setTimeout(resolve, 5_000)),
      ]);
      if (proc.exitCode === null) proc.kill("SIGKILL");
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    },
  };
}

async function websocketHandshake(baseUrl, extraHeaders = {}) {
  const { hostname, port } = new URL(baseUrl);
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: hostname, port: Number(port) });
    let data = "";

    socket.on("connect", () => {
      const headers = {
        Host: `${hostname}:${port}`,
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
        ...extraHeaders,
      };
      const raw = Object.entries(headers)
        .map(([key, value]) => `${key}: ${value}`)
        .join("\r\n");
      socket.write(`GET /openclaw HTTP/1.1\r\n${raw}\r\n\r\n`);
    });

    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });
    socket.on("end", () => resolve(data));
    socket.on("error", reject);
  });
}

test("Basic auth issues a reusable session cookie for setup and dashboard routes", async (t) => {
  const server = await startServer();
  t.after(() => server.close());

  const loginRes = await fetch(`${server.baseUrl}/setup`, {
    headers: { Authorization: basicAuth("test-password") },
  });
  assert.equal(loginRes.status, 200);

  const setCookie = loginRes.headers.getSetCookie().find((value) => value.startsWith("openclaw_session="));
  assert.ok(setCookie, "expected openclaw_session cookie");
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Strict/i);
  assert.match(setCookie, /Max-Age=259200/i);

  const cookie = setCookie.split(";", 1)[0];

  const jsRes = await fetch(`${server.baseUrl}/setup/app.js`, {
    headers: { Cookie: cookie },
  });
  assert.equal(jsRes.status, 200);

  const dashboardRes = await fetch(`${server.baseUrl}/openclaw`, {
    headers: { Cookie: cookie },
    redirect: "manual",
  });
  assert.equal(dashboardRes.status, 302);
  assert.equal(dashboardRes.headers.get("location"), "/setup");

  const blockedRes = await fetch(`${server.baseUrl}/setup/api/reset`, {
    method: "POST",
    headers: { Cookie: cookie },
  });
  assert.equal(blockedRes.status, 403);

  const allowedRes = await fetch(`${server.baseUrl}/setup/api/reset`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      Origin: server.baseUrl,
    },
  });
  assert.equal(allowedRes.status, 200);
});

test("failed auth attempts are rate limited without locking out valid credentials", async (t) => {
  const server = await startServer({
    OPENCLAW_AUTH_RATE_LIMIT_MAX_ATTEMPTS: "3",
    OPENCLAW_AUTH_RATE_LIMIT_BLOCK_SECONDS: "60",
    OPENCLAW_AUTH_RATE_LIMIT_WINDOW_SECONDS: "60",
  });
  t.after(() => server.close());

  for (let i = 0; i < 2; i += 1) {
    const res = await fetch(`${server.baseUrl}/setup`, {
      headers: { Authorization: basicAuth("wrong-password") },
    });
    assert.equal(res.status, 401);
  }

  const limited = await fetch(`${server.baseUrl}/setup`, {
    headers: { Authorization: basicAuth("wrong-password") },
  });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "60");

  const valid = await fetch(`${server.baseUrl}/setup`, {
    headers: { Authorization: basicAuth("test-password") },
  });
  assert.equal(valid.status, 200);

  const reset = await fetch(`${server.baseUrl}/setup`, {
    headers: { Authorization: basicAuth("wrong-password") },
  });
  assert.equal(reset.status, 401);
});

test("workspace upload stores only new files and rejects overwrites", async (t) => {
  const server = await startServer();
  t.after(() => server.close());

  const loginRes = await fetch(`${server.baseUrl}/setup`, {
    headers: { Authorization: basicAuth("test-password") },
  });
  assert.equal(loginRes.status, 200);

  const setCookie = loginRes.headers.getSetCookie().find((value) => value.startsWith("openclaw_session="));
  assert.ok(setCookie, "expected openclaw_session cookie");
  const cookie = setCookie.split(";", 1)[0];

  const firstRes = await fetch(`${server.baseUrl}/setup/api/workspace/upload`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      Origin: server.baseUrl,
      "Content-Type": "application/octet-stream",
      "X-OpenClaw-Filename": encodeURIComponent("notes.txt"),
    },
    body: Buffer.from("first file\n", "utf8"),
  });
  assert.equal(firstRes.status, 201);
  assert.deepEqual(await firstRes.json(), {
    ok: true,
    fileName: "notes.txt",
    bytes: 11,
  });
  assert.equal(fs.readFileSync(path.join(server.workspaceDir, "notes.txt"), "utf8"), "first file\n");

  const secondRes = await fetch(`${server.baseUrl}/setup/api/workspace/upload`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      Origin: server.baseUrl,
      "Content-Type": "application/octet-stream",
      "X-OpenClaw-Filename": encodeURIComponent("notes.txt"),
    },
    body: Buffer.from("replacement\n", "utf8"),
  });
  assert.equal(secondRes.status, 409);

  const secondJson = await secondRes.json();
  assert.equal(secondJson.ok, false);
  assert.match(secondJson.error, /already exists/i);
  assert.equal(fs.readFileSync(path.join(server.workspaceDir, "notes.txt"), "utf8"), "first file\n");
});

test("websocket upgrades require authentication instead of bypassing it", async (t) => {
  const server = await startServer();
  t.after(() => server.close());

  const response = await websocketHandshake(server.baseUrl);
  assert.match(response, /^HTTP\/1\.1 401 Unauthorized/m);
  assert.match(response, /WWW-Authenticate: Basic realm="OpenClaw Dashboard"/i);
});
