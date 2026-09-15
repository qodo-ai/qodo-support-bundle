import assert from "node:assert/strict";
import test from "node:test";

import {
  claimViewerSession,
  initializeClaimedViewer,
  sessionClaimHeader,
  takeLauncherToken,
} from "./session.mjs";

test("takeLauncherToken reads and immediately clears window.name", () => {
  const windowObject = { name: "a".repeat(64) };

  assert.equal(takeLauncherToken(windowObject), "a".repeat(64));
  assert.equal(windowObject.name, "");
});

test("takeLauncherToken rejects malformed launcher data", () => {
  const windowObject = { name: "not-a-viewer-token" };

  assert.equal(takeLauncherToken(windowObject), "");
  assert.equal(windowObject.name, "");
});

test("claimViewerSession makes a same-origin custom-header POST", async () => {
  const token = "a".repeat(64);
  let request;
  await claimViewerSession(
    token,
    async (url, options) => {
      request = { url, options };
      return { ok: true };
    },
    "http://127.0.0.1:4321",
  );

  assert.equal(request.url.toString(), "http://127.0.0.1:4321/api/session");
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.credentials, "same-origin");
  assert.deepEqual(request.options.headers, { [sessionClaimHeader]: token });
  assert.equal("body" in request.options, false);
});

test("claimViewerSession exposes an unsuccessful claim status", async () => {
  await assert.rejects(
    claimViewerSession(
      "a".repeat(64),
      async () => ({
        ok: false,
        status: 409,
        statusText: "Conflict",
      }),
      "http://127.0.0.1:4321",
    ),
    (error) => error.status === 409,
  );
});

test("initializeClaimedViewer retains its token and retries without reclaiming", async () => {
  const session = {
    accessToken: "a".repeat(64),
    sessionClaimed: false,
  };
  let claims = 0;
  let initializations = 0;
  const initialize = async () => {
    initializations += 1;
    if (initializations === 1) {
      throw new Error("temporary endpoint failure");
    }
  };
  const claim = async (token) => {
    assert.equal(token, session.accessToken);
    claims += 1;
  };

  await assert.rejects(
    initializeClaimedViewer(session, initialize, claim),
    /temporary endpoint failure/,
  );
  assert.equal(session.accessToken, "a".repeat(64));
  assert.equal(session.sessionClaimed, true);

  await initializeClaimedViewer(session, initialize, claim);
  assert.equal(claims, 1);
  assert.equal(initializations, 2);
});

test("initializeClaimedViewer retries a transient claim failure with the retained token", async () => {
  const session = {
    accessToken: "a".repeat(64),
    sessionClaimed: false,
  };
  let claims = 0;
  let initializations = 0;
  const claim = async (token) => {
    assert.equal(token, session.accessToken);
    claims += 1;
    if (claims === 1) {
      throw new Error("temporary claim failure");
    }
  };
  const initialize = async () => {
    initializations += 1;
  };

  await assert.rejects(
    initializeClaimedViewer(session, initialize, claim),
    /temporary claim failure/,
  );
  assert.equal(session.accessToken, "a".repeat(64));
  assert.equal(session.sessionClaimed, false);

  await initializeClaimedViewer(session, initialize, claim);
  assert.equal(claims, 2);
  assert.equal(initializations, 1);
  assert.equal(session.sessionClaimed, true);
});
