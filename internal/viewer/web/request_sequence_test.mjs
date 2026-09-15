import assert from "node:assert/strict";
import test from "node:test";

import { RequestSequence } from "./request_sequence.mjs";

test("only the latest detail request remains current", () => {
  const requests = new RequestSequence();
  const first = requests.next();
  const second = requests.next();

  assert.equal(requests.isCurrent(first), false);
  assert.equal(requests.isCurrent(second), true);
  assert.equal(first.signal.aborted, true);
  assert.equal(second.signal.aborted, false);
});

test("dialog close or cluster selection invalidates pending details", () => {
  const requests = new RequestSequence();
  const pending = requests.next();

  requests.invalidate();

  assert.equal(requests.isCurrent(pending), false);
  assert.equal(pending.signal.aborted, true);
});

test("finishing the current request does not abort it", () => {
  const requests = new RequestSequence();
  const request = requests.next();

  requests.finish(request);

  assert.equal(requests.isCurrent(request), true);
  assert.equal(request.signal.aborted, false);
});
