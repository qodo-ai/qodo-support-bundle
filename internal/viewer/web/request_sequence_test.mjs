import assert from "node:assert/strict";
import test from "node:test";

import { RequestSequence } from "./request_sequence.mjs";

test("only the latest detail request remains current", () => {
  const requests = new RequestSequence();
  const first = requests.next();
  const second = requests.next();

  assert.equal(requests.isCurrent(first), false);
  assert.equal(requests.isCurrent(second), true);
});

test("dialog close or cluster selection invalidates pending details", () => {
  const requests = new RequestSequence();
  const pending = requests.next();

  requests.invalidate();

  assert.equal(requests.isCurrent(pending), false);
});
