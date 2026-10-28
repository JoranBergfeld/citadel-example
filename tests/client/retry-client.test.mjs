import test from "node:test";
import assert from "node:assert/strict";
import { confirmRetry } from "../../src/citadel/operator/retry-client.mjs";

const form = checked => ({
  dataset: {},
  elements: { namedItem: name => name === "confirmed" ? { checked } : null },
});

test("unchecked confirmation never opens the dialog or authorizes submission", () => {
  assert.equal(confirmRetry(form(false), () => { throw new Error("must not ask"); }), false);
});

test("cancel leaves the form unsent; only a separate confirmation permits one submission", () => {
  const selected = form(true);
  assert.equal(confirmRetry(selected, () => false), false);
  let dialogs = 0;
  assert.equal(confirmRetry(selected, message => {
    dialogs++;
    assert.match(message, /Original inputs, deadline and remaining allowances/);
    return true;
  }), true);
  assert.equal(confirmRetry(selected, () => { throw new Error("duplicate dialog"); }), false);
  assert.equal(dialogs, 1);
});
