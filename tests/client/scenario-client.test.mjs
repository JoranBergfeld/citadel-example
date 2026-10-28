import test from "node:test";
import assert from "node:assert/strict";
import { createRefresh } from "../../src/citadel/operator/scenario-client.mjs";

function fixture() {
  let visible = true;
  let snapshot = { run: "run1", execution: "running", state: "ok", current: true };
  let timer = null;
  let calls = [];
  let release;
  const loop = createRefresh({
    visible: () => visible,
    current: () => snapshot,
    later: (callback, delay) => { assert.equal(delay, 15000); timer = callback; return 1; },
    cancel: () => { timer = null; },
    refresh: (automatic) => { calls.push(automatic); return new Promise(resolve => { release = resolve; }); },
  });
  return {
    loop, calls,
    tick: () => { const callback = timer; timer = null; return callback?.(); },
    setVisible: value => { visible = value; loop.changed(); },
    set: value => { snapshot = { ...snapshot, ...value }; },
    release: () => release?.(),
    scheduled: () => timer !== null,
  };
}

test("selected visible active run refreshes after 15s, manual and automatic coalesce", async () => {
  const f = fixture();
  f.loop.changed();
  assert.deepEqual(f.calls, []);
  const pending = f.tick();
  const manual = f.loop.manual();
  assert.deepEqual(f.calls, [true]);
  f.release();
  await Promise.all([pending, manual]);
  assert.equal(f.scheduled(), true);
});

test("hidden, history, terminal, exhausted and unknown selections never poll", async () => {
  for (const change of [
    { current: false }, { execution: "succeeded" }, { execution: "indeterminate" },
    { execution: "unknown" }, { state: "exhausted" }, { run: null },
  ]) {
    const f = fixture();
    f.loop.changed();
    f.set(change);
    f.loop.changed();
    assert.equal(f.scheduled(), false);
    assert.deepEqual(f.calls, []);
  }
  const f = fixture();
  f.loop.changed();
  f.setVisible(false);
  assert.equal(f.scheduled(), false);
  f.setVisible(true);
  assert.equal(f.scheduled(), true);
});

test("a completed observation halts; failure never invents success or retries submission", async () => {
  const f = fixture();
  f.loop.changed();
  const pending = f.tick();
  f.set({ execution: "succeeded" });
  f.release();
  await pending;
  assert.equal(f.scheduled(), false);
  assert.deepEqual(f.calls, [true]);
  f.loop.stop();
});

test("returning through browser history resumes observation, never submission", () => {
  const f = fixture();
  f.loop.changed();
  f.loop.stop();
  assert.equal(f.scheduled(), false);
  f.loop.resume();
  assert.equal(f.scheduled(), true);
  assert.deepEqual(f.calls, []);
});
