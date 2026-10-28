import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRefresh, activityState, inspectionPath } from "../../src/citadel/operator/scenario-client.mjs";

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

test("activity requires fresh run-bound owner evidence, never running or authored order", () => {
  const view = { run: "run1", owner: "candidate-planner", state: "ok", now: 1000,
    activity: { owner: "candidate-planner", run_id: "run1", kind: "inflight",
      target: "evidence-assessor", observed_at: 995, expires_at: 1010 } };
  assert.deepEqual(activityState(view), { live: true, pulse: true, target: "evidence-assessor", until: 1010 });
  for (const change of [
    { activity: null, execution: "running" }, { state: "denied" }, { state: "unavailable" },
    { stale: true }, { now: 1010 }, { run: "other" }, { owner: "release-reviewer" },
    { now: 990 }, { activity: { ...view.activity, expires_at: 1100 } },
    { activity: { ...view.activity, target: "arbitrary-service" } },
  ]) assert.equal(activityState({ ...view, ...change }).pulse, false);
});

test("reduced motion and animation pause remove pulses, not observed activity or refresh", () => {
  const view = { run: "run1", owner: "evidence-assessor", state: "partial", now: 1000,
    activity: { owner: "evidence-assessor", run_id: "run1", kind: "inflight",
      target: "reference", observed_at: 1000, expires_at: 1015 } };
  for (const change of [{ reducedMotion: true }, { paused: true }]) {
    assert.deepEqual(activityState({ ...view, ...change }),
      { live: true, pulse: false, target: "reference", until: 1015 });
    const f = fixture();
    f.loop.changed();
    assert.equal(f.scheduled(), true);
    assert.deepEqual(f.calls, []);
  }
});

test("node inspection preserves run and exact citations without creating execution URLs", () => {
  assert.equal(inspectionPath("run1", "drafts"), "/teams/evidence/runs/run1");
  assert.equal(inspectionPath("run1", "reference"), "/teams/reference/runs/run1");
  assert.equal(inspectionPath("run1", "briefing-author"), "/teams/planning/runs/run1");
  assert.equal(inspectionPath("run1", "findings", { artifact_id: "finding1", version: 2 }),
    "/teams/evidence/runs/run1/findings/finding1/versions/2");
  for (const node of ["ui", "backend", "apim", "gateway", "model", "reference-storage"]) {
    assert.match(inspectionPath("run1", node), /^#architecture-/);
  }
  assert.throws(() => inspectionPath("../run", "drafts"));
  assert.throws(() => inspectionPath("run1", "findings", { artifact_id: "finding1", version: 0 }));
});

test("current-run client protects retry controls inserted by a later observation", () => {
  const module = new URL("../../src/citadel/operator/scenario-client.mjs", import.meta.url).href;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import assert from "node:assert/strict";
    const listeners = [];
    globalThis.document = {
      visibilityState: "visible", querySelector: () => null,
      addEventListener: (name, handler) => { if (name === "submit") listeners.push(handler); },
    };
    globalThis.matchMedia = () => ({ matches: false, addEventListener() {} });
    globalThis.addEventListener = () => {};
    globalThis.fetch = () => { throw new Error("Observation/presentation must not execute work"); };
    await import(${JSON.stringify(module)});
    let asked = 0, prevented = false;
    globalThis.confirm = () => { asked++; return false; };
    const form = {
      dataset: {}, elements: { namedItem: () => ({ checked: true }) },
      matches: selector => selector === "form[data-retry-run]",
    };
    listeners.forEach(handler => handler({ target: form, preventDefault: () => { prevented = true; } }));
    assert.equal(asked, 1);
    assert.equal(prevented, true);
    assert.equal(form.dataset.retryPending, undefined);
  `], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
