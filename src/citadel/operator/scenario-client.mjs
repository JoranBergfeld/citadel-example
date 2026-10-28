// Execution is server-owned. Client refresh never submits or recovers a run.
import "./retry-client.mjs";

const routes = {
  "candidate-planner": ["model", "reference", "evidence-assessor", "findings", "briefing-author"],
  "evidence-assessor": ["model", "reference", "release-reviewer"],
  "release-reviewer": ["model", "reference"],
  "briefing-author": ["model", "findings"],
};

export function activityState({ activity, state, stale, run, owner, now, paused, reducedMotion }) {
  const live = ["ok", "partial", "empty"].includes(state) && !stale &&
    activity?.kind === "inflight" && activity.owner === owner && activity.run_id === run &&
    routes[owner]?.includes(activity.target) && Number.isFinite(activity.observed_at) &&
    Number.isFinite(activity.expires_at) && activity.observed_at <= now &&
    now < activity.expires_at && activity.expires_at - activity.observed_at <= 15;
  return live ? { live: true, pulse: !paused && !reducedMotion, target: activity.target,
    until: activity.expires_at } : { live: false, pulse: false, target: null, until: null };
}

export function inspectionPath(run, node, finding) {
  const identity = value => typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value);
  if (!identity(run)) throw new Error("Invalid run");
  if (node === "findings" && finding) {
    if (!identity(finding.artifact_id) || !Number.isSafeInteger(finding.version) || finding.version < 1)
      throw new Error("Exact finding version required");
    return `/teams/evidence/runs/${run}/findings/${finding.artifact_id}/versions/${finding.version}`;
  }
  const team = { reference: "reference", "candidate-planner": "planning", "briefing-author": "planning",
    records: "planning", "evidence-assessor": "evidence", "release-reviewer": "evidence",
    drafts: "evidence", findings: "evidence" }[node];
  if (team) return `/teams/${team}/runs/${run}`;
  if (!["ui", "backend", "apim", "gateway", "model", "reference-storage", "evidence-storage",
    "planning-storage"].includes(node)) throw new Error("Unknown architecture node");
  return `#architecture-${node}`;
}

export function createRefresh({ current, visible, refresh, later = setTimeout, cancel = clearTimeout }) {
  let timer = null;
  let pending = null;
  let stopped = false;
  const eligible = () => {
    const view = current();
    return !stopped && visible() && view?.current && view.run &&
      ["pending", "running"].includes(view.execution) && view.state !== "exhausted";
  };
  const changed = () => {
    if (timer !== null) cancel(timer);
    timer = null;
    if (eligible() && !pending) timer = later(() => { timer = null; return run(true); }, 15000);
  };
  const run = (automatic) => {
    if (pending) return pending;
    if (stopped || (automatic && !eligible())) return Promise.resolve();
    if (timer !== null) cancel(timer);
    timer = null;
    pending = Promise.resolve(refresh(automatic)).finally(() => {
      pending = null;
      changed();
    });
    return pending;
  };
  return { changed, manual: () => run(false), stop: () => { stopped = true; changed(); },
    resume: () => { stopped = false; changed(); } };
}

if (typeof document !== "undefined") {
  let paused = false;
  let expiry = null;
  const motion = globalThis.matchMedia("(prefers-reduced-motion: reduce)");
  const selected = () => document.querySelector("main[data-current-run]");
  const present = () => {
    if (expiry !== null) clearTimeout(expiry);
    expiry = null;
    const flow = document.querySelector("[data-flow-run]");
    if (!flow) return;
    const run = flow.dataset.flowRun;
    const now = Date.now() / 1000;
    let until = Infinity;
    flow.dataset.motion = paused || motion.matches ? "static" : "animated";
    flow.querySelectorAll("[data-pulse]").forEach(node => node.removeAttribute("data-pulse"));
    flow.querySelectorAll("[data-live]").forEach(node => node.removeAttribute("data-live"));
    flow.querySelectorAll("[data-inspect-node]").forEach(node => {
      node.setAttribute("href", inspectionPath(run, node.dataset.inspectNode));
    });
    flow.querySelectorAll("[data-owner-activity]").forEach(item => {
      const owner = item.dataset.ownerActivity;
      const activity = {
        owner, run_id: item.dataset.run, kind: item.dataset.kind, target: item.dataset.target,
        observed_at: Number(item.dataset.observedAt), expires_at: Number(item.dataset.expiresAt),
      };
      const state = activityState({ activity, owner, run, now, paused, reducedMotion: motion.matches,
        state: item.dataset.state, stale: item.dataset.stale === "true" });
      const label = item.querySelector("[data-activity-label]");
      if (label) label.textContent = state.live ? item.dataset.action :
        "Current activity unknown. Last observed: " + (item.dataset.action || "no in-flight call evidenced");
      if (!state.live) return;
      until = Math.min(until, state.until);
      for (const selector of [`[data-node="${owner}"]`, `[data-route="${owner}:${state.target}"]`]) {
        flow.querySelectorAll(selector).forEach(node => {
          node.dataset.live = "true";
          if (state.pulse) node.dataset.pulse = "true";
        });
      }
    });
    const button = flow.querySelector("[data-animation-toggle]");
    if (button) {
      button.setAttribute("aria-pressed", String(paused));
      button.textContent = paused ? "Resume animation" : "Pause animation";
    }
    if (globalThis.location.hash.startsWith("#architecture-")) {
      const target = document.getElementById(globalThis.location.hash.slice(1));
      const detail = target?.closest("details");
      if (detail) detail.open = true;
    }
    if (Number.isFinite(until)) expiry = setTimeout(present, Math.max(1, (until - now) * 1000));
  };
  const warning = (message) => {
    const main = selected();
    if (!main) return;
    main.dataset.state = "unavailable";
    document.querySelectorAll("[data-owner-activity]").forEach(item => { item.dataset.stale = "true"; });
    present();
    let notice = main.querySelector("[data-refresh-warning]");
    if (!notice) {
      notice = document.createElement("aside");
      notice.dataset.refreshWarning = "";
      main.prepend(notice);
    }
    notice.textContent = message;
  };
  const loop = createRefresh({
    current: () => {
      const main = selected();
      return main ? { run: main.dataset.currentRun, execution: main.dataset.execution,
        state: main.dataset.state, current: true } : null;
    },
    visible: () => document.visibilityState === "visible",
    refresh: async (automatic) => {
      const main = selected();
      const form = main?.querySelector("form[data-observation-refresh]");
      if (!form) return;
      try {
        const response = await fetch(form.action, {
          method: "POST", credentials: "same-origin", redirect: "error",
          signal: AbortSignal.timeout(30000),
          headers: { "Content-Type": "application/x-www-form-urlencoded",
            "X-Citadel-Refresh": automatic ? "automatic" : "manual" },
          body: new URLSearchParams(new FormData(form)),
        });
        if (response.status === 401 || response.status === 403) {
          warning("Observation denied or session expired. Last observed data is stale; log in explicitly. No submission is replayed.");
          loop.stop();
          return;
        }
        if (!response.ok) throw new Error("Observation unavailable");
        const parsed = new DOMParser().parseFromString(await response.text(), "text/html");
        const next = parsed.querySelector("main[data-current-run]");
        if (!next || next.dataset.currentRun !== main.dataset.currentRun) throw new Error("Unknown observation");
        if (selected() === main) {
          const region = main.closest("[data-run-observation]");
          const replacement = parsed.querySelector("[data-run-observation]");
          if (region && replacement) region.replaceWith(replacement);
          else main.replaceWith(next);
          present();
        }
      } catch {
        warning("stale — refresh unavailable; showing last observation, not current activity or execution failure.");
      }
    },
  });
  document.addEventListener("visibilitychange", () => { present(); loop.changed(); });
  document.addEventListener("click", event => {
    if (event.target.closest("[data-animation-toggle]")) {
      paused = !paused;
      present();
    }
    const anchor = event.target.closest('a[href^="#architecture-"]');
    if (anchor) {
      const target = document.querySelector(anchor.getAttribute("href"));
      const detail = target?.closest("details");
      if (detail) detail.open = true;
    }
  });
  motion.addEventListener("change", present);
  document.addEventListener("submit", (event) => {
    if (event.target.matches("main[data-current-run] form[data-observation-refresh]")) {
      event.preventDefault();
      void loop.manual();
    }
  });
  globalThis.addEventListener("pagehide", () => { loop.stop(); clearTimeout(expiry); });
  globalThis.addEventListener("pageshow", () => { present(); loop.resume(); });
  present();
  loop.changed();
}
