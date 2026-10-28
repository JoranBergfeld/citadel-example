// Execution is server-owned. Client refresh never submits or recovers a run.
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
  const selected = () => document.querySelector("main[data-current-run]");
  const warning = (message) => {
    const main = selected();
    if (!main) return;
    main.dataset.state = "unavailable";
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
        }
      } catch {
        warning("stale — refresh unavailable; showing last observation, not current activity or execution failure.");
      }
    },
  });
  document.addEventListener("visibilitychange", loop.changed);
  document.addEventListener("submit", (event) => {
    if (event.target.matches("main[data-current-run] form[data-observation-refresh]")) {
      event.preventDefault();
      void loop.manual();
    }
  });
  globalThis.addEventListener("pagehide", loop.stop);
  globalThis.addEventListener("pageshow", loop.resume);
  loop.changed();
}
