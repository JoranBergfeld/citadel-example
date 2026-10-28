// Confirmation is presentation only; the owner independently checks eligibility.
export function confirmRetry(form, ask) {
  if (form.dataset.retryPending || !form.elements.namedItem("confirmed")?.checked) return false;
  if (!ask("Retry this same run? Original inputs, deadline and remaining allowances are unchanged. Partial or unknown effects cannot be replayed.")) return false;
  form.dataset.retryPending = "true";
  return true;
}

if (typeof document !== "undefined") {
  document.addEventListener("submit", (event) => {
    if (!event.target.matches("form[data-retry-run]")) return;
    if (!confirmRetry(event.target, message => globalThis.confirm(message))) event.preventDefault();
  });
}
