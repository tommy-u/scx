(function () {
  "use strict";

  const button = document.querySelector("#resetAllStats");
  const status = document.querySelector("#resetStatsStatus");
  if (!button || !status) return;

  button.addEventListener("click", async () => {
    const confirmed = window.confirm(
      "Reset inspector-owned counters and browser histories? Mitosis scheduler stats and kernel-wide counters will be preserved.",
    );
    if (!confirmed) return;
    button.disabled = true;
    status.textContent = "Resetting";
    try {
      const response = await fetch("/api/reset", { method: "POST", cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      window.dispatchEvent(new CustomEvent("mitosis:stats-reset"));
      status.textContent = "New epoch";
    } catch {
      status.textContent = "Reset failed";
    } finally {
      button.disabled = false;
    }
  });
})();
