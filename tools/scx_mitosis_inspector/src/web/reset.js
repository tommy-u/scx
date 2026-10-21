(function () {
  "use strict";

  const button = document.querySelector("#resetAllStats");
  const status = document.querySelector("#resetStatsStatus");
  if (!button || !status) return;

  button.addEventListener("click", async () => {
    if (button.disabled) return;
    const confirmed = window.confirm(
      "Reset inspector-owned counters and browser histories? Mitosis scheduler stats and kernel-wide counters will be preserved.",
    );
    if (!confirmed) return;
    button.disabled = true;
    status.textContent = "Resetting";
    window.dispatchEvent(new CustomEvent("mitosis:stats-reset-start"));
    const controller = new AbortController();
    let timer;
    const deadline = new Promise((resolve, reject) => {
      // The server's reset deadline is 15 seconds; allow time for the response.
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("Reset request timed out after 20s"));
      }, 20000);
    });
    try {
      const request = async () => {
        const response = await fetch("/api/reset", { method: "POST", cache: "no-store", signal: controller.signal });
        return { response, ack: await response.json() };
      };
      const { response, ack } = await Promise.race([request(), deadline]);
      if (response.status !== 200) throw new Error(ack.error || `Reset not completed (HTTP ${response.status})`);
      if (ack.scope !== "inspector" || !Number.isSafeInteger(ack.epoch) || ack.epoch < 0
          || !Number.isSafeInteger(ack.sample_seq) || ack.sample_seq <= 0
          || !Number.isFinite(ack.reset_at_unix_ms)) throw new Error("Invalid reset acknowledgement");
      window.dispatchEvent(new CustomEvent("mitosis:stats-reset", { detail: ack }));
      status.textContent = "New epoch";
    } catch (error) {
      const message = error.message || String(error);
      status.textContent = `Reset failed: ${message}`;
      window.dispatchEvent(new CustomEvent("mitosis:stats-reset-failed", { detail: { error: message } }));
    } finally {
      clearTimeout(timer);
      button.disabled = false;
    }
  });
})();
