// Browser notification for a handoff queued while the dashboard is open
// (ADR-022 as amended). Metadata only: the row's data attributes carry the
// conversation id, verdict and timestamp, and nothing else ever reaches the
// notification. No service worker and no push service: this tab is the channel.
(() => {
  const slot = document.getElementById("handoff-slot");
  if (!slot) return;

  const seenKey = "bastion.handoffs.seen";
  const seen = new Set(JSON.parse(sessionStorage.getItem(seenKey) || "[]"));
  // The first poll primes the set: rows that were already queued when the page
  // opened are old news, so they do not arrive as a burst of notifications.
  let primed = sessionStorage.getItem(seenKey) !== null;
  const supported = "Notification" in window;
  const enable = document.getElementById("handoff-enable");

  const save = () => sessionStorage.setItem(seenKey, JSON.stringify([...seen].slice(-200)));

  const notify = (row) => {
    if (!supported || Notification.permission !== "granted") return;
    const id = row.dataset.handoffId;
    const verdict = row.dataset.handoffVerdict || "handoff";
    const when = row.dataset.handoffCreated || "";
    new Notification("Bastion-Agent: a conversation is waiting for an operator", {
      body: `${verdict} · conversation ${id}${when ? ` · ${when}` : ""}`,
      tag: `bastion-handoff-${id}`,
    });
  };

  const scan = () => {
    let changed = false;
    for (const row of slot.querySelectorAll("[data-handoff-id]")) {
      const id = row.dataset.handoffId;
      if (seen.has(id)) continue;
      seen.add(id);
      changed = true;
      if (primed) notify(row);
    }
    primed = true;
    if (changed) save();
  };

  const syncEnable = () => {
    if (!enable) return;
    enable.hidden = !supported || Notification.permission !== "default";
  };

  enable?.addEventListener("click", async () => {
    if (!supported) return;
    await Notification.requestPermission();
    syncEnable();
  });

  document.body.addEventListener("htmx:afterSwap", (event) => {
    if (event.target === slot) scan();
  });
  // htmx may have completed the first swap before this file was evaluated.
  if (slot.querySelector("[data-handoff-id]")) scan();
  syncEnable();
})();
