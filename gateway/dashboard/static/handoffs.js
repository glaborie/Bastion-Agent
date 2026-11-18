// Browser notification for a handoff queued while the dashboard is open
// (ADR-022 as amended). Metadata only: the row's data attributes carry the
// conversation id, verdict and timestamp, and nothing else ever reaches the
// notification. No service worker and no push service: this tab is the channel.
(() => {
  const slot = document.getElementById("handoff-slot");
  if (!slot) return;

  const seenKey = "bastion.handoffs.seen";
  const seen = new Set(JSON.parse(sessionStorage.getItem(seenKey) || "[]"));
  // A fresh page summarises what was already queued instead of firing a burst;
  // a page whose sessionStorage already holds the queue only reports new rows.
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

  const summarize = (rows) => {
    if (!supported || Notification.permission !== "granted") return;
    // The panel renders newest first (recent_handoffs orders by id desc).
    const newest = rows[0];
    const verdict = newest.dataset.handoffVerdict || "handoff";
    new Notification("Bastion-Agent: handoffs are waiting for an operator", {
      body: `${rows.length} waiting · newest ${verdict} · conversation ${newest.dataset.handoffId}`,
      tag: "bastion-handoff-queue",
    });
  };

  const scan = () => {
    const rows = [...slot.querySelectorAll("[data-handoff-id]")];
    if (!primed) {
      // One summary for the queue that was already there, never one per row.
      primed = true;
      for (const row of rows) seen.add(row.dataset.handoffId);
      if (rows.length) {
        summarize(rows);
        save();
      }
      return;
    }
    let changed = false;
    for (const row of rows) {
      const id = row.dataset.handoffId;
      if (seen.has(id)) continue;
      seen.add(id);
      changed = true;
      notify(row);
    }
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
  // Always evaluate once: htmx may have completed the first swap before this
  // file was evaluated, and an empty first poll must still count as primed.
  scan();
  syncEnable();
})();
