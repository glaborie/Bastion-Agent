/* Live approval queue: WebSocket first, 3 s polling as the degraded fallback.
 *
 * The socket is read-only and authenticated by the same session cookie and CSRF
 * token as the HTML page. Every message means "re-read the queue through the
 * tenant-scoped HTTP route"; the socket never carries ticket arguments. No
 * inline script is used, so the dashboard CSP stays script-src 'self'.
 */
(() => {
  "use strict";

  const POLL_INTERVAL_MS = 3000;
  const RETRY_MIN_MS = 3000;
  const RETRY_MAX_MS = 30000;

  let socket = null;
  let pollTimer = null;
  let retryTimer = null;
  let retryDelay = RETRY_MIN_MS;
  let inFlight = false;
  let queued = false;
  let stopped = false;

  function approvalsRoot() {
    return document.getElementById("approvals");
  }

  function refresh() {
    if (stopped || !approvalsRoot() || !window.htmx) {
      return;
    }
    if (inFlight) {
      queued = true;
      return;
    }
    inFlight = true;
    Promise.resolve(
      window.htmx.ajax("GET", "/api/approvals", {
        target: "#approvals",
        swap: "outerHTML",
      })
    ).finally(() => {
      inFlight = false;
      if (queued && !stopped) {
        queued = false;
        refresh();
      }
    });
  }

  function startPolling() {
    if (pollTimer || stopped) {
      return;
    }
    pollTimer = window.setInterval(refresh, POLL_INTERVAL_MS);
  }

  function stopPolling() {
    if (pollTimer) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function scheduleReconnect() {
    if (stopped || retryTimer) {
      return;
    }
    retryTimer = window.setTimeout(() => {
      retryTimer = null;
      connect();
    }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, RETRY_MAX_MS);
  }

  function connect() {
    if (stopped || socket || !window.WebSocket) {
      return;
    }
    const root = approvalsRoot();
    if (!root) {
      return;
    }
    const csrf = root.dataset.csrf || "";
    if (!csrf) {
      startPolling();
      return;
    }
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const url = scheme + "://" + window.location.host + "/ws/approvals";
    // A browser cannot set headers on a WebSocket; the CSRF token rides in the
    // subprotocol so it never appears in the URL or access logs.
    const candidate = new WebSocket(url, ["bastion.csrf." + csrf]);
    socket = candidate;

    candidate.addEventListener("open", () => {
      retryDelay = RETRY_MIN_MS;
      stopPolling();
    });
    candidate.addEventListener("message", () => {
      refresh();
    });
    candidate.addEventListener("error", () => {
      try {
        candidate.close();
      } catch (_error) {
        /* the close event below is the recovery path */
      }
    });
    candidate.addEventListener("close", () => {
      if (socket === candidate) {
        socket = null;
      }
      startPolling();
      scheduleReconnect();
    });
  }

  // Cover the gap between the first paint and the socket opening. If the
  // socket never connects, this timer stays the only refresh path.
  startPolling();
  connect();

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      refresh();
    }
  });
  window.addEventListener("focus", refresh);
  window.addEventListener("pagehide", () => {
    stopped = true;
    stopPolling();
    if (retryTimer) {
      window.clearTimeout(retryTimer);
      retryTimer = null;
    }
    if (socket) {
      socket.close();
      socket = null;
    }
  });
})();
