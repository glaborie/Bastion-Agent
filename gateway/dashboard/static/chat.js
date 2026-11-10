/* Guarded chat page (ADR-012). Model output is untrusted: render with
   textContent only, never innerHTML. */
(() => {
  "use strict";

  const root = document.getElementById("chat-app");
  if (!root) return;

  const endpoint = root.dataset.endpoint;
  const csrf = root.dataset.csrf;
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const send = document.getElementById("chat-send");
  const reset = document.getElementById("chat-reset");
  const log = document.getElementById("chat-log");
  const status = document.getElementById("chat-status");
  const meta = document.getElementById("chat-meta");
  const conversationLabel = document.getElementById("chat-conversation");
  const auditLink = document.getElementById("chat-audit");

  let conversationId = root.dataset.conversationId;
  let history = [];

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  const setStatus = (text, kind) => {
    status.textContent = text || "";
    status.className = kind ? `chat-status ${kind}` : "chat-status";
  };

  const setConversation = (identifier) => {
    conversationId = identifier;
    conversationLabel.textContent = identifier;
    auditLink.href = `/dashboard/sessions/${encodeURIComponent(identifier)}`;
    auditLink.hidden = false;
  };

  const renderTurn = (role, text) => {
    const turn = element("div", `chat-turn chat-${role}`);
    turn.append(element("small", "chat-role", role === "user" ? "You" : "Bastion"));
    turn.append(element("p", "chat-text", text));
    log.append(turn);
    log.scrollTop = log.scrollHeight;
  };

  const renderBadges = (data) => {
    meta.replaceChildren();
    const route = element(
      "span",
      `badge ${data.route === "local-llama" ? "badge-bad" : "badge-ok"}`,
      data.route,
    );
    const label = element(
      "span",
      `badge ${data.classification === "CONFIDENTIAL" ? "badge-bad" : "badge-ok"}`,
      data.classification,
    );
    meta.append(route, label);
    meta.append(
      element(
        "small",
        "chat-meta-text",
        `${data.reason} · ${Math.round(data.confidence * 100)}% · ` +
          `${data.restored_tokens} marker(s) restored`,
      ),
    );
  };

  const readError = async (response) => {
    try {
      const payload = await response.json();
      if (typeof payload.detail === "string") return payload.detail;
    } catch (_error) {
      /* FastAPI always returns JSON, but a proxy may not. */
    }
    return `request failed (${response.status})`;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text || send.disabled) return;

    send.disabled = true;
    setStatus("Routing, calling the model and inspecting the egress…", "pending");
    renderTurn("user", text);
    history.push({ role: "user", content: text });

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
        },
        body: JSON.stringify({ conversation_id: conversationId, messages: history }),
      });
      if (!response.ok) {
        history.pop();
        const detail = await readError(response);
        setStatus(
          response.status === 403 ? `${detail} Start a new conversation.` : detail,
          "error",
        );
        return;
      }
      const data = await response.json();
      history.push(data.message);
      renderTurn("assistant", data.message.content);
      renderBadges(data);
      setConversation(data.conversation_id);
      input.value = "";
      setStatus("Answer released by the egress filter.", "ok");
    } catch (error) {
      history.pop();
      setStatus(`Network error: ${error.message}`, "error");
    } finally {
      send.disabled = false;
      input.focus();
    }
  });

  root.querySelectorAll("[data-prompt]").forEach((button) => {
    button.addEventListener("click", () => {
      input.value = button.dataset.prompt;
      input.focus();
    });
  });

  reset.addEventListener("click", () => {
    const identifier =
      typeof crypto.randomUUID === "function"
        ? crypto.randomUUID()
        : Date.now().toString(36);
    history = [];
    log.replaceChildren();
    meta.replaceChildren();
    input.value = "";
    setStatus("New conversation. The vault and canary are scoped to this id.", "ok");
    setConversation(identifier);
    auditLink.hidden = true;
    input.focus();
  });
})();
