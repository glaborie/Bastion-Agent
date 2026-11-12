// Colour-scheme control (ADR-007 decision 1).
//
// The server already rendered the stored theme into <html data-theme>, so this
// file is progressive enhancement only: it applies a click immediately instead
// of reloading the page. With JavaScript disabled the form posts normally and
// the server persists the choice. The cookie is HttpOnly, so the browser never
// reads or writes it here; the POST does.
(() => {
  "use strict";

  const COOKIE_THEME_ATTRIBUTE = "data-theme";
  const SYSTEM = "system";

  function apply(theme) {
    const root = document.documentElement;
    if (theme === SYSTEM) {
      root.removeAttribute(COOKIE_THEME_ATTRIBUTE);
    } else {
      root.setAttribute(COOKIE_THEME_ATTRIBUTE, theme);
    }
    for (const button of document.querySelectorAll("[data-theme-form] .theme-option")) {
      button.setAttribute("aria-pressed", button.value === theme ? "true" : "false");
    }
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-theme-form] .theme-option");
    if (!button || !button.form) {
      return;
    }
    event.preventDefault();

    const form = button.form;
    const body = new URLSearchParams(new FormData(form));
    body.set("theme", button.value);

    fetch(form.action, {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      body,
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`theme rejected: ${response.status}`);
        }
        apply(button.value);
      })
      .catch(() => {
        // No fetch, no CSRF token, or a refused request: let the plain form
        // submit so the server can still persist the choice.
        form.submit();
      });
  });
})();
