// Runs gateway/dashboard/static/handoffs.js under Node with a stub DOM,
// sessionStorage and Notification so the notification policy is testable
// without a browser (IDEA-069, ADR-022 decision 8).
//
//   node tests/js/handoffs_harness.js gateway/dashboard/static/handoffs.js open_with_queue
//   node tests/js/handoffs_harness.js gateway/dashboard/static/handoffs.js open_empty_then_queue
//
// Prints one JSON object: the notifications raised by the first page load, the
// total after a repeat poll, and the total after a second page load that shares
// the same sessionStorage. (the reload total is cumulative)
const fs = require("fs");
const vm = require("vm");

const [scriptPath, scenario] = process.argv.slice(2);
const source = fs.readFileSync(scriptPath, "utf8");

const storage = new Map();
const calls = [];
let rows = [];

const row = (id, verdict) => ({
  dataset: {
    handoffId: id,
    handoffVerdict: verdict,
    handoffCreated: "2026-11-18T09:00:00Z",
  },
});

const slot = {
  querySelectorAll: (selector) => {
    if (selector !== "[data-handoff-id]") throw new Error(`unexpected selector ${selector}`);
    return rows.slice();
  },
  querySelector: (selector) => {
    if (selector !== "[data-handoff-id]") throw new Error(`unexpected selector ${selector}`);
    return rows[0] || null;
  },
};

// A page load: fresh script instance, shared sessionStorage, one pump per
// recorded htmx swap (the script's own scan runs at evaluation when rows exist).
function open() {
  const swaps = [];
  const context = {
    document: {
      getElementById: (id) => (id === "handoff-slot" ? slot : null),
      body: { addEventListener: (type, handler) => swaps.push(handler) },
    },
    sessionStorage: {
      getItem: (key) => (storage.has(key) ? storage.get(key) : null),
      setItem: (key, value) => storage.set(key, value),
    },
    Notification: function Notification(title, options) {
      calls.push({ title, body: options.body, tag: options.tag });
    },
  };
  context.Notification.permission = "granted";
  context.window = context;
  vm.createContext(context);
  vm.runInContext(source, context);
  return () => swaps.forEach((handler) => handler({ target: slot }));
}

const result = { firstLoad: 0, afterRepeatPoll: 0, afterReload: 0, calls };

if (scenario === "open_with_queue") {
  rows = [row("conv-new", "frustrated"), row("conv-old", "distress")];
  const page = open();
  result.firstLoad = calls.length;
  page();
  result.afterRepeatPoll = calls.length;
  const reload = open();
  reload();
  result.afterReload = calls.length;
} else if (scenario === "open_empty_then_queue") {
  const page = open();
  result.firstLoad = calls.length;
  rows = [row("conv-late", "frustrated")];
  page();
  result.afterRepeatPoll = calls.length;
  result.afterReload = calls.length;
} else {
  throw new Error(`unknown scenario ${scenario}`);
}

process.stdout.write(`${JSON.stringify(result)}\n`);
