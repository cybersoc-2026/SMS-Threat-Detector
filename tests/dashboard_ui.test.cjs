const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");
const {TextDecoder, TextEncoder} = require("node:util");

class Element {
  constructor(tag = "") {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.handlers = {};
    this.style = {};
    this.dataset = {};
    this.value = "";
    this.textContent = "";
    this.hidden = false;
    this.className = "";
    this.classList = {
      add: (value) => this.setClass(value, true),
      remove: (value) => this.setClass(value, false),
      toggle: (value, force) => this.setClass(value, force ?? !this.classes().has(value)),
      contains: (value) => this.classes().has(value),
    };
  }

  classes() {
    return new Set(this.className.split(/\s+/).filter(Boolean));
  }

  setClass(value, add) {
    const classes = this.classes();
    if (add) classes.add(value);
    else classes.delete(value);
    this.className = [...classes].join(" ");
  }

  addEventListener(type, handler) { this.handlers[type] = handler; }
  append(...nodes) { this.children.push(...nodes); }
  appendChild(node) { this.append(node); return node; }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name === "id") this.id = String(value);
    if (name === "class") this.className = String(value);
    if (name.startsWith("data-")) this.dataset[name.slice(5)] = String(value);
  }
  getAttribute(name) { return this.attributes[name] ?? null; }
  removeAttribute(name) { delete this.attributes[name]; }
  requestSubmit() { return this.handlers.submit({preventDefault() {}}); }
  focus() {}
}

async function render(analysis, events, message = "Share your OTP now.") {
  const html = fs.readFileSync("static/index.html", "utf8");
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)]
    .map(([, id]) => [id, new Element(id)]));
  const historyBody = new Element();
  const document = {
    body: new Element("body"),
    querySelector(selector) {
      if (selector === "#history tbody") return historyBody;
      const id = selector.slice(1);
      if (elements.has(id)) return elements.get(id);
      const find = (element) => {
        if (element.id === id) return element;
        for (const child of element.children) {
          if (child instanceof Element) {
            const result = find(child);
            if (result) return result;
          }
        }
        return null;
      };
      return [...elements.values()].map(find).find(Boolean);
    },
    createElement: (tag) => new Element(tag),
    createElementNS: (_namespace, tag) => new Element(tag),
    createTextNode: (text) => ({textContent: text}),
    addEventListener() {},
  };
  const fetch = async (url) => {
    if (url === "/api/health") {
      return {ok: true, json: async () => ({llm_available: true})};
    }
    if (url === "/api/analyze") return {ok: true, json: async () => analysis};
    const frames = events.map((event) => new TextEncoder()
      .encode(`data: ${JSON.stringify(event)}\n\n`));
    let index = 0;
    return {
      ok: true,
      body: {
        getReader: () => ({
          read: async () => index < frames.length
            ? {value: frames[index++], done: false}
            : {done: true},
        }),
      },
    };
  };
  const context = vm.createContext({
    document,
    fetch,
    performance: {now: () => 10},
    TextDecoder,
    Uint8Array,
    Object,
    Math,
    Date,
    String,
    Number,
    Promise,
  });
  vm.runInContext(fs.readFileSync("static/app.js", "utf8"), context);
  elements.get("message").value = message;
  await elements.get("analysis-form").handlers.submit({preventDefault() {}});
  return elements;
}

const lowRiskSmsAnalysis = {
  risk_label: "risk",
  title: "Low-risk message",
  action: "Use official support.",
  reasons: ["Requests an OTP."],
  llm_available: true,
  details: {
    risk_level: "low",
    risk_score: 18,
    classifier_label: "scam",
    indicators: ["CREDENTIAL_REQUEST"],
    links: [],
    url_analysis: {findings: []},
  },
};

test("dashboard keeps the threat verdict without displaying risk severity", async () => {
  const elements = await render(lowRiskSmsAnalysis, [
    {type: "complete", source: "llm", text: "Validated model explanation."},
  ]);
  assert.equal(elements.get("dial").className, "dial safe");
  assert.equal(elements.has("sevText"), false);
});

test("dashboard displays one recommended action sentence", async () => {
  const elements = await render({
    ...lowRiskSmsAnalysis,
    action: "Do not tap the link; check through the official app.",
  }, []);
  assert.equal(
    elements.get("action").textContent,
    "Do not tap the link; check through the official app.",
  );
  assert.equal(elements.get("action").children.length, 0);
});

test("dashboard highlights both SMS and URL for a mixed threat", async () => {
  const mixedAnalysis = {
    ...lowRiskSmsAnalysis,
    title: "Suspicious message",
    details: {
      ...lowRiskSmsAnalysis.details,
      risk_level: "medium",
      risk_score: 40,
      links: ["https://example.invalid"],
      url_analysis: {findings: [{prediction: "phishing"}]},
    },
  };
  const elements = await render(
    mixedAnalysis,
    [
      {type: "token", text: "Validated "},
      {type: "token", text: "model explanation."},
      {type: "complete", source: "llm", text: "Validated model explanation."},
    ],
    "Share your OTP at https://example.invalid",
  );
  assert.equal(elements.get("dial").className, "dial threat");
  const pie = elements.get("pie");
  const labels = pie.children.filter((node) => node.tag === "text").map((node) => node.textContent);
  const active = pie.children
    .filter((node) => node.tag === "path" && node.attributes.fill !== "#e6e9eb");
  assert.deepEqual(labels, ["SMS", "URL", "Network"]);
  assert.equal(active.length, 2);
  assert.equal(elements.get("explanation").textContent, "Validated model explanation.");
});

test("dashboard explains when an unvalidated LLM draft falls back to the vetted template", async () => {
  const elements = await render(lowRiskSmsAnalysis, [
    {type: "token", text: "Draft explanation."},
    {
      type: "complete",
      source: "template",
      reason: "rejected: length",
      text: "Vetted template explanation.",
    },
  ]);
  assert.equal(
    elements.get("explanation").textContent,
    "Vetted template explanation.",
    `UI error: ${elements.get("error").textContent}`,
  );
  assert.match(elements.get("explanation-source").textContent, /rejected: length/);
});
