const form = document.querySelector("#analysis-form");
const submitButton = document.querySelector("#submit");
const messageInput = document.querySelector("#message");
const errorBox = document.querySelector("#error");
const progress = document.querySelector("#progress");
const scanHistory = [];

const TYPES = ["sms", "url", "network"];
const TYPE_NAMES = {sms: "SMS", url: "URL", network: "Network"};
const TYPE_SHORT = {sms: "SMS", url: "URL", network: "Network"};
const TYPE_COLORS = {sms: "#c8413a", url: "#2f7fa6", network: "#d98a1f"};
const SVG_NS = "http://www.w3.org/2000/svg";
let currentCategories = [];

function setList(selector, values, emptyText) {
  const list = document.querySelector(selector);
  list.replaceChildren();
  if (!values?.length) {
    const item = document.createElement("li");
    item.className = "muted";
    item.textContent = emptyText;
    list.append(item);
    return;
  }
  for (const value of values) {
    const item = document.createElement("li");
    item.textContent = value;
    list.append(item);
  }
}

async function post(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload),
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return body;
}

async function streamExplanation(payload, onEvent) {
  const response = await fetch("/api/explain/stream", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  if (!response.body) {
    throw new Error("This browser does not support streamed explanations.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  function dispatch(frame) {
    const data = frame.split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trimStart())
      .join("\n");
    if (data) onEvent(JSON.parse(data));
  }

  while (true) {
    const {value, done} = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), {stream: !done});
    const frames = buffer.split(/\r?\n\r?\n/);
    buffer = frames.pop();
    for (const frame of frames) dispatch(frame);
    if (done) {
      if (buffer.trim()) dispatch(buffer);
      return;
    }
  }
}

function makeSvg(tag, attrs, parent) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) {
    node.setAttribute(name, value);
  }
  if (parent) parent.append(node);
  return node;
}

function drawGauge() {
  const svg = document.querySelector("#gauge");
  svg.replaceChildren();
  const cx = 100;
  const cy = 100;
  const radius = 80;

  const start = Math.PI;
  const end = 2 * Math.PI;
  makeSvg("path", {
    d: `M${cx + radius * Math.cos(start)},${cy + radius * Math.sin(start)} A${radius},${radius} 0 0 1 ${cx + radius * Math.cos(end)},${cy + radius * Math.sin(end)}`,
    fill: "none",
    "stroke-width": 16,
    class: "gauge-arc",
  }, svg);

  const zero = makeSvg("text", {x: 20, y: 118, "text-anchor": "middle", fill: "#5f6f7a", "font-size": 10}, svg);
  zero.textContent = "0";
  const hundred = makeSvg("text", {x: 180, y: 118, "text-anchor": "middle", fill: "#5f6f7a", "font-size": 10}, svg);
  hundred.textContent = "100";
  const needle = makeSvg("g", {id: "needle"}, svg);
  makeSvg("line", {x1: cx, y1: cy, x2: cx, y2: 32, stroke: "#17323f", "stroke-width": 3.5, "stroke-linecap": "round"}, needle);
  makeSvg("circle", {cx, cy, r: 7, fill: "#17323f"}, needle);
  needle.style.transform = "rotate(-90deg)";
}

function riskValue(analysis) {
  const details = analysis.details || {};
  if (Number.isFinite(details.risk_score)) {
    return Math.max(0, Math.min(100, details.risk_score));
  }
  if (Number.isFinite(details.heuristic_score) && Number.isFinite(details.model_support)) {
    return Math.max(0, Math.min(100, details.heuristic_score + details.model_support));
  }
  return null;
}

function riskLevel(analysis, score) {
  const level = String(analysis.details?.risk_level || "").toLowerCase();
  if (["low", "medium", "high"].includes(level)) return level;
  if (score !== null) {
    if (score >= 70) return "high";
    if (score >= 40) return "medium";
    if (score > 0) return "low";
    return "none";
  }
  if (analysis.risk_label === "risk") return "high";
  if (analysis.risk_label === "suspicious") return "medium";
  return "none";
}

function categoriesFor(analysis) {
  const details = analysis.details || {};
  const findings = details.url_analysis?.findings || [];
  const indicators = details.indicators || [];
  const hasSmsEvidence = ["scam", "spam"].includes(details.classifier_label) ||
    indicators.some((indicator) => !["URL_SHORTENER", "IP_ADDRESS_URL", "PUNYCODE_DOMAIN"].includes(indicator));
  const hasUrl = Boolean(details.shortened_link || details.links?.length || findings.length);
  return [
    ...(hasSmsEvidence ? ["sms"] : []),
    ...(hasUrl ? ["url"] : []),
  ];
}

function renderRisk(analysis) {
  const score = riskValue(analysis);
  const scoreElement = document.querySelector("#riskScore");
  scoreElement.textContent = score === null ? "—" : String(Math.round(score));
  scoreElement.className = "score";
  document.querySelector("#score-caption").textContent = score === null
    ? "Evidence score unavailable"
    : "Heuristic evidence; not a probability";
  const needle = document.querySelector("#needle");
  needle.style.transform = `rotate(${-90 + (score || 0) * 1.8}deg)`;
}

function drawTypeCircle() {
  const svg = document.querySelector("#pie");
  svg.replaceChildren();
  const cx = 90;
  const cy = 90;
  const radius = 84;
  const third = (2 * Math.PI) / TYPES.length;

  TYPES.forEach((type, index) => {
    const start = -Math.PI / 2 + index * third;
    const end = start + third;
    const middle = (start + end) / 2;
    const active = currentCategories.includes(type);
    const x1 = cx + radius * Math.cos(start);
    const y1 = cy + radius * Math.sin(start);
    const x2 = cx + radius * Math.cos(end);
    const y2 = cy + radius * Math.sin(end);
    makeSvg("path", {
      d: `M${cx},${cy} L${x1},${y1} A${radius},${radius} 0 0 1 ${x2},${y2} Z`,
      fill: active ? TYPE_COLORS[type] : "#e6e9eb",
      stroke: "#fff",
      "stroke-width": 3,
      class: active ? "sector lit" : "sector",
    }, svg);
    const label = makeSvg("text", {
      x: cx + radius * 0.58 * Math.cos(middle),
      y: cy + radius * 0.58 * Math.sin(middle) + 4,
      "text-anchor": "middle",
      fill: active ? "#fff" : "#8a959c",
      "font-size": 12,
      "font-weight": 700,
    }, svg);
    label.textContent = TYPE_SHORT[type];
  });
  makeSvg("circle", {cx, cy, r: radius, fill: "none", stroke: "#54626b", "stroke-width": 3}, svg);
  svg.setAttribute("aria-label", currentCategories.length
    ? `Current categories: ${currentCategories.map((type) => TYPE_NAMES[type]).join(", ")}`
    : "No threat category detected");
}

function drawBarChart() {
  const svg = document.querySelector("#bar");
  svg.replaceChildren();
  const counts = Object.fromEntries(TYPES.map((type) => [type, 0]));
  for (const record of scanHistory) {
    for (const category of record.categories) counts[category] += 1;
  }

  const left = 46;
  const right = 10;
  const top = 18;
  const bottom = 56;
  const width = 340;
  const height = 250;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const biggest = Math.max(...Object.values(counts));
  const step = biggest <= 30 ? 5 : 10;
  const maxValue = Math.max(5, Math.ceil(biggest / step) * step);
  const ticks = maxValue / step;

  for (let tick = 0; tick <= ticks; tick += 1) {
    const y = top + plotHeight - (plotHeight * tick) / ticks;
    makeSvg("line", {
      x1: left, x2: width - right, y1: y, y2: y,
      stroke: tick === 0 ? "#555" : "#e2e2dc", "stroke-width": 1,
    }, svg);
    const label = makeSvg("text", {
      x: left - 6, y: y + 4, "text-anchor": "end", fill: "#555", "font-size": 11,
    }, svg);
    label.textContent = String(tick * step);
  }

  const slot = plotWidth / TYPES.length;
  const barWidth = 52;
  TYPES.forEach((type, index) => {
    const value = counts[type];
    const barHeight = (plotHeight * value) / maxValue;
    const x = left + index * slot + (slot - barWidth) / 2;
    makeSvg("rect", {
      x, y: top + plotHeight - barHeight, width: barWidth,
      height: value > 0 ? Math.max(barHeight, 2) : 0,
      fill: TYPE_COLORS[type], class: "bar",
    }, svg);
    const count = makeSvg("text", {
      x: x + barWidth / 2, y: top + plotHeight - barHeight - 5,
      "text-anchor": "middle", fill: "#222", "font-size": 12, "font-weight": 700,
    }, svg);
    count.textContent = String(value);
    const name = makeSvg("text", {
      x: x + barWidth / 2, y: top + plotHeight + 16,
      "text-anchor": "middle", fill: "#222", "font-size": 11,
    }, svg);
    name.textContent = TYPE_SHORT[type];
  });
  const title = makeSvg("text", {
    x: left + plotWidth / 2, y: height - 8,
    "text-anchor": "middle", fill: "#555", "font-size": 11,
  }, svg);
  title.textContent = "Threat category";
}

function renderHistory() {
  const body = document.querySelector("#history tbody");
  body.replaceChildren();
  const count = scanHistory.filter((record) => record.isThreat).length;
  const counter = document.querySelector("#odo");
  counter.textContent = String(count);
  counter.className = count ? "bignum has" : "bignum";
  document.querySelector("#histNote").textContent = scanHistory.length
    ? `last ${Math.min(scanHistory.length, 10)} · session only`
    : "";

  if (!scanHistory.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.className = "empty";
    cell.textContent = "No scans yet.";
    row.append(cell);
    body.append(row);
  } else {
    scanHistory.slice(0, 10).forEach((record, index) => {
      const row = document.createElement("tr");
      if (index === 0) row.className = "fresh";
      const time = document.createElement("td");
      time.textContent = record.time.toLocaleTimeString();
      row.append(time);
      const type = document.createElement("td");
      type.textContent = record.categories.length
        ? record.categories.map((category) => TYPE_NAMES[category]).join(", ")
        : "No threat";
      row.append(type);
      const message = document.createElement("td");
      message.className = "msg";
      message.textContent = record.message;
      row.append(message);
      body.append(row);
    });
  }
  drawBarChart();
}

function renderAnalysis(analysis) {
  const details = analysis.details || {};
  const label = analysis.risk_label || "suspicious";
  const categories = categoriesFor(analysis);
  const severity = riskLevel(analysis, riskValue(analysis));
  const isThreat = ["medium", "high"].includes(severity);
  const dial = document.querySelector("#dial");
  dial.className = `dial ${isThreat ? "threat" : "safe"}`;
  dial.setAttribute("aria-label", isThreat ? "Threat detected" : "No threat detected");
  const verdict = document.querySelector("#verdictTxt");
  verdict.textContent = isThreat ? "Threat detected" : "No threat found";
  verdict.className = `verdict-txt ${isThreat ? "bad" : "good"}`;

  const labelText = {risk: "Threat detected", suspicious: "Suspicious message", safe: "Looks safe"};
  const classifierNames = {
    scam: "SMS risk",
    spam: "SMS risk",
    safe: "No SMS risk",
    ham: "No SMS risk",
  };
  const classifier = details.classifier_label
    ? `Classifier: ${classifierNames[details.classifier_label] || details.classifier_label}.`
    : "";
  document.querySelector("#description").textContent =
    [analysis.title || labelText[label] || label, classifier].filter(Boolean).join(" ");
  document.querySelector("#description").classList.remove("muted");
  setList("#reasons", analysis.reasons, "No signals were detected.");
  const action = typeof analysis.action === "string" ? analysis.action.trim() : "";
  document.querySelector("#action").textContent = action || "No action is needed.";
  document.querySelector("#disclaimer").textContent = analysis.disclaimer || "";
  document.querySelector("#explanation").textContent =
    analysis.explanation?.text || "Generating the explanation…";
  document.querySelector("#explanation-source").textContent = analysis.explanation?.source
    ? `Explanation source: ${analysis.explanation.source}`
    : "";

  currentCategories = categories;
  drawTypeCircle();
  renderRisk(analysis);
  scanHistory.unshift({
    time: new Date(),
    message: messageInput.value.trim(),
    categories,
    isThreat,
  });
  scanHistory.length = Math.min(scanHistory.length, 50);
  renderHistory();
}

function setMetric(id, value) {
  document.querySelector(`#${id}`).textContent = value;
}

function estimateTokens(text) {
  return (text.match(/[\p{L}\p{N}]+|[^\s\p{L}\p{N}]/gu) || []).length;
}

function clearMetrics() {
  for (const id of ["inference-time", "analysis-time", "output-tokens", "token-rate"]) {
    setMetric(id, "—");
  }
  document.querySelector("#metric-note").textContent =
    "Metrics appear after a scan. Token counts are estimated from generated text.";
}

function updateMetrics(inferenceMs, analysisMs, generationMs, explanation) {
  setMetric("inference-time", `${inferenceMs.toFixed(1)} ms`);
  setMetric("analysis-time", `${Math.round(analysisMs)} ms`);
  if (explanation?.source !== "llm") {
    setMetric("output-tokens", "—");
    setMetric("token-rate", "—");
    document.querySelector("#metric-note").textContent =
      "Template explanation used; no model tokens were generated.";
    return;
  }
  const tokens = estimateTokens(explanation.text || "");
  const seconds = generationMs / 1000;
  setMetric("output-tokens", `${tokens} est.`);
  setMetric("token-rate", `${seconds > 0 ? (tokens / seconds).toFixed(1) : "0.0"}`);
  document.querySelector("#metric-note").textContent =
    "Inference time is server-side analysis; API round-trip includes network time. Token count/rate are estimates, not tokenizer IDs.";
}

function explanationSource(event) {
  if (event.source !== "template") {
    return event.source ? `Explanation source: ${event.source}` : "";
  }
  if (event.reason?.startsWith("rejected:")) {
    return `The generated draft did not pass safety checks (${event.reason}); showing the vetted explanation.`;
  }
  if (event.reason === "llm unavailable") {
    return "LLM unavailable; showing the built-in explanation.";
  }
  if (event.reason?.startsWith("llm error:")) {
    return "LLM generation failed; showing the built-in explanation.";
  }
  return "Showing the built-in explanation.";
}

async function checkService() {
  const led = document.querySelector("#linkLed");
  const text = document.querySelector("#linkTxt");
  try {
    const response = await fetch("/api/health", {cache: "no-store"});
    if (!response.ok) throw new Error(`Service returned ${response.status}`);
    const health = await response.json();
    led.className = "dot live";
    text.textContent = health.llm_available ? "Service online · LLM ready" : "Service online · template mode";
    document.querySelector("#drawerInfo").textContent =
      `${health.llm_available ? "Local LLM is available." : "Local LLM is unavailable; built-in explanations will be used."} Scan history stays in memory for this session.`;
  } catch {
    led.className = "dot down";
    text.textContent = "Service unavailable";
    document.querySelector("#drawerInfo").textContent = "Could not reach the analysis service.";
  }
}

function openSettings(show) {
  document.querySelector("#drawer").hidden = !show;
  document.querySelector("#scrim").hidden = !show;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = messageInput.value.trim();
  if (!message) return;
  errorBox.hidden = true;
  progress.hidden = false;
  progress.textContent = "Checking the message…";
  submitButton.disabled = true;
  submitButton.textContent = "Analyzing…";
  form.setAttribute("aria-busy", "true");
  document.body.classList.add("scanning");
  clearMetrics();

  try {
    const payload = {message, lang: document.querySelector("#lang").value};
    const analysisStarted = performance.now();
    const analysis = await post("/api/analyze", payload);
    const analysisMs = performance.now() - analysisStarted;
    const inferenceMs = Number.isFinite(analysis.analysis_time_ms)
      ? analysis.analysis_time_ms
      : analysisMs;
    renderAnalysis(analysis);
    progress.textContent = analysis.llm_available
      ? "Assessment ready. Generating the explanation on this device…"
      : "Assessment ready. Preparing the built-in explanation…";
    document.querySelector("#explanation").textContent = "";
    document.querySelector("#explanation-source").textContent = "Generating explanation…";

    const generationStarted = performance.now();
    let completed = null;
    await streamExplanation(payload, (event) => {
      if (event.type === "token") {
        document.querySelector("#explanation").textContent += event.text;
        document.querySelector("#explanation-source").textContent =
          "Draft explanation · checking against safety rules…";
      } else if (event.type === "complete") {
        completed = event;
        document.querySelector("#explanation").textContent = event.text || "";
        document.querySelector("#explanation-source").textContent = explanationSource(event);
      } else if (event.type === "error") {
        throw new Error("Could not generate the explanation.");
      }
    });
    if (!completed) throw new Error("The explanation stream ended before completion.");
    const generationMs = performance.now() - generationStarted;
    updateMetrics(inferenceMs, analysisMs, generationMs, completed);
    progress.textContent = "";
    progress.hidden = true;
  } catch (error) {
    errorBox.textContent = error.message || "Could not analyze the message.";
    errorBox.hidden = false;
  } finally {
    progress.hidden = true;
    form.removeAttribute("aria-busy");
    submitButton.disabled = false;
    submitButton.textContent = "Analyze";
    document.body.classList.remove("scanning");
  }
});

messageInput.addEventListener("input", () => {
  document.querySelector("#chars").textContent = String(messageInput.value.length);
});
messageInput.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    form.requestSubmit();
  }
});
document.querySelector("#clear").addEventListener("click", () => {
  messageInput.value = "";
  document.querySelector("#chars").textContent = "0";
  messageInput.focus();
});
document.querySelector("#gear").addEventListener("click", () => openSettings(true));
document.querySelector("#closeDrawer").addEventListener("click", () => openSettings(false));
document.querySelector("#scrim").addEventListener("click", () => openSettings(false));
document.querySelector("#recheck").addEventListener("click", checkService);
document.querySelector("#clearHistory").addEventListener("click", () => {
  scanHistory.length = 0;
  renderHistory();
  openSettings(false);
});
document.querySelector("#sample").addEventListener("change", (event) => {
  const examples = {
    scam: "Your bank account is blocked. Verify your KYC immediately and share your OTP to restore access.",
    url: "Your parcel is waiting. Confirm delivery now at http://secure-account-verify.example.com",
    safe: "Hi, I am running ten minutes late. See you at the station.",
  };
  const value = examples[event.target.value];
  if (value) {
    messageInput.value = value;
    document.querySelector("#chars").textContent = String(value.length);
    openSettings(false);
    messageInput.focus();
  }
  event.target.value = "";
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") openSettings(false);
});

drawGauge();
drawTypeCircle();
drawBarChart();
renderHistory();
checkService();
