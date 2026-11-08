"use strict";

const $ = (selector) => document.querySelector(selector);
const workspace = $("#workspace");
const statusMessage = $("#status");
let currentSession = null;
let busy = false;

async function request(path, body) {
  const options = body === undefined
    ? { headers: { Accept: "application/json" } }
    : {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      };
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function setStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.classList.toggle("error", isError);
}

function addCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
  row.append(cell);
}

function fillTable(selector, rows, columns) {
  const body = $(selector);
  body.replaceChildren();
  if (rows.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = columns.length;
    cell.textContent = "No observations yet.";
    row.append(cell);
    body.append(row);
    return;
  }
  for (const data of rows) {
    const row = document.createElement("tr");
    for (const key of columns) {
      const value = typeof key === "function" ? key(data) : data[key];
      addCell(row, value);
    }
    body.append(row);
  }
}

function renderMetrics(session) {
  $("#budget-metric").textContent = `${session.budgetRemaining} / ${session.budgetTotal}`;
  $("#actions-metric").textContent = String(session.budgetUsed);
  $("#hosts-metric").textContent = String(session.hosts.length);
  $("#services-metric").textContent = String(session.services.length);
  $("#budget-progress").style.width = `${session.budgetTotal
    ? (session.budgetUsed / session.budgetTotal) * 100
    : 100}%`;
  const exhausted = session.budgetRemaining === 0;
  $("#run-steps").disabled = exhausted || busy;
  $("#run-all").disabled = exhausted || busy;
  $("#explore").disabled = exhausted || busy;
  $("#generate-form button").disabled = busy;
  $("#steps").disabled = busy;
  $("#subnet").disabled = busy;
}

function renderTopology(session) {
  const container = $("#topology");
  container.replaceChildren();
  const hosts = new Map(session.hosts.map((host) => [host.ip, host]));
  for (const link of session.links) {
    if (!hosts.has(link.source)) hosts.set(link.source, { ip: link.source, openPorts: [] });
    if (!hosts.has(link.target)) hosts.set(link.target, { ip: link.target, openPorts: [] });
  }
  if (hosts.size === 0) {
    const message = document.createElement("p");
    message.className = "form-hint";
    message.textContent = "Nothing discovered yet. Run reconnaissance.";
    container.append(message);
    return;
  }

  const nodes = [...hosts.values()].sort((a, b) => a.ip.localeCompare(b.ip));
  const width = Math.max(520, Math.min(1100, nodes.length * 52 + 80));
  const height = Math.max(190, Math.ceil(nodes.length / 12) * 72 + 70);
  const positions = new Map();
  nodes.forEach((node, index) => {
    const col = index % 12;
    const row = Math.floor(index / 12);
    positions.set(node.ip, {
      x: 42 + col * ((width - 84) / Math.max(1, Math.min(11, nodes.length - 1))),
      y: 40 + row * 72,
    });
  });

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("role", "presentation");
  for (const link of session.links) {
    const from = positions.get(link.source);
    const to = positions.get(link.target);
    if (!from || !to) continue;
    const line = document.createElementNS(svg.namespaceURI, "line");
    line.setAttribute("x1", from.x);
    line.setAttribute("y1", from.y);
    line.setAttribute("x2", to.x);
    line.setAttribute("y2", to.y);
    line.setAttribute("stroke", link.relation === "routed" ? "#d88275" : "#59716f");
    line.setAttribute("stroke-width", "1.5");
    svg.append(line);
  }
  for (const node of nodes) {
    const point = positions.get(node.ip);
    const group = document.createElementNS(svg.namespaceURI, "g");
    const circle = document.createElementNS(svg.namespaceURI, "circle");
    circle.setAttribute("cx", point.x);
    circle.setAttribute("cy", point.y);
    circle.setAttribute("r", String(7 + Math.min((node.openPorts || []).length, 4)));
    circle.setAttribute("fill", "#56d6b1");
    circle.setAttribute("stroke", "#18362f");
    circle.setAttribute("stroke-width", "3");
    const title = document.createElementNS(svg.namespaceURI, "title");
    title.textContent = `${node.ip} — ${(node.openPorts || []).length} observed open ports`;
    group.append(circle, title);
    const label = document.createElementNS(svg.namespaceURI, "text");
    label.setAttribute("x", point.x);
    label.setAttribute("y", point.y + 24);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("fill", "#a9b7bf");
    label.setAttribute("font-size", "9");
    label.textContent = node.ip.split(".").slice(-2).join(".");
    group.append(label);
    svg.append(group);
  }
  container.append(svg);
}

function render(session) {
  currentSession = session;
  if (!session) {
    workspace.hidden = true;
    return;
  }
  workspace.hidden = false;
  $("#scope").textContent = `Authorised simulated scope: ${session.scope.join(" · ")}`;
  $("#strategy-label").textContent = `${session.strategy} strategy`;
  const subnet = $("#subnet");
  const previous = subnet.value;
  subnet.replaceChildren();
  for (const cidr of session.scope) {
    const option = document.createElement("option");
    option.value = cidr;
    option.textContent = cidr;
    subnet.append(option);
  }
  if (session.scope.includes(previous)) subnet.value = previous;

  renderMetrics(session);
  fillTable("#hosts-table", session.hosts, [
    "ip",
    "osEstimate",
    (host) => (host.openPorts || []).join(", "),
  ]);
  fillTable("#services-table", session.services, [
    "ip",
    "port",
    "service",
    "version",
    "osHint",
  ]);
  fillTable("#history-table", session.history, [
    "sequence",
    "time",
    "action",
    "target",
    "port",
    "observations",
    "newHosts",
    "newServices",
    "budgetRemaining",
  ]);
  renderTopology(session);
}

async function perform(path, body, successMessage) {
  if (busy) return;
  busy = true;
  if (currentSession) renderMetrics(currentSession);
  setStatus("Working…");
  try {
    const payload = await request(path, body);
    render(payload.session);
    setStatus(successMessage);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    busy = false;
    if (currentSession) renderMetrics(currentSession);
  }
}

$("#generate-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  perform("/api/generate", {
    seed: Number(data.get("seed")),
    hosts: Number(data.get("hosts")),
    subnets: Number(data.get("subnets")),
    budget: Number(data.get("budget")),
    strategy: data.get("strategy"),
  }, "Synthetic network generated. Ready to explore.");
});

$("#run-steps").addEventListener("click", () => {
  const steps = Number($("#steps").value);
  if (!Number.isInteger(steps) || steps < 1) {
    setStatus("Steps must be a positive whole number.", true);
    return;
  }
  perform("/api/run", { steps }, "Reconnaissance steps completed.");
});

$("#run-all").addEventListener("click", () => {
  perform("/api/run", { steps: null }, "Strategy completed or action budget exhausted.");
});

$("#explore").addEventListener("click", () => {
  perform("/api/explore", { subnet: $("#subnet").value }, "Subnet exploration completed.");
});

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const candidate of document.querySelectorAll(".tab")) {
      const selected = candidate === tab;
      candidate.classList.toggle("active", selected);
      candidate.setAttribute("aria-selected", String(selected));
      $(`#${candidate.getAttribute("aria-controls")}`).hidden = !selected;
    }
  });
}

request("/api/state")
  .then(({ session }) => render(session))
  .catch((error) => setStatus(error.message, true));
