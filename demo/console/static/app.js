"use strict";

// Todo lo que viene del servidor se escribe con textContent: nada se interpreta como HTML.

const $ = (selector) => document.querySelector(selector);
const POLL_MS = 1500;

const ui = {
  data: null,          // última respuesta de /api/state
  view: null,          // detalle del escaneo que se está mirando
  viewId: null,        // id del escaneo que se está mirando
  newestDone: null,    // id del escaneo terminado más reciente (para saltar al nuevo cuando termina)
  progress: null,      // {status, progress} del escaneo en curso
  accepted: false,     // casilla de los términos
  portRange: "top-1000",
  notes: {},           // mensajes por paso: {account: "...", ownership: "...", scan: "..."}
  busy: false,
  resetArmed: false,
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (value !== false && value != null) node.setAttribute(key, value === true ? "" : String(value));
  }
  node.append(...children.filter((child) => child != null && child !== false));   // append() escribiría «null» para un hijo nulo
  return node;
}

async function call(method, url, body) {
  const options = { method, cache: "no-store", headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  let data = null;
  try {
    data = await response.json();
  } catch {
    // respuesta sin cuerpo
  }
  return { ok: response.ok, status: response.status, data };
}

const SEVERITY_LABEL = { critical: ["crítico", "críticos"], high: ["alto", "altos"], medium: ["medio", "medios"], low: ["bajo", "bajos"], info: ["informativo", "informativos"] };

// ---- estado general ------------------------------------------------------------------------------------------------

function setStatus(kind, text) {
  const node = $("#status");
  node.dataset.state = kind;
  node.textContent = text;
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString("es-AR", { hour12: false });
}

function formatDateTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("es-AR", { hour12: false });
}

async function refresh() {
  let data;
  try {
    const result = await call("GET", "/api/state");
    if (!result.ok) throw new Error(String(result.status));
    data = result.data;
  } catch {
    setStatus("error", "No se puede hablar con la consola");
    return;
  }
  ui.data = data;
  setStatus(data.engine_ready ? "ok" : "wait", data.engine_ready ? "Sistema listo" : "Esperando que el motor termine de arrancar…");

  const running = data.history.find((h) => h.status === "queued" || h.status === "running");
  ui.progress = null;
  if (running) {
    const result = await call("GET", `/api/scan/${encodeURIComponent(running.id)}`);
    if (result.ok) ui.progress = result.data.job;
  }

  const done = data.history.filter((h) => h.status === "completed");
  const newest = done.length ? done[0].id : null;
  if (newest !== ui.newestDone) {   // terminó un escaneo nuevo: pasar a mirarlo
    ui.newestDone = newest;
    ui.viewId = newest;
    ui.view = null;
  }
  if (ui.viewId && !done.some((h) => h.id === ui.viewId)) {   // el escaneo que se miraba ya no existe (reinicio)
    ui.viewId = newest;
    ui.view = null;
  }
  if (ui.viewId && (!ui.view || ui.view.job.id !== ui.viewId)) {
    const result = await call("GET", `/api/scan/${encodeURIComponent(ui.viewId)}`);
    if (result.ok) ui.view = result.data;
  }
  if (!ui.viewId) ui.view = null;
  render();
}

// ---- acciones --------------------------------------------------------------------------------------------------------

async function act(step, method, url, body) {
  if (ui.busy) return;
  ui.busy = true;
  ui.notes[step] = "";
  render();
  try {
    const result = await call(method, url, body);
    if (!result.ok) ui.notes[step] = (result.data && result.data.error) || `Error ${result.status}`;
    return result;
  } catch {
    ui.notes[step] = "No se puede hablar con la consola.";
  } finally {
    ui.busy = false;
    await refresh();
  }
}

// ---- pasos -----------------------------------------------------------------------------------------------------------

function button(text, onClick, { primary = false, disabled = false, id = null } = {}) {
  const node = el("button", { type: "button", class: primary ? "btn primary" : "btn", text, id });
  node.disabled = disabled || ui.busy;
  node.addEventListener("click", onClick);
  return node;
}

function note(step) {
  return ui.notes[step] ? el("p", { class: "note", text: ui.notes[step], role: "alert" }) : null;
}

function mono(text) {
  return el("span", { class: "mono", text });
}

function buildSteps(d) {
  const hasAccount = d.account;
  const domain = d.domain;
  const verified = domain && domain.status === "verified";
  const hasScan = d.history.length > 0;
  const hasDone = d.history.some((h) => h.status === "completed");
  const running = d.history.some((h) => h.status === "queued" || h.status === "running");
  const stateOf = (done, unlocked) => (done ? "done" : unlocked ? "active" : "locked");

  return [
    {
      key: "account", title: "Crear la cuenta de práctica", state: stateOf(hasAccount, true),
      sig: [hasAccount, ui.busy, ui.notes.account, d.engine_ready],
      build: () => hasAccount
        ? [el("p", { class: "summary", text: `Cuenta lista (${d.email}). Existe solo mientras la demo esté encendida.` })]
        : [
            el("p", { text: "El producto trabaja con cuentas. En la demo es una cuenta descartable, sin contraseña que recordar." }),
            el("p", { class: "terms", text: d.terms }),
            (() => {
              const box = el("input", { type: "checkbox", id: "accept" });
              box.checked = ui.accepted;
              box.addEventListener("change", () => {
                ui.accepted = box.checked;
                const create = $("#create-account");
                if (create) create.disabled = !ui.accepted || ui.busy || !d.engine_ready;
              });
              return el("label", { class: "check", for: "accept" }, box, " Acepto los términos de la demo");
            })(),
            el("div", { class: "actions" },
              button("Crear cuenta", () => act("account", "POST", "/api/account", { accept_terms: ui.accepted }),
                { primary: true, disabled: !ui.accepted || !d.engine_ready, id: "create-account" })),
            note("account"),
          ],
    },
    {
      key: "domain", title: "Registrar el dominio", state: stateOf(Boolean(domain), hasAccount),
      sig: [hasAccount, Boolean(domain), ui.busy, ui.notes.domain],
      build: () => domain
        ? [el("p", { class: "summary" }, "Dominio registrado: ", mono(d.domain_name))]
        : [
            el("p", { text: "Se le dice al motor qué dominio se quiere revisar. Todavía no escanea nada: primero hay que demostrar que el dominio es propio." }),
            el("div", { class: "actions" },
              button(`Registrar ${d.domain_name}`, () => act("domain", "POST", "/api/domain"), { primary: true, disabled: !hasAccount })),
            note("domain"),
          ],
    },
    {
      key: "ownership", title: "Demostrar que el dominio es propio", state: stateOf(verified, Boolean(domain)),
      sig: [Boolean(domain), domain && domain.status, d.file_published, ui.busy, ui.notes.ownership],
      build: () => {
        if (verified) {
          return [el("p", { class: "summary", text: "Propiedad demostrada. El motor ya puede escanear este dominio." })];
        }
        const children = [
          el("p", { text: "Revisar un sitio ajeno no es legítimo, así que el motor pide una prueba: quien administra el dominio publica en su sitio un archivo con un código, y el motor lo busca por HTTPS (también acepta un registro DNS)." }),
        ];
        if (domain) {
          children.push(
            el("dl", { class: "facts" },
              el("div", {}, el("dt", { text: "Archivo" }), el("dd", {}, mono(domain.file_url))),
              el("div", {}, el("dt", { text: "Contenido" }), el("dd", {}, mono(domain.token))),
              el("div", {}, el("dt", { text: "En el sitio" }), el("dd", { text: d.file_published ? "publicado" : "todavía no está publicado" })),
            ),
            el("div", { class: "actions" },
              button("Probar un escaneo ahora", () => act("ownership", "POST", "/api/try-scan").then(showRefusal)),
              d.file_published
                ? button("Retirar el archivo", () => act("ownership", "POST", "/api/file", { publish: false }))
                : button("Publicar el archivo en el sitio", () => act("ownership", "POST", "/api/file", { publish: true }), { primary: true }),
              button("Verificar propiedad", () => act("ownership", "POST", "/api/verify").then(showVerification), { primary: d.file_published }),
            ),
          );
          if (ui.notes.ownership) children.push(note("ownership"));
        }
        return children;
      },
    },
    {
      key: "scan", title: "Escanear desde afuera", state: running ? "active" : stateOf(hasDone, Boolean(verified)),
      sig: [Boolean(verified), running, ui.progress && ui.progress.progress, ui.progress && ui.progress.status, ui.busy, ui.notes.scan, hasDone],
      build: () => {
        const children = [
          el("p", { text: "Con el dominio verificado, el motor hace tres cosas, todas desde afuera: busca subdominios en el registro público de certificados, prueba qué puertos responden y mira cómo se presentan los sitios web (cabeceras, tecnologías, certificado)." }),
        ];
        const select = el("select", { id: "range", "aria-label": "Cantidad de puertos a probar" },
          el("option", { value: "top-100", text: "Rápido: los 100 puertos más usados" }),
          el("option", { value: "top-1000", text: "Completo: los 1000 puertos más usados" }),
        );
        select.value = ui.portRange;
        select.disabled = running || ui.busy || !verified;
        select.addEventListener("change", () => { ui.portRange = select.value; });
        children.push(el("div", { class: "actions" }, select,
          button(hasDone ? "Escanear de nuevo" : "Iniciar escaneo",
            () => act("scan", "POST", "/api/scan", { port_range: ui.portRange }), { primary: !hasDone, disabled: running || !verified })));
        if (running) {
          const job = ui.progress || {};
          children.push(
            el("p", { class: "progress-text", role: "status", text: job.status === "queued" ? "En cola…" : `En curso: ${job.progress ?? 0} %` }),
            el("progress", { max: 100, value: job.progress ?? 0 }),
          );
        }
        children.push(note("scan"));
        return children.filter(Boolean);
      },
    },
    {
      key: "results", title: "Qué se encontró", state: stateOf(hasDone, false),
      sig: [ui.view ? ui.view.job.id : null, hasDone],
      build: () => (ui.view && ui.view.findings ? resultsView(ui.view) : [el("p", { class: "muted", text: "Aparece acá cuando termina el escaneo." })]),
    },
    {
      key: "fix", title: "Corregir y comparar", state: stateOf(false, hasDone),
      sig: [hasDone, d.staging_on, running, ui.busy, ui.notes.fix, JSON.stringify(d.history.map((h) => [h.id, h.status, h.summary])), ui.viewId],
      build: () => [
        el("p", { text: "Casi todo lo grave viene de un solo lugar: el servidor de pruebas que nadie recordaba. Darlo de baja y escanear de nuevo muestra cómo cambia el informe." }),
        el("div", { class: "actions" },
          d.staging_on
            ? button("Apagar el servidor de pruebas", () => act("fix", "POST", "/api/staging", { on: false }), { primary: true, disabled: !hasDone })
            : button("Volver a encender el servidor de pruebas", () => act("fix", "POST", "/api/staging", { on: true }), { disabled: !hasDone }),
          button("Escanear de nuevo", () => act("fix", "POST", "/api/scan", { port_range: ui.portRange }), { disabled: running || !verified })),
        note("fix"),
        historyTable(d),
      ].filter(Boolean),
    },
  ];
}

function showRefusal(result) {
  if (result && result.ok && result.data && result.data.refused) {
    ui.notes.ownership = `El motor rechazó el escaneo, como corresponde: «${result.data.message}». Sin verificación, no se escanea.`;
    render();
  }
}

function showVerification(result) {
  if (result && result.ok && result.data && result.data.verified === false) {
    ui.notes.ownership = "El motor no encontró el archivo con el código. Publicarlo en el sitio y volver a verificar.";
    render();
  }
}

// ---- resultados ------------------------------------------------------------------------------------------------------

function severityChips(counts) {
  const chips = ["critical", "high", "medium", "low", "info"]
    .filter((key) => counts[key])
    .map((key) => el("span", { class: "sev", "data-sev": key, text: `${counts[key]} ${SEVERITY_LABEL[key][counts[key] === 1 ? 0 : 1]}` }));
  return chips.length ? chips : [el("span", { class: "sev", "data-sev": "none", text: "sin hallazgos" })];
}

function findingCard(finding) {
  const technical = el("details", {}, el("summary", { text: "Ver lo que dijo el motor" }),
    el("pre", { text: JSON.stringify({ title: finding.raw_title, category: finding.category, severity: finding.severity, evidence: finding.evidence }, null, 2) }));
  return el("li", { class: "finding", "data-sev": finding.severity },
    el("div", { class: "finding-top" },
      el("span", { class: "sev", "data-sev": finding.severity, text: finding.severity_label }),
      el("h4", { text: finding.title })),
    finding.where ? el("p", { class: "where" }, "En ", mono(finding.where)) : null,
    el("p", { text: finding.what }),
    finding.todo ? el("p", { class: "todo" }, el("strong", { text: "Qué hacer: " }), finding.todo) : null,
    technical,
  );
}

function table(headers, rows) {
  if (!rows.length) return el("p", { class: "muted", text: "Nada para mostrar." });
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { text: h })))),
    el("tbody", {}, ...rows.map((row) => el("tr", {}, ...row.map((cell) => el("td", { text: cell == null || cell === "" ? "-" : String(cell) }))))),
  ));
}

function resultsView(view) {
  const when = formatDateTime(view.job.completed_at || view.job.created_at);
  const range = view.job.config && view.job.config.port_range;
  return [
    el("div", { class: "result-head" },
      el("p", { class: "headline", text: view.summary }),
      el("div", { class: "chips" }, ...severityChips(view.counts)),
      el("p", { class: "muted", text: `Escaneo de ${when}${range ? ` (${range})` : ""}` })),
    view.findings.length
      ? el("ol", { class: "findings" }, ...view.findings.map(findingCard))
      : el("p", { class: "summary", text: "El motor no encontró nada para señalar." }),
    el("details", { class: "tech" }, el("summary", { text: "Detalle técnico del escaneo" }),
      el("h4", { text: "Subdominios" }),
      table(["Nombre", "Dirección"], view.subdomains.map((s) => [s.hostname, s.ip])),
      el("h4", { text: "Puertos abiertos" }),
      table(["Servidor", "Puerto", "Servicio", "Saludo del servicio"],
        view.ports.map((p) => [p.name ? `${p.name} (${p.host})` : p.host, p.port, p.service, p.banner])),
      el("h4", { text: "Sitios web" }),
      table(["Dirección", "Respuesta", "Servidor", "Título"], view.web.map((w) => [w.url, w.status, w.server, w.title])),
      el("h4", { text: "Tecnologías detectadas" }),
      table(["Nombre", "Versión", "Tipo"], view.technologies.map((t) => [t.name, t.version, t.category])),
      el("h4", { text: "Certificados" }),
      table(["Sitio", "Emisor", "Válido", "Vence"],
        view.tls.map((c) => [c.host, c.issuer, c.valid ? "sí" : "no", c.valid_to ? formatDateTime(c.valid_to) : ""])),
    ),
    el("div", { class: "actions" },
      el("a", { class: "btn", href: `/api/report/${encodeURIComponent(view.job.id)}`, download: "", text: "Descargar el informe completo (JSON)" })),
  ];
}

function historyTable(d) {
  const done = d.history.filter((h) => h.status === "completed");
  if (!done.length) return null;
  return el("div", { class: "table-wrap" }, el("table", { class: "history" },
    el("thead", {}, el("tr", {}, ...["Escaneo", "Subdominios", "Puertos abiertos", "Hallazgos", ""].map((h) => el("th", { text: h })))),
    el("tbody", {}, ...done.map((h) => el("tr", { "data-current": h.id === ui.viewId ? "true" : "false" },
      el("td", { text: formatDateTime(h.completed_at || h.created_at) }),
      el("td", { text: h.subdomains }),
      el("td", { text: h.open_ports }),
      el("td", { text: h.summary }),
      el("td", {}, h.id === ui.viewId
        ? el("span", { class: "muted", text: "se está mirando" })
        : (() => {
            const node = el("button", { type: "button", class: "link", text: "Ver" });
            node.addEventListener("click", () => { ui.viewId = h.id; ui.view = null; refresh(); });
            return node;
          })()),
    ))),
  ));
}

// ---- dibujo --------------------------------------------------------------------------------------------------------------

function render() {
  const d = ui.data;
  if (!d) return;
  const list = $("#steps");
  buildSteps(d).forEach((step, index) => {
    let item = list.children[index];
    if (!item) {
      item = el("li", { class: "step" });
      list.append(item);
    }
    const signature = JSON.stringify(step.sig);
    if (item.dataset.sig !== signature) {
      item.dataset.sig = signature;
      item.dataset.state = step.state;
      item.replaceChildren(
        el("h3", { class: "step-title" }, el("span", { class: "step-n", text: String(index + 1) }), step.title),
        el("div", { class: "step-body" }, ...step.build().filter(Boolean)),
      );
    }
  });
  renderSites(d);
  renderLog(d.events);
}

function renderSites(d) {
  const sites = [
    { name: d.domain_name, what: "La tienda: un sitio sano, con certificado vigente", status: d.file_published ? "en línea, con el archivo de verificación" : "en línea" },
    { name: `pruebas.${d.domain_name}`, what: "El servidor de pruebas que nadie recordaba", status: d.staging_on ? "encendido" : "apagado", off: !d.staging_on },
    { name: "crt.sh", what: "Registro público de certificados (de práctica)", status: "en línea" },
  ];
  const signature = JSON.stringify(sites);
  const list = $("#sites");
  if (list.dataset.sig === signature) return;
  list.dataset.sig = signature;
  list.replaceChildren(...sites.map((site) =>
    el("li", { "data-off": site.off ? "true" : "false" },
      el("span", { class: "mono", text: site.name }),
      el("span", { class: "muted", text: site.what }),
      el("span", { class: "site-status", text: site.status }))));
}

function renderLog(events) {
  const log = $("#log");
  const signature = events.length ? String(events[events.length - 1].n) : "";
  if (log.dataset.sig === signature) return;
  log.dataset.sig = signature;
  if (!events.length) {
    log.replaceChildren(el("li", { class: "empty", text: "Todavía no pasó nada. Empezar por el paso 1." }));
    return;
  }
  log.replaceChildren(...[...events].reverse().map((event) =>
    el("li", { class: "entry", "data-ok": event.ok ? "true" : "false" },
      el("span", { class: "time", text: formatTime(event.t) }),
      el("p", { text: event.text }),
      event.detail ? el("p", { class: "muted", text: event.detail }) : null)));
}

// ---- reinicio --------------------------------------------------------------------------------------------------------------

$("#reset").addEventListener("click", async (event) => {
  const node = event.currentTarget;
  if (!ui.resetArmed) {   // dos clics: no se borra el recorrido por un toque sin querer
    ui.resetArmed = true;
    node.textContent = "¿Seguro? Borra el dominio y los escaneos. Tocar otra vez para confirmar";
    setTimeout(() => { ui.resetArmed = false; node.textContent = "Reiniciar el recorrido"; }, 5000);
    return;
  }
  ui.resetArmed = false;
  node.textContent = "Reiniciar el recorrido";
  ui.notes = {};
  ui.view = null;
  ui.viewId = null;
  ui.newestDone = null;
  await call("POST", "/api/reset");
  await refresh();
});

refresh();
setInterval(() => { if (!ui.busy) refresh(); }, POLL_MS);
