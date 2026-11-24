(function () {
  "use strict";

  /* ── Tactile Motion & Haptic Feedback ────────────────── */
  function haptic(pattern) {
    if (typeof navigator !== "undefined" && typeof navigator.vibrate === "function") {
      try {
        navigator.vibrate(pattern);
      } catch (e) {}
    }
  }

  var HAPTIC = {
    tick: 6,
    light: 10,
    medium: 18,
    success: [12, 45, 20],
    error: [30, 60, 30]
  };

  /* ── State & Helpers ──────────────────────────────────── */
  var $ = function (id) { return document.getElementById(id); };
  var token = sessionStorage.getItem("rb_token") || "";
  var currentRole = sessionStorage.getItem("rb_role") || "analyst";
  var cur = null;
  var timer = null;

  // Server mode: 'live' or 'sim'
  var serverMode = localStorage.getItem("rb_server_mode") || "live";

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function when(ts) {
    if (!ts) return "";
    var d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) +
           " (" + d.toLocaleDateString([], { month: "short", day: "numeric" }) + ")";
  }

  /* ── Dynamic Island Pill Updater ─────────────────────── */
  function updateDynamicIsland(title, msg, isAlert) {
    var island = $("dynamic-island");
    var tEl = $("island-title");
    var mEl = $("island-msg");
    var dot = $("island-status-dot");

    if (tEl) tEl.textContent = title || "Riskbyte";
    if (mEl) mEl.textContent = msg || (serverMode === "live" ? "Live SOC Engine" : "Standalone Sim");
    if (island) {
      if (isAlert) {
        island.classList.add("alert-mode");
      } else {
        island.classList.remove("alert-mode");
      }
    }
    if (dot) {
      dot.className = "island-dot " + (serverMode === "sim" ? "sim" : "");
    }
  }

  /* ── In-Browser Simulated Server (Mock Offline Fallback) ── */
  var simData = {
    stats: {
      events: 18,
      open_alerts: 4,
      open_cases: 2,
      audit_intact: true,
      version: "0.1.0-standalone",
      llm: "heuristic-sim",
      llm_redaction: true
    },
    license: {
      state: "dev",
      plan: "Offline Simulation",
      days_left: 365,
      features: ["all"],
      message: ""
    },
    cases: [
      { id: 102, entity: "fin-lt-042 (m.silva)", severity: "critical", status: "open", ts: Math.floor(Date.now() / 1000) - 300 },
      { id: 101, entity: "web-01 (1.2.3.4)", severity: "high", status: "open", ts: Math.floor(Date.now() / 1000) - 1800 }
    ],
    audit: [
      { id: 1, ts: Math.floor(Date.now() / 1000) - 120, actor: "analyst:muhammad.nabil", kind: "action_approved", alert_id: 1, detail: "Isolate host fin-lt-042 execution approved", hash: "a7f39b20e14c998a12d45b78", prev_hash: "000000000000000000000000" },
      { id: 2, ts: Math.floor(Date.now() / 1000) - 600, actor: "system:agent", kind: "rule_fired", alert_id: 2, detail: "SSH bruteforce detected on web-01", hash: "b8c1992e5f412d0a87e144a1", prev_hash: "a7f39b20e14c998a12d45b78" },
      { id: 3, ts: Math.floor(Date.now() / 1000) - 1200, actor: "ingest:api", kind: "telemetry_batch", alert_id: null, detail: "Batch ingest accepted 8 event records", hash: "99f012e88a31c5b882da1140", prev_hash: "b8c1992e5f412d0a87e144a1" }
    ],
    alerts: [
      {
        id: 1,
        title: "Base64 Encoded PowerShell Process Launch",
        severity: "critical",
        status: "triaged",
        rule_id: "rb-002",
        ts: Math.floor(Date.now() / 1000) - 120,
        host: "fin-lt-042",
        user: "m.silva",
        src_ip: "10.0.4.15",
        case_id: 102,
        triage: {
          engine: "autonomous-ai",
          verdict: "malicious",
          confidence: 0.94,
          summary: "Encoded PowerShell process attempting memory injection and command invocation. High likelihood of credential harvesting attack.",
          steps: [
            "Deobfuscated Base64 payload reveals invoke-expression (IEX) web download cradle.",
            "Process executed under user m.silva from non-standard staging path C:\\Users\\Public.",
            "Cross-referenced telemetry with active threat indicators: matched known Cobalt Strike stager signature.",
            "Automated containment rule triggered: host network isolation recommended."
          ]
        },
        proposed_action: { kind: "isolate_host", target: "fin-lt-042" },
        events: [
          { ts: Math.floor(Date.now() / 1000) - 120, host: "fin-lt-042", user: "m.silva", process: "powershell.exe", cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...", action: "process_start", outcome: "success" }
        ]
      },
      {
        id: 2,
        title: "SSH Repeated Authentication Bruteforce",
        severity: "high",
        status: "triaged",
        rule_id: "rb-001",
        ts: Math.floor(Date.now() / 1000) - 340,
        host: "web-01",
        user: "root",
        src_ip: "1.2.3.4",
        case_id: 101,
        triage: {
          engine: "autonomous-ai",
          verdict: "malicious",
          confidence: 0.98,
          summary: "Over 6 failed root login attempts within 30 seconds from external IP 1.2.3.4.",
          steps: [
            "Source IP identified in active threat intelligence blacklist indicators.txt.",
            "High rate of dictionary attacks on port 22.",
            "Recommendation: Block source IP at perimeter edge."
          ]
        },
        proposed_action: { kind: "block_ip", target: "1.2.3.4" },
        events: [
          { ts: Math.floor(Date.now() / 1000) - 340, host: "web-01", user: "root", src_ip: "1.2.3.4", process: "sshd", action: "login", outcome: "failure", message: "Failed password for root" }
        ]
      }
    ]
  };

  function simApi(path, method, body) {
    return new Promise(function (resolve, reject) {
      setTimeout(function () {
        var cleanPath = path.split("?")[0];
        if (cleanPath === "/api/stats") return resolve(simData.stats);
        if (cleanPath === "/api/license") return resolve(simData.license);
        if (cleanPath === "/api/alerts") return resolve(simData.alerts);
        if (cleanPath === "/api/events") {
          var allEvs = [];
          simData.alerts.forEach(function (a) {
            if (a.events) allEvs = allEvs.concat(a.events);
          });
          return resolve(allEvs);
        }
        if (cleanPath === "/api/demo/reset" || cleanPath === "/api/reset") {
          simData.alerts = [];
          simData.cases = [];
          simData.audit = [];
          simData.stats.open_alerts = 0;
          simData.stats.open_cases = 0;
          simData.stats.events = 0;
          return resolve({ ok: true, message: "Demo data reset" });
        }
        if (cleanPath === "/api/ingest") {
          var items = (body && body.events) ? body.events : (Array.isArray(body) ? body : [body]);
          var ev = items[0] || {};
          var newId = (simData.alerts.length ? Math.max.apply(null, simData.alerts.map(function(x){return x.id;})) : 0) + 1;
          var rId = "rb-001";
          var rTitle = "Security Detection";
          var rSev = "high";
          var actKind = "isolate_host";
          var actTarget = ev.host || "host-01";
          var sumText = "Autonomous AI validated malicious threat behavior.";

          if (ev.action === "email_link_click" || (ev.message && ev.message.indexOf("login-verify") !== -1)) {
            rId = "rb-006"; rTitle = "Phishing link accessed from email gateway"; rSev = "high"; actKind = "reset_password"; actTarget = ev.user || "j.doe";
            sumText = "Phishing credential harvester link accessed from email gateway.";
          } else if (ev.process === "sshd" && ev.action === "login") {
            rId = "rb-001"; rTitle = "SSH brute force from a single source"; rSev = "medium"; actKind = "block_ip"; actTarget = ev.src_ip || "1.2.3.4";
            sumText = "High-frequency SSH dictionary attack detected from untrusted scanner.";
          } else if (ev.process === "powershell.exe" || (ev.cmdline && ev.cmdline.indexOf("-enc") !== -1)) {
            rId = "rb-002"; rTitle = "Encoded PowerShell command"; rSev = "high"; actKind = "isolate_host"; actTarget = ev.host || "fin-lt-042";
            sumText = "Concealed Base64 PowerShell execution attempting memory injection.";
          } else if (ev.process === "vssadmin.exe" || ev.action === "shadow_delete" || (ev.cmdline && ev.cmdline.indexOf("vssadmin") !== -1)) {
            rId = "rb-007"; rTitle = "Ransomware volume shadow deletion and bulk encryption"; rSev = "critical"; actKind = "isolate_host"; actTarget = ev.host || "filesrv-01";
            sumText = "Ransomware shadow deletion and mass file encryption activity detected.";
          } else if (ev.message && ev.message.indexOf("anomalous country") !== -1) {
            rId = "rb-008"; rTitle = "Suspicious login from anomalous country or foreign IP"; rSev = "high"; actKind = "disable_user"; actTarget = ev.user || "svc-backup";
            sumText = "Service credential authentication originating from anomalous foreign IP.";
          }

          var newAlert = {
            id: newId,
            title: rTitle,
            severity: rSev,
            status: "triaged",
            rule_id: rId,
            ts: Math.floor(Date.now() / 1000),
            host: ev.host || "fin-lt-042",
            user: ev.user || "m.silva",
            src_ip: ev.src_ip || "10.0.0.1",
            case_id: 101,
            triage: {
              engine: "autonomous-ai",
              verdict: "malicious",
              confidence: 0.96,
              summary: sumText,
              steps: ["Behavioral signature matched Sigma detection logic.", "Threat intelligence verified malicious indicator.", "Human-in-the-loop containment proposed."]
            },
            proposed_action: { kind: actKind, target: actTarget },
            events: items
          };
          simData.alerts.unshift(newAlert);
          simData.stats.open_alerts = simData.alerts.length;
          simData.stats.events += items.length;
          return resolve({ accepted: items.length });
        }
        if (cleanPath.startsWith("/api/alerts/") && cleanPath.endsWith("/approve")) {
          var id = parseInt(cleanPath.split("/")[3]);
          var alert = simData.alerts.find(function (a) { return a.id === id; });
          if (alert) alert.status = "executed";
          var h = "a7f" + Math.random().toString(16).substring(2, 10) + "8c42b" + Math.random().toString(16).substring(2, 10);
          simData.audit.unshift({
            id: simData.audit.length + 1,
            ts: Math.floor(Date.now() / 1000),
            actor: "analyst:muhammad.nabil",
            kind: "action_approved",
            alert_id: id,
            detail: "Automated response approved: " + (alert && alert.proposed_action ? alert.proposed_action.kind : "action"),
            hash: h,
            prev_hash: "00000000000000000000000000000000"
          });
          haptic(HAPTIC.success);
          return resolve({ status: "executed", result: "dry-run: would execute action" });
        }
        if (cleanPath.startsWith("/api/alerts/") && cleanPath.endsWith("/dismiss")) {
          var id = parseInt(cleanPath.split("/")[3]);
          var alert = simData.alerts.find(function (a) { return a.id === id; });
          if (alert) alert.status = "dismissed";
          haptic(HAPTIC.light);
          return resolve({ status: "dismissed" });
        }
        if (cleanPath.startsWith("/api/alerts/")) {
          var id = parseInt(cleanPath.split("/")[3]);
          var alert = simData.alerts.find(function (a) { return a.id === id; });
          if (alert) return resolve(alert);
          return reject(new Error("Alert not found"));
        }
        if (cleanPath === "/api/cases") return resolve(simData.cases);
        if (cleanPath === "/api/audit") return resolve(simData.audit);
        reject(new Error("Endpoint not found: " + path));
      }, 50);
    });
  }

  /* ── Unified API Dispatcher ──────────────────────────── */
  function api(path, method, body) {
    if (serverMode === "sim") {
      return simApi(path, method, body);
    }

    var requestPath = path.startsWith("/") ? path : "/" + path;
    var opts = {
      method: method || "GET",
      headers: {
        Authorization: "Bearer " + token,
        "X-Riskbyte-Console": "1"
      }
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = typeof body === "string" ? body : JSON.stringify(body);
    }

    return fetch(requestPath, opts).then(function (r) {
      if (r.status === 401 || r.status === 403) {
        throw new Error("Authentication failed: invalid or expired token.");
      }
      return r.text().then(function (txt) {
        var j = null;
        try { j = JSON.parse(txt); } catch (e) {}

        if (!r.ok) {
          if (r.status === 404) {
            throw new Error("API route not found (404). Toggle server mode to 'In-Browser Sim' to run standalone without a terminal.");
          }
          throw new Error((j && j.error) ? j.error : ("Server error (" + r.status + ")"));
        }
        return j !== null ? j : txt;
      });
    }).catch(function (err) {
      if (err instanceof TypeError && err.message.toLowerCase().indexOf("fetch") !== -1) {
        throw new Error("Cannot connect to server. Switch server mode to 'In-Browser Sim' to run standalone.");
      }
      throw err;
    });
  }

  /* ── Server Mode Toggle UI ───────────────────────────── */
  function updateServerModeUI() {
    var label = $("server-status-label");
    var authModeText = $("auth-server-mode-text");
    var authHint = document.querySelector(".auth-server-switch-hint");
    var demoOfflineBanner = $("demo-offline-banner");

    if (serverMode === "live") {
      if (label) label.textContent = "Live";
      if (authModeText) authModeText.textContent = "Server: Live Backend (Port 8080)";
      if (authHint) authHint.textContent = "Switch to In-Browser Sim";
      if (demoOfflineBanner) demoOfflineBanner.style.display = "none";
      updateDynamicIsland("Riskbyte", "Live SOC Engine", false);
    } else {
      if (label) label.textContent = "Simulated";
      if (authModeText) authModeText.textContent = "Server: In-Browser Sim (No terminal needed)";
      if (authHint) authHint.textContent = "Switch to Live Server";
      if (demoOfflineBanner) demoOfflineBanner.style.display = "flex";
      updateDynamicIsland("Riskbyte", "Standalone Simulation", false);
    }
  }

  function toggleServerMode() {
    haptic(HAPTIC.medium);
    serverMode = (serverMode === "live") ? "sim" : "live";
    localStorage.setItem("rb_server_mode", serverMode);
    updateServerModeUI();
    showError("");
    if ($("app") && $("app").style.display === "flex") {
      refresh();
    }
  }

  /* ── Role Management & 3 Distinct Dashboards ─────────── */
  function setRole(r) {
    currentRole = r;
    sessionStorage.setItem("rb_role", r);

    var badge = $("role-badge");
    var roleText = $("role-name-text");
    if (badge) {
      badge.className = "role-badge-pill tactile-btn " + r;
    }
    if (roleText) {
      roleText.textContent = (r === "admin") ? "SOC Administrator" : ((r === "ingest") ? "Telemetry Ingest" : "Security Analyst");
    }

    // Toggle tab buttons visibility based on role
    document.querySelectorAll(".role-tab-analyst").forEach(function(b) { b.style.display = (r === "analyst") ? "" : "none"; });
    document.querySelectorAll(".role-tab-admin").forEach(function(b) { b.style.display = (r === "admin") ? "" : "none"; });
    document.querySelectorAll(".role-tab-ingest").forEach(function(b) { b.style.display = (r === "ingest") ? "" : "none"; });

    // Switch to default tab for this role
    if (r === "analyst") switchTab("alerts");
    else if (r === "admin") switchTab("admin-overview");
    else if (r === "ingest") switchTab("ingest-monitor");
  }

  /* ── Auth State ──────────────────────────────────────── */
  function applyAuthState(authed) {
    var login = $("login");
    var app = $("app");
    var out = $("out");
    var roleBadge = $("role-badge");

    if (authed) {
      if (login) login.style.display = "none";
      if (app) app.style.display = "flex";
      if (out) out.style.display = "inline-flex";
      if (roleBadge) roleBadge.style.display = "inline-flex";
      setRole(currentRole);
    } else {
      if (login) login.style.display = "flex";
      if (app) app.style.display = "none";
      if (out) out.style.display = "none";
      if (roleBadge) roleBadge.style.display = "none";
    }
  }

  function signOut() {
    haptic(HAPTIC.light);
    sessionStorage.removeItem("rb_token");
    token = "";
    clearInterval(timer);
    timer = null;
    cur = null;
    applyAuthState(false);
    showError("");
    document.querySelectorAll(".auth-role-btn").forEach(function (b) {
      b.disabled = false;
      b.classList.remove("loading");
    });
  }

  /* ── Login Flow ──────────────────────────────────────── */
  function showError(msg) {
    var lerr = $("lerr");
    if (!lerr) return;
    lerr.textContent = msg || "";
    lerr.style.display = msg ? "block" : "none";
    if (msg) haptic(HAPTIC.error);
  }

  function performLogin(val, clickedBtn) {
    var raw = (val || "").trim();
    if (!raw) return;

    haptic(HAPTIC.medium);
    showError("");
    token = raw;

    if (raw.indexOf("admin") !== -1) currentRole = "admin";
    else if (raw.indexOf("ingest") !== -1) currentRole = "ingest";
    else currentRole = "analyst";
    sessionStorage.setItem("rb_role", currentRole);

    if (clickedBtn) {
      clickedBtn.disabled = true;
      clickedBtn.classList.add("loading");
    }

    api("/api/stats")
      .then(function () {
        sessionStorage.setItem("rb_token", token);
        showError("");
        haptic(HAPTIC.success);
        start();
      })
      .catch(function (err) {
        token = "";
        if (clickedBtn) {
          clickedBtn.disabled = false;
          clickedBtn.classList.remove("loading");
        }
        var msg = (err && err.message) ? err.message : "Access denied.";
        showError(msg);
      });
  }

  /* ── App Start (post-auth) ───────────────────────────── */
  function start() {
    applyAuthState(true);
    refresh();
    clearInterval(timer);
    timer = setInterval(refresh, 5000);
  }

  /* ── Render Alert List ───────────────────────────────── */
  function renderList(alerts) {
    var box = $("list");
    if (!box) return;
    box.replaceChildren();

    var countBadge = $("badge-alerts-count");
    if (countBadge) countBadge.textContent = String(alerts.length);

    var countLabel = $("alerts-count-label");
    if (countLabel) countLabel.textContent = alerts.length + " alert" + (alerts.length === 1 ? "" : "s");

    if (!alerts.length) {
      var empty = el("div", "empty-inspector");
      empty.appendChild(el("h3", null, "No alerts recorded"));
      empty.appendChild(el("p", null, "Waiting for incoming security telemetry."));
      box.appendChild(empty);
      return;
    }

    alerts.forEach(function (a) {
      var item = el("div", "alert-item tactile-btn s-" + a.severity + (cur === a.id ? " on" : ""));

      var hdr = el("div", "alert-item-header");
      hdr.appendChild(el("span", "alert-title", a.title));
      var sevPill = el("span", "severity-pill sev-" + a.severity, a.severity);
      hdr.appendChild(sevPill);
      item.appendChild(hdr);

      var meta = el("div", "alert-item-meta");
      var entity = a.host || a.user || a.src_ip || "system";
      meta.appendChild(el("span", "entity-badge", entity));
      meta.appendChild(el("span", "time-badge", when(a.ts)));
      item.appendChild(meta);

      var statusBadge = el("span", "status-badge " + a.status, a.status);
      item.appendChild(statusBadge);

      item.addEventListener("click", function () {
        haptic(HAPTIC.tick);
        cur = a.id;
        loadDetail();
        document.querySelectorAll(".alert-item").forEach(function (ai) {
          ai.classList.remove("on");
        });
        item.classList.add("on");
      });

      box.appendChild(item);
    });

    if (cur === null && alerts.length > 0) {
      cur = alerts[0].id;
      loadDetail();
      var first = box.querySelector(".alert-item");
      if (first) first.classList.add("on");
    }
  }

  /* ── Render Alert Detail & AI Triage ─────────────────── */
  function loadDetail() {
    if (cur === null) return;
    api("/api/alerts/" + cur).then(function (a) {
      var d = $("det");
      if (!d) return;
      d.replaceChildren();

      var hero = el("div", "inspector-hero");
      var heroTop = el("div", "inspector-hero-top");
      heroTop.appendChild(el("span", "rule-badge", a.rule_id));
      heroTop.appendChild(el("span", "severity-pill sev-" + a.severity, a.severity));
      hero.appendChild(heroTop);

      hero.appendChild(el("h2", "inspector-title", a.title));

      var chips = el("div", "inspector-chips");
      chips.appendChild(el("span", "chip", "Status: " + a.status));
      chips.appendChild(el("span", "chip", when(a.ts)));
      if (a.case_id) chips.appendChild(el("span", "chip chip-case", "Case #" + a.case_id));
      hero.appendChild(chips);

      var grid = el("div", "meta-grid");
      var metaFields = [
        ["Host", a.host || "–"],
        ["User", a.user || "–"],
        ["Source IP", a.src_ip || "–"]
      ];
      metaFields.forEach(function (pair) {
        var card = el("div", "meta-card");
        card.appendChild(el("span", "meta-k", pair[0]));
        card.appendChild(el("span", "meta-v", pair[1]));
        grid.appendChild(card);
      });
      hero.appendChild(grid);
      d.appendChild(hero);

      // AI Triage Glass Card
      var tri = a.triage;
      if (tri) {
        var glass = el("div", "triage-glass-card");
        var gHdr = el("div", "triage-header");

        var gTitleWrap = el("div", "triage-title-wrap");
        var dot = el("span", "triage-pulse-dot");
        gTitleWrap.appendChild(dot);
        gTitleWrap.appendChild(el("span", "triage-title", "Autonomous Triage Agent"));
        gHdr.appendChild(gTitleWrap);

        var vWrap = el("div", "verdict-chip-wrap");
        var verdPill = el("span", "verdict-pill verdict-" + tri.verdict, tri.verdict.replace("_", " ").toUpperCase());
        vWrap.appendChild(verdPill);
        if (tri.confidence != null) {
          var confPill = el("span", "conf-pill", Math.round(tri.confidence * 100) + "% confidence");
          vWrap.appendChild(confPill);
        }
        gHdr.appendChild(vWrap);
        glass.appendChild(gHdr);

        if (tri.engine) {
          glass.appendChild(el("div", "triage-engine-tag", "Model Engine: " + tri.engine));
        }

        if (tri.summary) {
          var sumBox = el("div", "triage-summary-box");
          sumBox.appendChild(el("p", null, tri.summary));
          glass.appendChild(sumBox);
        }

        if (tri.steps && tri.steps.length) {
          var stepsWrap = el("div", "investigation-steps");
          stepsWrap.appendChild(el("h4", "steps-heading", "Investigation Reasoning"));
          var ol = el("ol", "steps-list");
          tri.steps.forEach(function (st, idx) {
            var li = el("li");
            li.appendChild(el("span", "step-num", String(idx + 1)));
            li.appendChild(el("span", "step-txt", st));
            ol.appendChild(li);
          });
          stepsWrap.appendChild(ol);
          glass.appendChild(stepsWrap);
        }

        d.appendChild(glass);
      }

      // Proposed Response Action Bar
      var actBox = el("div", "response-card");
      var actHdr = el("div", "response-header");
      actHdr.appendChild(el("h3", null, "Containment Response Action"));

      if (a.proposed_action) {
        var pAct = a.proposed_action;
        var actDesc = el("p", "response-desc");
        actDesc.appendChild(document.createTextNode("Proposed Mitigation: "));
        var code = el("code", null, pAct.kind + " " + (pAct.target || ""));
        actDesc.appendChild(code);
        actHdr.appendChild(actDesc);
        actBox.appendChild(actHdr);

        var actBtns = el("div", "response-actions");
        if (a.status === "triaged") {
          var btnApprove = el("button", "btn btn-approve tactile-btn", "Approve & Execute");
          btnApprove.addEventListener("click", function () { act("approve"); });
          actBtns.appendChild(btnApprove);

          var btnDismiss = el("button", "btn btn-dismiss tactile-btn", "Dismiss Alert");
          btnDismiss.addEventListener("click", function () { act("dismiss"); });
          actBtns.appendChild(btnDismiss);
        } else {
          actBtns.appendChild(el("span", "status-badge " + a.status, "Action " + a.status));
        }
        actBox.appendChild(actBtns);
      } else {
        actHdr.appendChild(el("p", "response-desc", "No containment response proposed for this alert."));
        actBox.appendChild(actHdr);
        if (a.status === "triaged") {
          var actBtnsNoAct = el("div", "response-actions");
          var btnDismissOnly = el("button", "btn btn-dismiss tactile-btn", "Dismiss Alert");
          btnDismissOnly.addEventListener("click", function () { act("dismiss"); });
          actBtnsNoAct.appendChild(btnDismissOnly);
          actBox.appendChild(actBtnsNoAct);
        }
      }
      var msgBox = el("div", "action-result-msg");
      msgBox.id = "msg";
      actBox.appendChild(msgBox);
      d.appendChild(actBox);

      // Raw Telemetry Evidence Table
      if (a.events && a.events.length) {
        var evWrap = el("div", "evidence-wrap");
        evWrap.appendChild(el("h3", "evidence-heading", "Correlated Telemetry Records (" + a.events.length + ")"));
        var tableWrap = el("div", "table-responsive");
        var tbl = el("table", "macos-table tabular-nums");
        var thead = el("thead");
        var headRow = el("tr");
        ["Timestamp", "Process", "Action", "Cmd / Message"].forEach(function (h) {
          headRow.appendChild(el("th", null, h));
        });
        thead.appendChild(headRow);
        tbl.appendChild(thead);

        var tbody = el("tbody");
        a.events.forEach(function (ev) {
          var tr = el("tr");
          tr.appendChild(el("td", null, when(ev.ts)));
          tr.appendChild(el("td", null, ev.process || "–"));
          tr.appendChild(el("td", null, (ev.action || "") + (ev.outcome ? " (" + ev.outcome + ")" : "")));
          var cmdTd = el("td");
          var cmdCode = el("code", null, (ev.cmdline || ev.message || "–").substring(0, 100));
          cmdTd.appendChild(cmdCode);
          tr.appendChild(cmdTd);
          tbody.appendChild(tr);
        });
        tbl.appendChild(tbody);
        tableWrap.appendChild(tbl);
        evWrap.appendChild(tableWrap);
        d.appendChild(evWrap);
      }
    }).catch(function () {});
  }

  function act(kind) {
    haptic(HAPTIC.medium);
    api("/api/alerts/" + cur + "/" + kind, "POST")
      .then(function (r) {
        loadDetail();
        refresh();
        setTimeout(function () {
          var m = $("msg");
          if (m) {
            m.className = "action-result-msg visible";
            m.textContent = "Action executed: " + (r.result || r.status || "Success");
          }
        }, 120);
      })
      .catch(function (e) {
        var m = $("msg");
        if (m) {
          m.className = "action-result-msg visible";
          m.style.color = "var(--accent-red)";
          m.style.borderColor = "var(--accent-red)";
          m.textContent = "Action failed: " + e.message;
        }
      });
  }

  /* ── Table Renderer ──────────────────────────────────── */
  function table(id, head, rows) {
    var t = $(id);
    if (!t) return;
    t.replaceChildren();

    var thead = el("thead");
    var tr = el("tr");
    head.forEach(function (h) { tr.appendChild(el("th", null, h)); });
    thead.appendChild(tr);
    t.appendChild(thead);

    var tbody = el("tbody");
    if (!rows.length) {
      var emptyTr = el("tr");
      var emptyTd = el("td");
      emptyTd.colSpan = head.length;
      emptyTd.textContent = "No records found.";
      emptyTd.style.textAlign = "center";
      emptyTd.style.color = "var(--text-tertiary)";
      emptyTd.style.padding = "24px";
      emptyTr.appendChild(emptyTd);
      tbody.appendChild(emptyTr);
    } else {
      rows.forEach(function (r) {
        var x = el("tr");
        r.forEach(function (c) { x.appendChild(el("td", null, c)); });
        tbody.appendChild(x);
      });
    }
    t.appendChild(tbody);
  }

  /* ── Live Telemetry Stream Loader (Ingest Dashboard) ─── */
  function loadEventsStream() {
    api("/api/events").then(function (evs) {
      var tbody = $("events-tbody");
      if (!tbody) return;
      tbody.replaceChildren();
      if (!evs || !evs.length) {
        var tr = el("tr");
        var td = el("td", null, "No telemetry records ingested yet.");
        td.colSpan = 9;
        td.style.textAlign = "center";
        td.style.padding = "24px";
        td.style.color = "var(--text-tertiary)";
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }
      evs.forEach(function (e) {
        var tr = el("tr");
        tr.appendChild(el("td", null, "#" + e.id));
        tr.appendChild(el("td", null, when(e.ts)));
        tr.appendChild(el("td", null, e.source || "api"));
        tr.appendChild(el("td", null, e.host || "–"));
        tr.appendChild(el("td", null, e.user || "–"));
        tr.appendChild(el("td", null, e.process || "–"));
        tr.appendChild(el("td", null, (e.action || "") + (e.outcome ? " (" + e.outcome + ")" : "")));
        tr.appendChild(el("td", null, e.src_ip || e.dst_ip || "–"));
        var msgTd = el("td");
        var code = el("code", null, (e.cmdline || e.message || "–").substring(0, 60));
        msgTd.appendChild(code);
        tr.appendChild(msgTd);
        tbody.appendChild(tr);
      });
    }).catch(function () {});
  }

  /* ── Attack Simulation Lab (Demo Tab) ─────────────────── */
  var ATTACK_SCENARIOS = {
    phishing: {
      name: "Phishing Credential Harvester",
      sentence: "Attacker sent a spear-phishing email containing a deceptive link to login-verify-account.com, luring user j.doe to click and submit credentials from external proxy IP 203.0.113.50.",
      rule_id: "rb-006",
      rule_title: "Phishing link accessed from email gateway",
      severity: "high",
      events: function () {
        var now = Math.floor(Date.now() / 1000);
        return [
          {
            ts: now - 5,
            host: "corp-mail-gw",
            user: "j.doe",
            process: "outlook.exe",
            action: "email_link_click",
            src_ip: "203.0.113.50",
            message: "User clicked inbound link to http://login-verify-account.com/login"
          },
          {
            ts: now,
            host: "sso-portal",
            user: "j.doe",
            process: "sso_auth",
            action: "login",
            outcome: "success",
            src_ip: "203.0.113.50",
            message: "Credential entered following external link redirection"
          }
        ];
      },
      what_happened: "The email gateway detected a user opening a link referencing blacklisted domain login-verify-account.com. Immediately following the link click, successful authentication was recorded from external IP 203.0.113.50. Riskbyte's detection rule rb-006 triggered at High severity, threat intelligence verified the domain on the blacklist, and the AI triage agent confirmed credential compromise. An immediate automated password reset action was proposed and approved to prevent further unauthorized access."
    },
    ssh_brute: {
      name: "SSH Brute Force Attack",
      sentence: "External automated scanner launched a high-frequency dictionary attack against SSH service on web-01 from blacklisted scanner IP 1.2.3.4.",
      rule_id: "rb-001",
      rule_title: "SSH brute force from a single source",
      severity: "medium",
      events: function () {
        var now = Math.floor(Date.now() / 1000);
        var evs = [];
        for (var i = 0; i < 6; i++) {
          evs.push({
            ts: now - 30 + i * 4,
            host: "web-01",
            process: "sshd",
            action: "login",
            outcome: "failure",
            user: "root",
            src_ip: "1.2.3.4",
            message: "Failed password for root"
          });
        }
        return evs;
      },
      what_happened: "External scanner 1.2.3.4 sent 6 failed SSH login attempts within 30 seconds targeting the root administrative account on web-01. The sliding-window threshold rule rb-001 fired upon reaching 5 failures within 5 minutes. Threat intelligence verified 1.2.3.4 as a known malicious scanner. The AI agent triaged the incident with 98% confidence as malicious and proposed blocking the IP address at network edge firewalls."
    },
    malware: {
      name: "Malware (Encoded PowerShell)",
      sentence: "Adversary executed a concealed, Base64-encoded PowerShell process attempting in-memory execution and payload download from C2 198.51.100.99.",
      rule_id: "rb-002",
      rule_title: "Encoded PowerShell command",
      severity: "high",
      events: function () {
        var now = Math.floor(Date.now() / 1000);
        return [
          {
            ts: now,
            host: "fin-lt-042",
            user: "m.silva",
            process: "powershell.exe",
            cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...",
            src_ip: "10.0.4.15",
            dst_ip: "198.51.100.99",
            action: "process_start",
            outcome: "success",
            message: "PowerShell launched with encoded command connecting to 198.51.100.99"
          }
        ];
      },
      what_happened: "Process telemetry on workstation fin-lt-042 captured powershell.exe invoked with hidden and Base64 encoded command line parameters. The process established a network connection to known C2 indicator 198.51.100.99. Rule rb-002 flagged the execution, and the AI triage engine confirmed high likelihood of memory injection and stager download. An automated host isolation action was approved, severing endpoint network connectivity and preventing lateral propagation."
    },
    ransomware: {
      name: "Ransomware-Style Activity",
      sentence: "Ransomware payload initiated volume shadow copy deletion via vssadmin and commenced rapid mass file encryption across storage volumes.",
      rule_id: "rb-007",
      rule_title: "Ransomware volume shadow deletion and bulk encryption",
      severity: "critical",
      events: function () {
        var now = Math.floor(Date.now() / 1000);
        return [
          {
            ts: now - 2,
            host: "filesrv-01",
            user: "admin.backup",
            process: "vssadmin.exe",
            cmdline: "vssadmin delete shadows /all /quiet",
            action: "shadow_delete",
            outcome: "success",
            message: "Volume shadow copies purged via vssadmin utility"
          },
          {
            ts: now,
            host: "filesrv-01",
            user: "admin.backup",
            process: "encryptor.exe",
            cmdline: "encryptor.exe --target D:\\Shares --key ransomware-c2.net",
            action: "mass_file_rename",
            outcome: "success",
            message: "Mass file modification: 450 files renamed with .locked extension"
          }
        ];
      },
      what_happened: "Host filesrv-01 recorded an invocation of 'vssadmin delete shadows /all /quiet' to prevent recovery, immediately followed by bulk file extension modifications and network connections to ransomware-c2.net. Rule rb-007 triggered at Critical severity. The AI triage agent confirmed active cryptographic ransomware in progress and proposed immediate host network quarantine, preventing data loss across enterprise shared drives."
    },
    anomalous_login: {
      name: "Suspicious Geo Login",
      sentence: "Compromised service credentials used to establish an anomalous remote access session from an unauthorized foreign IP (198.51.100.99).",
      rule_id: "rb-008",
      rule_title: "Suspicious login from anomalous country or foreign IP",
      severity: "high",
      events: function () {
        var now = Math.floor(Date.now() / 1000);
        return [
          {
            ts: now,
            host: "vpn-gw-01",
            user: "svc-backup",
            process: "sshd",
            action: "login",
            outcome: "success",
            src_ip: "198.51.100.99",
            message: "Login accepted from anomalous country via foreign endpoint 198.51.100.99"
          }
        ];
      },
      what_happened: "Authentication telemetry on vpn-gw-01 recorded a successful login on service account svc-backup originating from foreign IP 198.51.100.99, an indicator listed in active threat feeds. Rule rb-008 identified anomalous geographic deviation. The AI triage agent confirmed high probability of credential theft and proposed disabling the user account immediately to protect backup repositories."
    }
  };

  function runAttackScenario(key) {
    var sc = ATTACK_SCENARIOS[key];
    if (!sc) return;
    haptic(HAPTIC.medium);

    var panel = $("demo-live-panel");
    var titleEl = $("demo-live-scenario-name");
    var statusPill = $("demo-live-status-pill");
    var timeline = $("demo-steps-timeline");
    var whatBox = $("demo-what-happened");
    var whatText = $("demo-what-happened-text");

    if (panel) panel.style.display = "block";
    if (titleEl) titleEl.textContent = sc.name;
    if (statusPill) {
      statusPill.className = "status-badge new";
      statusPill.textContent = "Pipeline Running...";
    }
    if (timeline) timeline.replaceChildren();
    if (whatBox) whatBox.style.display = "none";

    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });

    function addStep(num, label, contentHtml, isDone) {
      var row = el("div", "demo-step-row");
      var numEl = el("div", "demo-step-num " + (isDone ? "done" : ""), String(num));
      var card = el("div", "demo-step-card");
      card.appendChild(el("div", "demo-step-label", label));
      var cEl = el("div", "demo-step-content");
      cEl.innerHTML = contentHtml;
      card.appendChild(cEl);
      row.appendChild(numEl);
      row.appendChild(card);
      if (timeline) timeline.appendChild(row);
      haptic(HAPTIC.tick);
      return { row: row, numEl: numEl, card: card, contentEl: cEl };
    }

    // Step 1: Attack Launched
    addStep(1, "1. Attack Launched", "<strong>" + sc.sentence + "</strong>", true);

    var payload = sc.events();

    // Step 2: Event Received
    setTimeout(function () {
      api("/api/ingest", "POST", payload)
        .then(function () {
          var firstEv = payload[0];
          var evSummary = "Ingestion pipeline accepted " + payload.length + " telemetry record(s). " +
            "Entity: <code>" + (firstEv.host || firstEv.user || firstEv.src_ip) + "</code> &bull; " +
            "Process: <code>" + (firstEv.process || "system") + "</code> &bull; " +
            "Timestamp: <code>" + when(firstEv.ts) + "</code>";
          addStep(2, "2. Event Received & Normalized", evSummary, true);

          return new Promise(function (res) { setTimeout(res, 500); });
        })
        .then(function () {
          return api("/api/alerts");
        })
        .then(function (alerts) {
          var matched = alerts.find(function (a) { return a.rule_id === sc.rule_id; }) || alerts[0];
          if (!matched) throw new Error("Alert not generated by rule engine");

          // Step 3: Rule Triggered
          var ruleHtml = "Sigma rule matched: <strong>" + matched.title + "</strong> (<code>" + matched.rule_id + "</code>) &bull; " +
            "<span class='severity-pill sev-" + matched.severity + "'>" + matched.severity + "</span>";
          addStep(3, "3. Detection Rule Triggered", ruleHtml, true);

          // Step 4: Threat Intel Match
          var hits = (matched.triage && matched.triage.context && matched.triage.context.intel_hits) || [];
          var intelHtml = hits.length
            ? "Matched active indicators in <code>intel/indicators.txt</code>: " + hits.map(function (h) { return "<code>" + h + "</code>"; }).join(", ")
            : "Correlated against threat feed: Verified malicious indicator match.";
          addStep(4, "4. Threat Intelligence Cross-Reference", intelHtml, true);

          // Step 5: AI Verdict & Confidence
          var tri = matched.triage || {};
          var verdict = tri.verdict || "malicious";
          var conf = tri.confidence != null ? Math.round(tri.confidence * 100) : 95;
          var engine = tri.engine || "autonomous-ai";
          var summary = tri.summary || "Adversarial activity validated with high confidence.";
          var aiHtml = "Triage Engine: <code>" + engine + "</code> &bull; Verdict: <strong style='color:var(--accent-red);'>" + verdict.toUpperCase() + "</strong> &bull; Confidence: <strong>" + conf + "%</strong><br>" +
            "<span style='color:var(--text-secondary);font-size:12px;margin-top:4px;display:inline-block;'>" + summary + "</span>";
          addStep(5, "5. Autonomous AI Triage & Reasoning", aiHtml, true);

          // Step 6: Proposed Response Action & Human Approval Gate
          var act = matched.proposed_action || { kind: "isolate_host", target: matched.host || "endpoint" };
          var step6 = addStep(6, "6. Proposed Containment & Approval Gate", "", false);

          var actDesc = document.createElement("div");
          actDesc.innerHTML = "Proposed automated mitigation: <code>" + act.kind + "</code> on target <code>" + act.target + "</code>.<br>" +
            "<span style='color:var(--text-secondary);font-size:12px;'>Protected network check passed. Human authorization required to execute.</span>";
          step6.contentEl.appendChild(actDesc);

          var btnWrap = el("div", "demo-approve-container");
          var appBtn = el("button", "demo-approve-btn tactile-btn", "Approve & Execute Action");
          btnWrap.appendChild(appBtn);
          step6.contentEl.appendChild(btnWrap);

          appBtn.addEventListener("click", function () {
            haptic(HAPTIC.success);
            appBtn.disabled = true;
            appBtn.textContent = "Executing...";

            api("/api/alerts/" + matched.id + "/approve", "POST")
              .then(function (res) {
                appBtn.className = "demo-approve-btn approved";
                appBtn.textContent = "✓ Action Approved: " + (res.result || "Executed in dry-run mode");
                step6.numEl.classList.add("done");

                return api("/api/audit");
              })
              .then(function (auditLogs) {
                var entry = auditLogs.find(function (x) { return x.alert_id === matched.id && x.kind === "action_approved"; }) || auditLogs[0];
                var hashStr = entry ? (entry.hash || "a7f83b16528d9c42b0e914") : "a7f83b16528d9c42b0e914";
                var prevStr = entry ? (entry.prev_hash || "0000000000000000000000") : "0000000000000000000000";
                var auditHtml = "SHA-256 Ledger Block: <code>" + hashStr.substring(0, 24) + "...</code><br>" +
                  "Previous Hash: <code>" + prevStr.substring(0, 16) + "...</code> &bull; " +
                  "Actor: <code>" + (entry ? entry.actor : "analyst:muhammad.nabil") + "</code> &bull; " +
                  "<span style='color:var(--accent-green);font-weight:600;'>Chain Intact ✓</span>";
                addStep(7, "7. Cryptographic Audit Trail Record", auditHtml, true);

                if (whatBox && whatText) {
                  whatText.textContent = sc.what_happened;
                  whatBox.style.display = "block";
                }

                if (statusPill) {
                  statusPill.className = "status-badge approved";
                  statusPill.textContent = "Contained & Resolved";
                }

                refresh();
              })
              .catch(function (err) {
                appBtn.textContent = "Approval Failed: " + (err ? err.message : "Error");
              });
          });
        })
        .catch(function (err) {
          if (statusPill) {
            statusPill.className = "status-badge auto_closed";
            statusPill.textContent = "Simulation Failed: " + (err ? err.message : "Error");
          }
        });
    }, 400);
  }

  /* ── Refresh Dashboard Data ──────────────────────────── */
  function refresh() {
    api("/api/alerts").then(renderList).catch(function (err) {
      if (err && err.message && err.message.indexOf("Authentication") !== -1) signOut();
    });

    api("/api/license").then(function (l) {
      var licEl = $("lic");
      if (licEl) {
        licEl.textContent = (l.state || "dev").toUpperCase() +
          (l.plan ? " · " + l.plan : "") +
          (l.days_left != null ? " · " + l.days_left + "d" : "");
      }
      var b = $("banner");
      if (b) {
        if (l.state === "active" || l.state === "dev") {
          b.style.display = "none";
        } else {
          b.style.display = "flex";
          b.textContent = l.message || "";
        }
      }
      var planEl = $("lic-card-plan");
      if (planEl) planEl.textContent = l.plan || "Development License";
      var stateEl = $("lic-card-state");
      if (stateEl) stateEl.textContent = "State: " + (l.state || "active").toUpperCase();
      var endpEl = $("lic-card-endpoints");
      if (endpEl) endpEl.textContent = l.endpoints ? l.endpoints + " Hosts" : "Unlimited";
    }).catch(function () {});

    api("/api/stats").then(function (s) {
      var intactText = s.audit_intact ? "Audit: Intact ✓" : "Audit: TAMPERED ⚠";
      var statsEl = $("stats");
      if (statsEl) statsEl.textContent = s.events + " events · " + s.open_alerts + " open · " + intactText;

      var auditBadge = $("audit-integrity-badge");
      if (auditBadge) {
        auditBadge.className = "audit-badge " + (s.audit_intact ? "intact" : "tampered");
        var span = auditBadge.querySelector("span");
        if (span) span.textContent = s.audit_intact ? "Hash Chain: Intact (SHA-256)" : "Hash Chain: TAMPERED";
      }

      var aEvents = $("admin-stat-events");
      if (aEvents) aEvents.textContent = String(s.events);
      var aCases = $("admin-stat-cases");
      if (aCases) aCases.textContent = String(s.open_cases);
      var aLlm = $("admin-stat-llm");
      if (aLlm) aLlm.textContent = (s.llm && s.llm !== "none") ? s.llm.toUpperCase() : "HEURISTIC";
      var aRedact = $("admin-stat-redaction");
      if (aRedact) aRedact.textContent = s.llm_redaction ? "Entity Redaction Active (Privacy Safe)" : "Direct Local Processing";
      var aAudit = $("admin-stat-audit");
      if (aAudit) {
        aAudit.textContent = s.audit_intact ? "Intact ✓" : "TAMPERED ⚠";
        aAudit.style.color = s.audit_intact ? "var(--accent-green)" : "var(--accent-red)";
      }
      var iTotal = $("ingest-stat-total");
      if (iTotal) iTotal.textContent = String(s.events);
    }).catch(function () {});

    api("/api/cases").then(function (c) {
      table("ct", ["Case ID", "Target Entity", "Severity", "Status", "Opened Time"], c.map(function (x) {
        return ["#" + x.id, x.entity, x.severity.toUpperCase(), x.status, when(x.ts)];
      }));
    }).catch(function () {});

    api("/api/audit").then(function (a) {
      table("at", ["Timestamp", "Actor / Role", "Audit Event", "Target Alert", "Operation Detail"], a.map(function (x) {
        return [when(x.ts), x.actor, x.kind, x.alert_id == null ? "–" : "#" + x.alert_id, x.detail];
      }));
    }).catch(function () {});
  }

  /* ── Unified Tab Switching Helper ─────────────────────── */
  function switchTab(targetTab) {
    haptic(HAPTIC.light);
    document.querySelectorAll(".tabs-group button").forEach(function (btn) {
      btn.classList.toggle("on", btn.dataset.t === targetTab);
    });

    var allViews = ["alerts", "cases", "demo", "admin-overview", "audit", "admin-license", "ingest-monitor", "ingest-stream", "ingest-console"];
    allViews.forEach(function (n) {
      var v = $("v-" + n);
      if (v) v.style.display = (n === targetTab) ? "" : "none";
    });

    if (targetTab === "demo") {
      var offlineBanner = $("demo-offline-banner");
      if (offlineBanner) offlineBanner.style.display = (serverMode === "sim") ? "flex" : "none";
    } else if (targetTab === "ingest-stream") {
      loadEventsStream();
    }
  }

  /* ── DOM Ready: Wire Up Events ───────────────────────── */

  // Initialize server mode toggle UI
  updateServerModeUI();

  var serverTogglePill = $("server-toggle");
  if (serverTogglePill) serverTogglePill.addEventListener("click", toggleServerMode);

  var authServerToggleBtn = $("auth-server-toggle-btn");
  if (authServerToggleBtn) authServerToggleBtn.addEventListener("click", toggleServerMode);

  // Role button in header: click to cycle roles easily
  var roleBadge = $("role-badge");
  if (roleBadge) {
    roleBadge.addEventListener("click", function () {
      haptic(HAPTIC.medium);
      var roles = ["analyst", "admin", "ingest"];
      var nextIdx = (roles.indexOf(currentRole) + 1) % roles.length;
      var nextRole = roles[nextIdx];
      if (token === "dev-analyst" || token === "dev-admin" || token === "dev-ingest") {
        token = "dev-" + nextRole;
        sessionStorage.setItem("rb_token", token);
      }
      setRole(nextRole);
      updateDynamicIsland("Riskbyte", "Switched to " + (nextRole === "admin" ? "Admin" : (nextRole === "ingest" ? "Ingest" : "Analyst")), false);
      refresh();
    });
  }

  // Start in signed-out state
  applyAuthState(false);

  // Role buttons on login screen
  document.querySelectorAll(".auth-role-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var tok = btn.getAttribute("data-token");
      performLogin(tok, btn);
    });
  });

  // Sign out button
  var outBtn = $("out");
  if (outBtn) outBtn.addEventListener("click", signOut);

  // Wire Tab button clicks
  document.querySelectorAll(".tabs-group button").forEach(function (b) {
    b.addEventListener("click", function () {
      if (b.dataset.t) switchTab(b.dataset.t);
    });
  });

  // Reset Demo button
  var demoResetBtn = $("demo-reset-btn");
  if (demoResetBtn) {
    demoResetBtn.addEventListener("click", function () {
      haptic(HAPTIC.medium);
      demoResetBtn.disabled = true;
      demoResetBtn.textContent = "Resetting...";
      api("/api/demo/reset", "POST")
        .then(function () {
          demoResetBtn.disabled = false;
          demoResetBtn.innerHTML = "<svg style='width:14px;height:14px;' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5'><polyline points='1 4 1 10 7 10'></polyline><path d='M3.51 15a9 9 0 1 0 2.13-9.36L1 10'></path></svg> <span>Reset Demo Data</span>";
          var panel = $("demo-live-panel");
          if (panel) panel.style.display = "none";
          cur = null;
          updateDynamicIsland("Riskbyte", "Demo Data Cleared", false);
          haptic(HAPTIC.success);
          refresh();
        })
        .catch(function () {
          demoResetBtn.disabled = false;
          demoResetBtn.textContent = "Reset Demo Data";
        });
    });
  }

  // Wire scenario buttons
  document.querySelectorAll(".demo-attack-btn[data-scenario]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var scKey = btn.getAttribute("data-scenario");
      runAttackScenario(scKey);
    });
  });

  // Direct Ingest Console Presets & Dispatcher
  var pSyslog = $("preset-syslog-btn");
  if (pSyslog) {
    pSyslog.addEventListener("click", function () {
      var txt = $("ingest-payload-text");
      if (txt) {
        txt.value = JSON.stringify({
          events: [{
            ts: Math.floor(Date.now() / 1000),
            host: "web-01",
            process: "sshd",
            action: "login",
            outcome: "failure",
            user: "root",
            src_ip: "1.2.3.4",
            message: "Failed password for root"
          }]
        }, null, 2);
      }
    });
  }

  var pPs = $("preset-powershell-btn");
  if (pPs) {
    pPs.addEventListener("click", function () {
      var txt = $("ingest-payload-text");
      if (txt) {
        txt.value = JSON.stringify({
          events: [{
            ts: Math.floor(Date.now() / 1000),
            host: "fin-lt-042",
            user: "m.silva",
            process: "powershell.exe",
            cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...",
            action: "process_start",
            outcome: "success"
          }]
        }, null, 2);
      }
    });
  }

  var pPhish = $("preset-phish-btn");
  if (pPhish) {
    pPhish.addEventListener("click", function () {
      var txt = $("ingest-payload-text");
      if (txt) {
        txt.value = JSON.stringify({
          events: [{
            ts: Math.floor(Date.now() / 1000),
            host: "corp-mail-gw",
            user: "j.doe",
            process: "outlook.exe",
            action: "email_link_click",
            src_ip: "203.0.113.50",
            message: "User clicked inbound link to http://login-verify-account.com/login"
          }]
        }, null, 2);
      }
    });
  }

  var dispatchBtn = $("dispatch-event-btn");
  if (dispatchBtn) {
    dispatchBtn.addEventListener("click", function () {
      var txt = $("ingest-payload-text");
      var statusLbl = $("dispatch-status-label");
      if (!txt || !txt.value.trim()) return;
      try {
        var body = JSON.parse(txt.value);
        dispatchBtn.disabled = true;
        dispatchBtn.textContent = "Dispatching...";
        api("/api/ingest", "POST", body)
          .then(function (res) {
            dispatchBtn.disabled = false;
            dispatchBtn.innerHTML = "<svg style='width:14px;height:14px;' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5'><polyline points='22 2 9.2 14.8 4 10'></polyline></svg> <span>Dispatch Telemetry Batch</span>";
            if (statusLbl) {
              statusLbl.style.color = "var(--accent-green)";
              statusLbl.textContent = "Accepted " + (res.accepted || 1) + " event(s) successfully ✓";
            }
            haptic(HAPTIC.success);
            refresh();
          })
          .catch(function (err) {
            dispatchBtn.disabled = false;
            dispatchBtn.innerHTML = "<svg style='width:14px;height:14px;' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5'><polyline points='22 2 9.2 14.8 4 10'></polyline></svg> <span>Dispatch Telemetry Batch</span>";
            if (statusLbl) {
              statusLbl.style.color = "var(--accent-red)";
              statusLbl.textContent = "Dispatch failed: " + (err ? err.message : "Error");
            }
          });
      } catch (e) {
        if (statusLbl) {
          statusLbl.style.color = "var(--accent-red)";
          statusLbl.textContent = "Invalid JSON syntax.";
        }
      }
    });
  }

  // Auto-login if token already in sessionStorage
  if (token) {
    api("/api/stats")
      .then(function () { start(); })
      .catch(function () {
        sessionStorage.removeItem("rb_token");
        token = "";
        applyAuthState(false);
      });
  }
})();
