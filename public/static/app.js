(function () {
  "use strict";

  /* ── Helpers ─────────────────────────────────────────── */
  var $ = function (id) { return document.getElementById(id); };
  var token = sessionStorage.getItem("rb_token") || "";
  var cur = null;
  var timer = null;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  /* ── API Call ─────────────────────────────────────────── */
  function api(path, method) {
    var requestPath = path.startsWith("/") ? path : "/" + path;
    return fetch(requestPath, {
      method: method || "GET",
      headers: {
        Authorization: "Bearer " + token,
        "X-Riskbyte-Console": "1"
      }
    }).then(function (r) {
      if (r.status === 401 || r.status === 403) {
        throw new Error("Authentication failed: invalid or expired token.");
      }
      return r.text().then(function (txt) {
        var j = null;
        try {
          j = JSON.parse(txt);
        } catch (e) {}

        if (!r.ok) {
          if (r.status === 404) {
            throw new Error("API route not found (404). If running locally, ensure backend server is started.");
          }
          throw new Error((j && j.error) ? j.error : ("Server error (" + r.status + ")"));
        }
        return j !== null ? j : txt;
      });
    }).catch(function (err) {
      if (err instanceof TypeError && err.message.toLowerCase().indexOf("fetch") !== -1) {
        throw new Error("Cannot connect to server. Please ensure the backend is running.");
      }
      throw err;
    });
  }

  function when(ts) {
    if (!ts) return "";
    var d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) +
           " (" + d.toLocaleDateString([], { month: "short", day: "numeric" }) + ")";
  }

  /* ── Auth State ──────────────────────────────────────── */
  function applyAuthState(authed) {
    var login = $("login");
    var app = $("app");
    var out = $("out");

    if (authed) {
      if (login) login.style.display = "none";
      if (app) app.style.display = "flex";
      if (out) out.style.display = "";
    } else {
      if (login) login.style.display = "";
      if (app) app.style.display = "none";
      if (out) out.style.display = "none";
    }
  }

  function signOut() {
    sessionStorage.removeItem("rb_token");
    token = "";
    clearInterval(timer);
    timer = null;
    cur = null;
    applyAuthState(false);
    showError("");
    // Re-enable all role buttons
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
  }

  function performLogin(val, clickedBtn) {
    var raw = (val || "").trim();
    if (!raw) return;

    showError("");
    token = raw;

    // Show loading state on the clicked button
    if (clickedBtn) {
      clickedBtn.disabled = true;
      clickedBtn.classList.add("loading");
    }

    api("/api/stats")
      .then(function () {
        sessionStorage.setItem("rb_token", token);
        showError("");
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
      var item = el("div", "alert-item s-" + a.severity + (cur === a.id ? " on" : ""));

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

  /* ── Load Alert Detail ───────────────────────────────── */
  function loadDetail() {
    if (!cur) return;
    api("/api/alerts/" + cur).then(function (a) {
      var d = $("det");
      if (!d) return;
      d.replaceChildren();

      var headCard = el("div", "detail-header-card");
      var topRow = el("div", "detail-top-row");
      topRow.appendChild(el("span", "detail-rule-tag", "Rule: " + a.rule_id));
      var sev = el("span", "severity-pill sev-" + a.severity, a.severity.toUpperCase());
      topRow.appendChild(sev);
      headCard.appendChild(topRow);
      headCard.appendChild(el("h2", "detail-title", a.title));

      var subMeta = el("div", "detail-sub-meta");
      subMeta.appendChild(el("span", null, "Status: " + a.status));
      subMeta.appendChild(el("span", null, "Opened: " + when(a.ts)));
      if (a.case_id) subMeta.appendChild(el("span", null, "Case #" + a.case_id));
      if (a.host) subMeta.appendChild(el("span", null, "Host: " + a.host));
      if (a.user) subMeta.appendChild(el("span", null, "User: " + a.user));
      if (a.src_ip) subMeta.appendChild(el("span", null, "Source IP: " + a.src_ip));
      headCard.appendChild(subMeta);
      d.appendChild(headCard);

      var triageCard = el("div", "triage-card");
      var tHdr = el("div", "triage-header");
      var headingGroup = el("div", "triage-heading-group");
      headingGroup.appendChild(el("span", "triage-title", "Autonomous Triage & Investigation"));
      tHdr.appendChild(headingGroup);
      var engineTag = el("span", "triage-engine-tag", a.triage ? a.triage.engine : "pending");
      tHdr.appendChild(engineTag);
      triageCard.appendChild(tHdr);

      var t = a.triage;
      if (t) {
        var vBanner = el("div", "verdict-banner");
        var vLeft = el("div", "verdict-left");
        var vPill = el("span", "verdict-pill verdict-" + t.verdict, t.verdict);
        vLeft.appendChild(vPill);
        vLeft.appendChild(el("span", "verdict-summary", t.summary));
        vBanner.appendChild(vLeft);

        var gauge = el("div", "confidence-gauge");
        var confPct = Math.round(t.confidence * 100);
        gauge.appendChild(el("span", "confidence-label", "Confidence: " + confPct + "%"));
        var track = el("div", "confidence-bar-track");
        var fill = el("div", "confidence-bar-fill");
        fill.style.width = confPct + "%";
        track.appendChild(fill);
        gauge.appendChild(track);
        vBanner.appendChild(gauge);
        triageCard.appendChild(vBanner);

        if (t.steps && t.steps.length) {
          var stepList = el("ul", "reasoning-steps-list");
          t.steps.forEach(function (s, idx) {
            var sItem = el("li", "reasoning-step-item");
            sItem.appendChild(el("span", "step-num", String(idx + 1)));
            sItem.appendChild(el("span", null, s));
            stepList.appendChild(sItem);
          });
          triageCard.appendChild(stepList);
        }
      } else {
        triageCard.appendChild(el("p", "empty-sub", "Awaiting AI triage analysis."));
      }
      d.appendChild(triageCard);

      var actCard = el("div", "action-card");
      var actHeader = el("div", "action-card-header");
      actHeader.appendChild(el("span", "action-card-title", "Analyst Approval Gate · Response Action"));
      actCard.appendChild(actHeader);

      if (a.proposed_action) {
        var detailsBox = el("div", "action-details-box");
        var leftBox = el("div", null);
        leftBox.appendChild(el("div", "action-kind-label", "Recommended Action:"));
        leftBox.appendChild(el("div", "action-kind-val", a.proposed_action.kind.replace("_", " ").toUpperCase()));
        detailsBox.appendChild(leftBox);
        var rightBox = el("div", null);
        rightBox.appendChild(el("div", "action-kind-label", "Target Entity:"));
        rightBox.appendChild(el("div", "action-target-badge", a.proposed_action.target));
        detailsBox.appendChild(rightBox);
        actCard.appendChild(detailsBox);
      } else {
        var noAct = el("p", "empty-sub", "No automated containment action required for this alert.");
        noAct.style.marginBottom = "14px";
        actCard.appendChild(noAct);
      }

      var open = a.status === "triaged" || a.status === "failed";
      var btnRow = el("div", "action-buttons-row");
      var okBtn = el("button", "btn-approve", "Approve Action");
      var noBtn = el("button", "btn-dismiss", "Dismiss Alert");
      okBtn.type = "button";
      noBtn.type = "button";
      okBtn.disabled = !(a.status === "triaged" && a.proposed_action);
      noBtn.disabled = !open;
      okBtn.addEventListener("click", function () { act("approve"); });
      noBtn.addEventListener("click", function () { act("dismiss"); });
      btnRow.appendChild(okBtn);
      btnRow.appendChild(noBtn);
      actCard.appendChild(btnRow);

      var msg = el("div", "action-result-msg");
      msg.id = "msg";
      actCard.appendChild(msg);
      d.appendChild(actCard);

      var termCard = el("div", "terminal-card");
      var termHdr = el("div", "terminal-header");
      var termTitle = el("div", "terminal-title");
      termTitle.appendChild(el("span", null, "raw_telemetry_events.log (" + (a.events ? a.events.length : 0) + " events)"));
      termHdr.appendChild(termTitle);
      termCard.appendChild(termHdr);

      var termBody = el("div", "terminal-body");
      if (a.events && a.events.length) {
        termBody.textContent = a.events.map(function (e, i) {
          var parts = [
            "[" + String(i + 1).padStart(2, "0") + "] " + when(e.ts),
            e.host ? "host=" + e.host : "",
            e.user ? "user=" + e.user : "",
            e.src_ip ? "src=" + e.src_ip : "",
            e.process ? "proc=" + e.process : "",
            e.action ? "action=" + e.action : "",
            e.outcome ? "outcome=" + e.outcome : "",
            e.cmdline ? "cmd=\"" + e.cmdline + "\"" : (e.message ? "msg=\"" + e.message + "\"" : "")
          ].filter(Boolean);
          return parts.join("  |  ");
        }).join("\n\n");
      } else {
        termBody.textContent = "// No raw event records attached.";
      }
      termCard.appendChild(termBody);
      d.appendChild(termCard);
    });
  }

  /* ── Approve / Dismiss Action ────────────────────────── */
  function act(kind) {
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
        }, 150);
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
      emptyTd.style.color = "var(--text-muted)";
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
          (l.days_left != null ? " · " + l.days_left + "d left" : "");
      }
      var b = $("banner");
      if (b) {
        if (l.state === "active" || l.state === "dev") {
          b.style.display = "none";
        } else {
          b.style.display = "";
          b.textContent = l.message || "";
        }
      }
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

  /* ── DOM Ready: Wire Up Events ───────────────────────── */

  // Start in signed-out state
  applyAuthState(false);

  // Role buttons — click to authenticate directly
  document.querySelectorAll(".auth-role-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var tok = btn.getAttribute("data-token");
      performLogin(tok, btn);
    });
  });

  // Sign out button
  var outBtn = $("out");
  if (outBtn) outBtn.addEventListener("click", signOut);

  // Activity tabs switching
  document.querySelectorAll(".tabs-group button").forEach(function (b) {
    b.addEventListener("click", function () {
      document.querySelectorAll(".tabs-group button").forEach(function (x) {
        x.classList.toggle("on", x === b);
      });
      ["alerts", "cases", "audit"].forEach(function (n) {
        var v = $("v-" + n);
        if (v) v.style.display = (n === b.dataset.t) ? "" : "none";
      });
    });
  });

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
