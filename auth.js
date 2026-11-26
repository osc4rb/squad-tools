/* auth.js: one sign-in for the whole CS-37 site (home, eSSS, Strats).
   Same Supabase project, key and rules as Falcon Bullets (bullets/index.html), so the session supabase-js keeps in
   localStorage (sb-<project>-auth-token, same origin) also signs the user in to Falcon Bullets, and Bullets'
   "Log out" signs them out here. The login card is a copy of the Bullets one. This only gates the pages:
   eSSS and strat data still stay in the browser (AGENTS.md: no cloud backend for scores).
   Needs: the supabase-js script before this one, and the inline <head> check that sets html.locked. */
(function () {
  "use strict";
  var SUPABASE_URL = "https://rfpkukgaiuguhgkdzgqk.supabase.co";
  var SUPABASE_KEY = "sb_publishable_oy_DMlnMysY0J1oBkAZEuw_OWGhd_Xh";
  var EMAIL_DOMAIN = "@afacademy.af.edu";
  var root = document.documentElement;
  if (!window.supabase) { root.classList.remove("locked"); return; }
  var sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
  var mode = "login";

  var gate = document.createElement("div");
  gate.id = "siteAuth";
  gate.innerHTML =
    '<div class="auth-card">' +
      '<div class="auth-brand"><strong>Cadet Squadron 37</strong></div>' +
      '<div class="auth-tabs"><button class="auth-tab active" id="sa-login" type="button">Log in</button>' +
      '<button class="auth-tab" id="sa-signup" type="button">Sign up</button></div>' +
      '<form id="sa-form">' +
        '<div id="sa-msg" class="auth-msg" hidden></div>' +
        '<div class="auth-field"><label class="lab" for="sa-email">Academy email</label>' +
        '<input type="email" id="sa-email" placeholder="c29first.last@afacademy.af.edu" autocomplete="email" required></div>' +
        '<div class="auth-field"><label class="lab" for="sa-pass">Password</label>' +
        '<input type="password" id="sa-pass" placeholder="••••••••" autocomplete="current-password" required></div>' +
        '<button type="submit" class="auth-submit" id="sa-submit">Log in</button>' +
      '</form>' +
      '<div class="auth-note" id="sa-note"></div>' +
    '</div>';
  var nav = document.querySelector("header.nav");
  if (nav && nav.nextSibling) nav.parentNode.insertBefore(gate, nav.nextSibling); else document.body.appendChild(gate);
  function $(id) { return document.getElementById(id); }

  function setMode(m) {
    mode = m;
    var login = m === "login";
    $("sa-login").classList.toggle("active", login);
    $("sa-signup").classList.toggle("active", !login);
    $("sa-submit").textContent = login ? "Log in" : "Create account";
    $("sa-pass").setAttribute("autocomplete", login ? "current-password" : "new-password");
    $("sa-note").textContent = login ? "" : EMAIL_DOMAIN + " email. Password 6+ characters.";
    hideMsg();
  }
  function showMsg(text, kind) { var m = $("sa-msg"); m.textContent = text; m.className = "auth-msg " + (kind || "err"); m.hidden = false; }
  function hideMsg() { $("sa-msg").hidden = true; }
  $("sa-login").addEventListener("click", function () { setMode("login"); });
  $("sa-signup").addEventListener("click", function () { setMode("signup"); });
  setMode("login");

  $("sa-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var email = $("sa-email").value.trim().toLowerCase(), pass = $("sa-pass").value;
    if (!email || !pass) { showMsg("Enter your email and password."); return; }
    var domain = email.split("@")[1] || "";
    if (mode === "signup" && !/(^|\.)afacademy\.(af\.)?edu$/.test(domain)) { showMsg("Use an " + EMAIL_DOMAIN + " email."); return; }
    if (mode === "signup" && pass.length < 6) { showMsg("Password must be at least 6 characters."); return; }
    var btn = $("sa-submit"), label = mode === "login" ? "Log in" : "Create account";
    btn.disabled = true; btn.textContent = mode === "login" ? "Logging in…" : "Creating…"; hideMsg();
    var p = mode === "login"
      ? sb.auth.signInWithPassword({ email: email, password: pass })
      : sb.auth.signUp({ email: email, password: pass, options: { emailRedirectTo: location.origin + location.pathname } });
    p.then(function (res) {
      btn.disabled = false; btn.textContent = label;
      if (res.error) {
        var m = res.error.message || "Something went wrong.";
        if (mode === "login" && /invalid login/i.test(m)) showMsg("Wrong email or password.");
        else if (/not confirmed/i.test(m)) showMsg("Account not confirmed. Check your email.");
        else if (/already registered|already exists/i.test(m)) showMsg("Account already exists. Log in.");
        else showMsg(m);
        return;
      }
      if (mode === "signup" && !res.data.session) { showMsg("Account created. Confirm it from your email, then log in.", "ok"); setMode("login"); }
    }, function () { btn.disabled = false; btn.textContent = label; showMsg("Network error."); });
  });

  var links = document.querySelector(".nav-links"), out = null;
  function route(session) {
    var on = !!(session && session.user);
    root.classList.toggle("locked", !on);
    if (on && links && !out) {
      out = document.createElement("a"); out.href = "#"; out.textContent = "Log out";
      out.addEventListener("click", function (e) { e.preventDefault(); sb.auth.signOut(); });
      links.appendChild(out);
    } else if (!on && out) { out.remove(); out = null; }
  }
  sb.auth.onAuthStateChange(function (_e, session) { route(session); });
  sb.auth.getSession().then(function (r) { route(r.data.session); }, function () { route(null); });
})();
