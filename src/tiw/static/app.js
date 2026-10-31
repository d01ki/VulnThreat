// Minimal progressive enhancement. Every page works without JavaScript.
(function () {
  "use strict";
  var sidebar = document.getElementById("sidebar");
  var toggle = document.getElementById("nav-toggle");
  function closeNav() {
    if (!sidebar || !toggle) return;
    sidebar.classList.remove("open");
    toggle.setAttribute("aria-expanded", "false");
  }
  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      var open = !sidebar.classList.contains("open");
      sidebar.classList.toggle("open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) {
        var first = sidebar.querySelector("a");
        if (first) first.focus();
      }
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && sidebar.classList.contains("open")) { closeNav(); toggle.focus(); }
    });
    document.addEventListener("click", function (e) {
      if (sidebar.classList.contains("open") && !sidebar.contains(e.target) && e.target !== toggle && !toggle.contains(e.target)) closeNav();
    });
  }

  // Dialogs: <button data-open="id"> opens <dialog id>. Esc closes natively.
  document.querySelectorAll("[data-open]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var d = document.getElementById(btn.getAttribute("data-open"));
      if (d && typeof d.showModal === "function") d.showModal();
    });
  });
  document.querySelectorAll("[data-close]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var d = btn.closest("dialog");
      if (d) d.close();
    });
  });

  // Busy state for long-running form posts (import validation/commit).
  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var b = form.querySelector("button[type=submit]");
      if (b) { b.setAttribute("aria-busy", "true"); b.disabled = true; b.textContent = form.getAttribute("data-busy"); }
      var region = document.getElementById("form-status");
      if (region) region.textContent = form.getAttribute("data-busy");
    });
  });

  // Auto-submit filter selects (forms also have a visible Apply button).
  document.querySelectorAll("select[data-autosubmit]").forEach(function (sel) {
    sel.addEventListener("change", function () { sel.form && sel.form.submit(); });
  });

  // Copy-to-clipboard for long identifiers.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(function () {
        var old = btn.textContent; btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = old; }, 1200);
      });
    });
  });
})();
