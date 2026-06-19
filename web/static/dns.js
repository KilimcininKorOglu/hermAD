// Local DNS add/edit modal. The modal shows record-type-specific fields and
// composes them into the single `value` string the server expects (e.g. MX ->
// "10 mail.home.lab"). The subfield inputs have no `name`, so only domain, type
// and the composed value (injected on htmx:configRequest) are submitted.
(function () {
  "use strict";
  var modal = document.getElementById("dns-modal");
  if (!modal) return;
  var form = document.getElementById("dns-modal-form");
  var elDomain = document.getElementById("dns-domain");
  var elType = document.getElementById("dns-type");
  var title = document.getElementById("dns-modal-title");
  var oldDomain = form.querySelector('[name="old_domain"]');
  var oldType = form.querySelector('[name="old_type"]');
  var oldValue = form.querySelector('[name="old_value"]');
  var groups = form.querySelectorAll(".dns-fg");

  function inp(k) {
    return form.querySelector('[data-k="' + k + '"]');
  }
  function get(k) {
    var e = inp(k);
    return e ? e.value.trim() : "";
  }
  function set(k, v) {
    var e = inp(k);
    if (e) e.value = v || "";
  }

  // Show only the field group for the selected type.
  function showFields() {
    var t = elType.value;
    groups.forEach(function (g) {
      g.hidden = g.getAttribute("data-type") !== t;
    });
  }

  // Build the AdGuard $dnsrewrite value from the visible fields.
  function compose() {
    switch (elType.value) {
      case "A": return get("a");
      case "AAAA": return get("aaaa");
      case "CNAME": return get("cname");
      case "PTR": return get("ptr");
      case "TXT": return get("txt");
      case "MX": return [get("mx-pref"), get("mx-host")].filter(Boolean).join(" ");
      case "SRV": return [get("srv-prio"), get("srv-weight"), get("srv-port"), get("srv-target")].filter(Boolean).join(" ");
    }
    return "";
  }

  // Parse an existing value back into the per-type fields for editing.
  function fill(t, value) {
    ["a", "aaaa", "cname", "ptr", "txt", "mx-pref", "mx-host", "srv-prio", "srv-weight", "srv-port", "srv-target"].forEach(function (k) {
      set(k, "");
    });
    var p = (value || "").trim().split(/\s+/);
    switch (t) {
      case "A": set("a", value); break;
      case "AAAA": set("aaaa", value); break;
      case "CNAME": set("cname", value); break;
      case "PTR": set("ptr", value); break;
      case "TXT": set("txt", value); break;
      case "MX": set("mx-pref", p[0]); set("mx-host", p.slice(1).join(" ")); break;
      case "SRV": set("srv-prio", p[0]); set("srv-weight", p[1]); set("srv-port", p[2]); set("srv-target", p.slice(3).join(" ")); break;
    }
  }

  function openModal() { modal.hidden = false; }
  function closeModal() { modal.hidden = true; }
  window.dnsCloseModal = closeModal;

  window.dnsAdd = function () {
    title.textContent = title.getAttribute("data-add");
    oldDomain.value = ""; oldType.value = ""; oldValue.value = "";
    elDomain.value = "";
    elType.value = "A";
    fill("A", "");
    showFields();
    openModal();
    elDomain.focus();
  };

  window.dnsEdit = function (btn) {
    var d = btn.getAttribute("data-domain");
    var t = btn.getAttribute("data-type");
    var v = btn.getAttribute("data-value");
    title.textContent = title.getAttribute("data-edit");
    oldDomain.value = d; oldType.value = t; oldValue.value = v;
    elDomain.value = d;
    elType.value = t;
    fill(t, v);
    showFields();
    openModal();
  };

  elType.addEventListener("change", showFields);

  // Inject the composed value into the request just before HTMX sends it.
  form.addEventListener("htmx:configRequest", function (e) {
    e.detail.parameters["value"] = compose();
  });

  // Close the modal only when the save actually succeeded (error toasts keep it
  // open so the user can correct the input).
  form.addEventListener("htmx:afterRequest", function (e) {
    if (e.detail.successful && e.detail.xhr && e.detail.xhr.responseText.indexOf("alert err") === -1) {
      closeModal();
    }
  });

  modal.addEventListener("click", function (e) {
    if (e.target === modal) closeModal();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !modal.hidden) closeModal();
  });
})();
