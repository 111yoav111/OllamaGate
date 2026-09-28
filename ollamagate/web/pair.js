"use strict";
(function () {
  const $ = (id) => document.getElementById(id);

  // The secret travels in the URL fragment so it never reaches any server log.
  const params = new URLSearchParams(window.location.hash.slice(1));
  const linkSecret = params.get("t");
  if (window.location.hash) {
    // Remove the secret from the address bar and history.
    history.replaceState(null, "", window.location.pathname);
  }
  if (linkSecret) {
    $("code-row").hidden = true;
    $("link-note").hidden = false;
  }
  $("name").value = guessDeviceName(navigator.userAgent);

  function guessDeviceName(ua) {
    const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android"
      : /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : "";
    const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome"
      : /Safari\//.test(ua) ? "Safari" : "";
    return [os, browser].filter(Boolean).join(" ") || "";
  }

  function showError(msg) {
    $("error").textContent = msg;
    $("error").hidden = false;
  }

  $("pair-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("error").hidden = true;
    const body = { device_name: $("name").value };
    if (linkSecret) body.secret = linkSecret;
    else body.code = $("code").value;
    $("submit").disabled = true;
    let res;
    try {
      res = await fetch("/pair/claim", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        credentials: "same-origin",
        cache: "no-store",
      });
    } catch (e) {
      $("submit").disabled = false;
      return showError("Network error. Try again.");
    }
    let data = {};
    try { data = await res.json(); } catch (e) { /* ignore */ }
    if (!res.ok) {
      $("submit").disabled = false;
      if (res.status === 404) return showError("No pairing window is open. Ask the owner to open one.");
      if (res.status === 429) return showError("Too many attempts. Wait a minute and try again.");
      if (res.status === 403 && linkSecret) {
        return showError("This pairing link is no longer valid. Ask the owner for a new one.");
      }
      if (res.status === 403) {
        return showError("Wrong code (" + (data.attempts_left ?? 0) + " attempts left).");
      }
      return showError(data.error || "Pairing failed.");
    }
    $("pair-form").hidden = true;
    $("done").hidden = false;
    $("token").value = data.token;
    $("base-url").textContent = data.base_url;
    $("api-url").textContent = data.base_url + "/api";
    $("v1-url").textContent = data.base_url + "/v1";
    $("fp").textContent = data.fingerprint || "(not using a self-signed certificate)";
    const cert = data.client_cert;
    if (cert) {
      // Built in the page from the one-time response; nothing is fetched again.
      $("cert-p12").href = "data:application/x-pkcs12;base64," + cert.p12;
      $("cert-pem").href = "data:application/x-pem-file;charset=utf-8," + encodeURIComponent(cert.cert_pem);
      $("cert-key").href = "data:application/x-pem-file;charset=utf-8," + encodeURIComponent(cert.key_pem);
      $("cert-pass").textContent = cert.p12_password;
      $("cert").hidden = false;
      // The chat in this browser needs the certificate installed first.
      $("open-chat").textContent = "Install the certificate, then open chat in this browser →";
    }
  });

  $("copy").addEventListener("click", async () => {
    const t = $("token");
    try {
      await navigator.clipboard.writeText(t.value);
    } catch (e) {
      t.select();
      document.execCommand("copy");
    }
    $("copy").textContent = "Copied";
  });
})();
