"use strict";
(function () {
  const $ = (id) => document.getElementById(id);

  // The secret travels in the URL fragment so it never reaches any server log.
  const params = new URLSearchParams(window.location.hash.slice(1));
  const linkSecret = params.get("t");
  const expectedFp = params.get("fp");
  if (window.location.hash) {
    // Remove the secret from the address bar and history.
    history.replaceState(null, "", window.location.pathname);
  }
  if (linkSecret) {
    $("code-row").hidden = true;
    $("link-note").hidden = false;
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
      return showError(data.error || "Pairing failed.");
    }
    $("pair-form").hidden = true;
    $("done").hidden = false;
    $("token").value = data.token;
    $("base-url").textContent = data.base_url;
    $("api-url").textContent = data.base_url + "/api";
    $("v1-url").textContent = data.base_url + "/v1";
    $("fp").textContent = data.fingerprint || "(not using a self-signed certificate)";
    if (expectedFp && data.fingerprint && expectedFp.toLowerCase() !== data.fingerprint.toLowerCase()) {
      $("fp-warn").hidden = false;
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
