"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  let csrf = "";
  let history = [];
  let controller = null;

  function api(path, options = {}) {
    const headers = Object.assign({ "X-OllamaGate-CSRF": csrf }, options.headers || {});
    return fetch(path, Object.assign({}, options, { headers, credentials: "same-origin", cache: "no-store" }));
  }

  // Change the log, then keep it scrolled to the end only if it already was:
  // someone reading further up shouldn't be yanked down by every token.
  function follow(change) {
    const log = $("log");
    const atEnd = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    change();
    if (atEnd) log.scrollTop = log.scrollHeight;
  }

  function bubble(role, text) {
    const div = document.createElement("div");
    div.className = "msg " + role;
    div.textContent = text; // never innerHTML: model output is untrusted
    follow(() => $("log").appendChild(div));
    return div;
  }

  function status(text) {
    $("status").textContent = text || "";
    $("status").hidden = !text;
  }

  async function explain(res) {
    let msg = "";
    try { msg = (await res.json()).error || ""; } catch (e) { /* not JSON */ }
    if (res.status === 401) return "This browser is no longer signed in. Pair it again.";
    if (res.status === 429) return "Limit reached: " + (msg || "try again later") + ".";
    if (res.status === 403) return msg || "Not allowed.";
    return msg || ("Error " + res.status);
  }

  async function start() {
    const res = await fetch("/app/session", { credentials: "same-origin", cache: "no-store" });
    if (!res.ok) { status("Not signed in. Pair this browser first."); $("composer").hidden = true; return; }
    csrf = (await res.json()).csrf;
    const tags = await api("/api/tags");
    if (!tags.ok) { status(await explain(tags)); return; }
    const models = ((await tags.json()).models || []).map((m) => m.name).filter(Boolean);
    const select = $("model");
    for (const name of models) {
      const opt = document.createElement("option");
      opt.value = opt.textContent = name;
      select.appendChild(opt);
    }
    try { const saved = localStorage.getItem("og-model"); if (models.includes(saved)) select.value = saved; } catch (e) { /* storage off */ }
    if (!models.length) status("No models available to this device.");
  }

  async function send(text) {
    history.push({ role: "user", content: text });
    bubble("user", text);
    const out = bubble("assistant", "");
    $("send").hidden = true; $("stop").hidden = false; status("");
    // Screen readers: announce the finished answer, not every streamed token.
    $("log").setAttribute("aria-busy", "true");
    controller = new AbortController();
    let answer = "";
    const handle = (line) => {
      line = line.trim();
      if (!line) return;
      let msg;
      try { msg = JSON.parse(line); } catch (e) { return; }
      if (msg.error) { bubble("error", String(msg.error)); return; }
      if (msg.message && typeof msg.message.content === "string") {
        answer += msg.message.content;
        follow(() => { out.textContent = answer; });
      }
    };
    try {
      const res = await api("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: $("model").value, messages: history, stream: true }),
        signal: controller.signal,
      });
      if (!res.ok) { out.remove(); bubble("error", await explain(res)); return; }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          handle(buf.slice(0, nl));
          buf = buf.slice(nl + 1);
        }
      }
      handle(buf + decoder.decode()); // a last line without a trailing newline
    } catch (e) {
      if (e.name !== "AbortError") bubble("error", "Connection lost.");
    } finally {
      controller = null;
      $("log").removeAttribute("aria-busy");
      $("send").hidden = false; $("stop").hidden = true;
      if (answer) {
        history.push({ role: "assistant", content: answer });
      } else {
        // No answer (error, stop, lost connection): forget the question too, so the
        // next message doesn't send two user turns in a row.
        history.pop();
        if (out.isConnected && !out.textContent) out.remove();
      }
    }
  }

  $("composer").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const text = $("prompt").value.trim();
    if (!text || controller) return;
    $("prompt").value = "";
    send(text);
  });
  $("prompt").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); $("composer").requestSubmit(); }
  });
  $("stop").addEventListener("click", () => controller && controller.abort());
  $("new").addEventListener("click", () => { if (!controller) { history = []; $("log").textContent = ""; } });
  $("model").addEventListener("change", () => { try { localStorage.setItem("og-model", $("model").value); } catch (e) { /* ignore */ } });
  $("logout").addEventListener("click", async () => {
    try { await api("/app/logout", { method: "POST" }); } catch (e) { return status("Can't reach the server to sign out."); }
    location.replace("/app");
  });
  // Heartbeat while the tab is visible, so the owner sees this device as online
  // only while the page is actually open.
  setInterval(() => {
    if (csrf && document.visibilityState === "visible") api("/app/session").catch(() => {});
  }, 30000);
  start().catch(() => status("Can't reach the server. Check the connection and reload."));
})();
