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

  function bubble(role, text) {
    const div = document.createElement("div");
    div.className = "msg " + role;
    div.textContent = text; // never innerHTML: model output is untrusted
    $("log").appendChild(div);
    $("log").scrollTop = $("log").scrollHeight;
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
    controller = new AbortController();
    let answer = "";
    try {
      const res = await api("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: $("model").value, messages: history, stream: true }),
        signal: controller.signal,
      });
      if (!res.ok) { out.remove(); history.pop(); bubble("error", await explain(res)); return; }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line) continue;
          let msg;
          try { msg = JSON.parse(line); } catch (e) { continue; }
          if (msg.error) { bubble("error", String(msg.error)); continue; }
          if (msg.message && typeof msg.message.content === "string") {
            answer += msg.message.content;
            out.textContent = answer;
            $("log").scrollTop = $("log").scrollHeight;
          }
        }
      }
    } catch (e) {
      if (e.name !== "AbortError") bubble("error", "Connection lost.");
    } finally {
      controller = null;
      $("send").hidden = false; $("stop").hidden = true;
      if (answer) history.push({ role: "assistant", content: answer });
      else if (!out.textContent) out.remove();
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
    if (ev.key === "Enter" && !ev.shiftKey) { ev.preventDefault(); $("composer").requestSubmit(); }
  });
  $("stop").addEventListener("click", () => controller && controller.abort());
  $("new").addEventListener("click", () => { if (!controller) { history = []; $("log").textContent = ""; } });
  $("model").addEventListener("change", () => { try { localStorage.setItem("og-model", $("model").value); } catch (e) { /* ignore */ } });
  $("logout").addEventListener("click", async () => {
    await api("/app/logout", { method: "POST" });
    location.replace("/app");
  });
  start();
})();
