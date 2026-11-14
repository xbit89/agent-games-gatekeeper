"use strict";
/* Local test harness: spawns server.js with a test secret, replays sample
 * envelopes (preflight + Gatekeeper valid/trap cases), verifies response
 * signatures and decisions. Run: node test.js */
const { spawn } = require("child_process");
const crypto = require("crypto");

const SECRET = "test-secret-for-local-harness-only";
const PORT = 8799;
const BASE = `http://127.0.0.1:${PORT}`;
const sign = (raw) => crypto.createHmac("sha256", SECRET).update(raw).digest("hex");

let pass = 0, fail = 0;
function check(name, cond, extra = "") {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
}

async function post(obj, { badSig = false } = {}) {
  const raw = JSON.stringify(obj);
  const r = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": badSig ? "deadbeef" : sign(raw) },
    body: raw,
  });
  const text = await r.text();
  const sigOk = r.headers.get("x-agent-games-signature") === sign(text);
  let body = null; try { body = JSON.parse(text); } catch { /* keep null */ }
  return { status: r.status, body, sigOk };
}

const VALID = {
  registered_vk: "0x7d91", proof_vk: "0x7d91",
  minimum: "1000", public_balance: "1460",
  expiry_block: 8430000, current_block: 8420000,
  recipient: "0xDe429f01", condition_recipient: "0xDe429f01",
  amount: "500", max_transfer: "1000", proof_tx: "0xa82c0001",
};
const task = (input, id) => ({
  type: "agent-games.proof-gatekeeper.v1", task_id: id || "gk_test_1",
  mode: "practice", issued_at: new Date().toISOString(),
  deadline_at: new Date(Date.now() + 60000).toISOString(), input,
});

(async () => {
  const srv = spawn("node", ["server.js"], {
    env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT) },
    stdio: "ignore",
  });
  try {
    for (let i = 0; i < 40; i++) {
      try { const h = await fetch(`${BASE}/health`); if (h.ok) break; } catch { /* retry */ }
      await new Promise((r) => setTimeout(r, 250));
    }
    console.log("== preflight ==");
    let r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
    check("preflight 200 + ok:true + v1", r.status === 200 && r.body && r.body.ok === true && r.body.protocolVersion === "v1", JSON.stringify(r.body));
    check("preflight response signed", r.sigOk);
    r = await post({ type: "agent-games.preflight.v1", nonce: "x" }, { badSig: true });
    check("bad signature -> 401", r.status === 401, `got ${r.status}`);

    console.log("== gatekeeper decisions ==");
    r = await post(task(VALID));
    check("valid request -> APPROVE", r.body && r.body.decision === "APPROVE", JSON.stringify(r.body));
    check("decision response signed", r.sigOk);
    r = await post(task(VALID, "gk_test_2"));
    check("same proof_tx again -> REJECT PROOF_REUSED", r.body && r.body.decision === "REJECT" && r.body.reason_code === "PROOF_REUSED", JSON.stringify(r.body));
    r = await post(task({ ...VALID, proof_tx: "0xa82c0002", proof_vk: "0x13aa" }));
    check("vk substitution -> REJECT VK_SUBSTITUTION", r.body && r.body.reason_code === "VK_SUBSTITUTION", JSON.stringify(r.body));
    r = await post(task({ ...VALID, proof_tx: "0xa82c0003", current_block: 8440000 }));
    check("expired -> REJECT PROOF_EXPIRED", r.body && r.body.reason_code === "PROOF_EXPIRED", JSON.stringify(r.body));
    r = await post(task({ ...VALID, proof_tx: "0xa82c0004", condition_recipient: "0xBEEF" }));
    check("recipient mismatch -> REJECT", r.body && r.body.reason_code === "RECIPIENT_MISMATCH", JSON.stringify(r.body));
    r = await post(task({ ...VALID, proof_tx: "0xa82c0005", amount: "5000" }));
    check("amount > max -> REJECT", r.body && r.body.reason_code === "AMOUNT_EXCEEDS_MAX", JSON.stringify(r.body));
    r = await post(task({ ...VALID, proof_tx: "0xa82c0006", public_balance: "900" }));
    check("balance < minimum -> REJECT", r.body && r.body.reason_code === "BELOW_MINIMUM_BALANCE", JSON.stringify(r.body));
    r = await post(task({ ...VALID, proof_tx: "0xa82c0007", public_balance: "1200", amount: "1300", max_transfer: "2000" }));
    check("balance < amount -> REJECT", r.body && r.body.reason_code === "INSUFFICIENT_BALANCE", JSON.stringify(r.body));
  } catch (e) {
    console.error("harness error:", e.message); fail++;
  } finally {
    srv.kill();
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
