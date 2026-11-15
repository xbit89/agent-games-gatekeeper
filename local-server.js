"use strict";
/*
 * Agent Games — Proof Gatekeeper agent endpoint (v1 plumbing)
 * Spec source: https://agentgames.zkverify.io/build (read 2026-11-15)
 *
 * - POST /agent accepts signed task envelopes (HMAC-SHA256 over the RAW body,
 *   header: x-agent-games-signature).
 * - Preflight  {type:"agent-games.preflight.v1"}        -> {ok:true, protocolVersion:"v1"}
 * - Gatekeeper {type:"agent-games.proof-gatekeeper.v1"} -> {decision, reason_code, proof_tx}
 * - EVERY response is signed with x-agent-games-signature over the raw response body.
 * - Decision rules are deterministic and fail closed (any doubt -> REJECT).
 * - Secrets come from env only: AGENT_GAMES_HMAC_SECRET. Never logged.
 *
 * Iteration note: local Groth16 proof generation (snarkjs + gatekeeper circuit)
 * is NOT wired in v1 — the circuit's input signal names are fnv-hashed inside
 * the wasm and are not published in the guide; the response therefore carries
 * the decision + proof_tx reference only. See README.md.
 */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
if (!SECRET) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start (a placeholder secret fails preflight by design).");
  process.exit(1);
}
const PORT = parseInt(process.env.PORT || "8791", 10);
const SEEN_FILE = path.join(__dirname, "seen-proof-tx.json");

function hmacHex(data) {
  return crypto.createHmac("sha256", SECRET).update(data).digest("hex");
}
function sigMatches(headerVal, rawBody) {
  if (!headerVal || typeof headerVal !== "string") return false;
  const expected = hmacHex(rawBody);
  const candidates = [headerVal.trim(), headerVal.trim().replace(/^sha256=/i, "")];
  return candidates.some((c) => {
    if (c.length !== expected.length) return false;
    try { return crypto.timingSafeEqual(Buffer.from(c, "utf8"), Buffer.from(expected, "utf8")); }
    catch { return false; }
  });
}
function loadSeen() {
  try { return new Set(JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"))); } catch { return new Set(); }
}
function saveSeen(set) {
  try { fs.writeFileSync(SEEN_FILE, JSON.stringify([...set].slice(-5000))); } catch { /* non-fatal */ }
}
const seenProofTx = loadSeen();

function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(body),
  });
  res.end(body);
}

const eqAddr = (a, b) =>
  typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
const asBig = (v) => { try { return BigInt(v); } catch { return null; } };

/* Deterministic Gatekeeper policy — mirrors the /build Security checklist.
 * Returns {decision, reason_code}. Fail closed: any anomaly -> REJECT. */
function decideGatekeeper(input) {
  if (!input || typeof input !== "object") return { decision: "REJECT", reason_code: "MALFORMED_INPUT" };
  const {
    registered_vk, proof_vk, minimum, public_balance,
    expiry_block, current_block, recipient, condition_recipient,
    amount, max_transfer, proof_tx,
  } = input;

  if (!proof_vk || !registered_vk || proof_vk !== registered_vk)
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  if (!recipient || !condition_recipient || !eqAddr(recipient, condition_recipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };

  const amt = asBig(amount), maxT = asBig(max_transfer), bal = asBig(public_balance), min = asBig(minimum);
  if (amt === null || maxT === null || bal === null || min === null)
    return { decision: "REJECT", reason_code: "MALFORMED_INPUT" };
  if (amt <= 0n) return { decision: "REJECT", reason_code: "INVALID_AMOUNT" };
  if (amt > maxT) return { decision: "REJECT", reason_code: "AMOUNT_EXCEEDS_MAX" };
  if (bal < min) return { decision: "REJECT", reason_code: "BELOW_MINIMUM_BALANCE" };
  if (bal < amt) return { decision: "REJECT", reason_code: "INSUFFICIENT_BALANCE" };

  const exp = asBig(expiry_block), cur = asBig(current_block);
  if (exp === null || cur === null) return { decision: "REJECT", reason_code: "MALFORMED_INPUT" };
  if (cur > exp) return { decision: "REJECT", reason_code: "PROOF_EXPIRED" };

  if (!proof_tx || typeof proof_tx !== "string")
    return { decision: "REJECT", reason_code: "MISSING_PROOF_TX" };
  if (seenProofTx.has(proof_tx))
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };

  return { decision: "APPROVE", reason_code: "OK" };
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  if (req.method !== "POST" || !req.url.startsWith("/agent")) {
    sendSigned(res, 404, { ok: false, error: "not_found" });
    return;
  }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const raw = Buffer.concat(chunks);
    // 1) Verify HMAC over the RAW body BEFORE parsing (spec requirement).
    if (!sigMatches(req.headers["x-agent-games-signature"], raw)) {
      sendSigned(res, 401, { ok: false, error: "bad_signature" });
      return;
    }
    let msg;
    try { msg = JSON.parse(raw.toString("utf8")); }
    catch { sendSigned(res, 400, { ok: false, error: "bad_json" }); return; }

    // 2) Route by envelope type.
    if (msg.type === "agent-games.preflight.v1") {
      sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      return;
    }
    if (msg.type === "agent-games.proof-gatekeeper.v1") {
      const verdict = decideGatekeeper(msg.input);
      if (verdict.decision === "APPROVE" && msg.input && msg.input.proof_tx) {
        seenProofTx.add(msg.input.proof_tx);
        saveSeen(seenProofTx);
      }
      sendSigned(res, 200, {
        decision: verdict.decision,
        reason_code: verdict.reason_code,
        proof_tx: msg.input && msg.input.proof_tx ? msg.input.proof_tx : null,
      });
      return;
    }
    sendSigned(res, 400, { ok: false, error: "unsupported_type" });
  });
  req.on("error", () => { try { sendSigned(res, 500, { ok: false, error: "read_error" }); } catch { /* closed */ } });
});

server.listen(PORT, () => console.log(`agent-games gatekeeper agent listening on :${PORT} (POST /agent)`));
