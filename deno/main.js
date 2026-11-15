// xbit89-gatekeeper — Proof Gatekeeper agent, Deno Deploy edition.
// Same protocol and policy as ../server.js (Node), adapted to Deno.serve +
// WebCrypto. The HMAC secret comes from the AGENT_GAMES_HMAC_SECRET env var.
// Note: the proof-replay set is in-memory on this edition (per-isolate);
// the decision policy itself is identical and fail-closed.

const SECRET = Deno.env.get("AGENT_GAMES_HMAC_SECRET") || "";
const seenProofTx = new Set();

const enc = new TextEncoder();
let keyPromise = null;
function hmacKey() {
  if (!keyPromise) {
    keyPromise = crypto.subtle.importKey(
      "raw", enc.encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false,
      ["sign", "verify"],
    );
  }
  return keyPromise;
}
async function hmacHex(data) {
  const key = await hmacKey();
  const sig = await crypto.subtle.sign("HMAC", key, typeof data === "string" ? enc.encode(data) : data);
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function timingSafeEqHex(a, b) {
  if (typeof a !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function sigMatches(headerVal, rawBytes) {
  if (!headerVal) return false;
  const expected = await hmacHex(rawBytes);
  const given = headerVal.trim().replace(/^sha256=/i, "");
  return timingSafeEqHex(given, expected);
}

const eqAddr = (a, b) =>
  typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
const asBig = (v) => { try { return BigInt(v); } catch { return null; } };

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

async function signedJson(status, obj) {
  const body = JSON.stringify(obj);
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": await hmacHex(body),
    },
  });
}

Deno.serve(async (req) => {
  const url = new URL(req.url);
  if (req.method === "GET" && url.pathname === "/health") {
    return Response.json({ ok: true });
  }
  if (req.method !== "POST" || url.pathname !== "/agent") {
    return signedJson(404, { ok: false, error: "not_found" });
  }
  if (!SECRET) return signedJson(500, { ok: false, error: "secret_not_configured" });

  const raw = new Uint8Array(await req.arrayBuffer());
  if (!(await sigMatches(req.headers.get("x-agent-games-signature"), raw))) {
    return signedJson(401, { ok: false, error: "bad_signature" });
  }
  let msg;
  try { msg = JSON.parse(new TextDecoder().decode(raw)); }
  catch { return signedJson(400, { ok: false, error: "bad_json" }); }

  if (msg.type === "agent-games.preflight.v1") {
    return signedJson(200, { ok: true, protocolVersion: "v1" });
  }
  if (msg.type === "agent-games.proof-gatekeeper.v1") {
    const verdict = decideGatekeeper(msg.input);
    if (verdict.decision === "APPROVE" && msg.input?.proof_tx) seenProofTx.add(msg.input.proof_tx);
    return signedJson(200, {
      decision: verdict.decision,
      reason_code: verdict.reason_code,
      proof_tx: msg.input?.proof_tx ?? null,
    });
  }
  return signedJson(400, { ok: false, error: "unsupported_type" });
});
