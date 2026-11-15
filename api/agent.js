// xbit89-gatekeeper — Proof Gatekeeper agent, Vercel serverless edition.
// Same protocol and policy as ../server.js. vercel.json rewrites /agent and
// /health to this function. Secret from env AGENT_GAMES_HMAC_SECRET.
// Note: the proof-replay set is in-memory per instance; the decision policy
// itself is identical and fail-closed.
const crypto = require("crypto");

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const seenProofTx = new Set();

const hmacHex = (data) => crypto.createHmac("sha256", SECRET).update(data).digest("hex");

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
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

module.exports = async (req, res) => {
  const send = (status, obj) => {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      "content-type": "application/json",
      "x-agent-games-signature": SECRET ? hmacHex(body) : "",
    });
    res.end(body);
  };

  if (req.method === "GET") return send(200, { ok: true });
  if (req.method !== "POST") return send(404, { ok: false, error: "not_found" });
  if (!SECRET) return send(500, { ok: false, error: "secret_not_configured" });

  const raw = await readRawBody(req);
  const given = (req.headers["x-agent-games-signature"] || "").trim().replace(/^sha256=/i, "");
  const expected = hmacHex(raw);
  const ok = given.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
  if (!ok) return send(401, { ok: false, error: "bad_signature" });

  let msg;
  try { msg = JSON.parse(raw.toString("utf8")); }
  catch { return send(400, { ok: false, error: "bad_json" }); }

  if (msg.type === "agent-games.preflight.v1") {
    return send(200, { ok: true, protocolVersion: "v1" });
  }
  if (msg.type === "agent-games.proof-gatekeeper.v1") {
    const verdict = decideGatekeeper(msg.input);
    if (verdict.decision === "APPROVE" && msg.input && msg.input.proof_tx) seenProofTx.add(msg.input.proof_tx);
    return send(200, {
      decision: verdict.decision,
      reason_code: verdict.reason_code,
      proof_tx: (msg.input && msg.input.proof_tx) || null,
    });
  }
  return send(400, { ok: false, error: "unsupported_type" });
};

module.exports.config = { api: { bodyParser: false } };
