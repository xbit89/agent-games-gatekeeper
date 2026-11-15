# xbit89-gatekeeper

An AI-agent endpoint for **Proof Gatekeeper**, an event in the
[Agent Games](https://agentgames.zkverify.io) tournament powered by zkVerify.

The platform POSTs signed payment-approval tasks to this agent. For each task
the agent verifies the request, checks the attached zero-knowledge proof's
claims against the task's rules, and returns a signed APPROVE / REJECT
decision. A valid proof is necessary but not sufficient — the agent confirms
*what* was proven, not only *whether* verification succeeded.

## How it works

1. **Transport** — `POST /agent` reads the raw request body and verifies the
   `x-agent-games-signature` HMAC-SHA256 header *before* parsing any JSON.
   Mismatched signatures are rejected with 401.
2. **Preflight** — `agent-games.preflight.v1` envelopes are answered with
   `{ ok: true, protocolVersion: "v1" }`, signed like every response.
3. **Policy** — Gatekeeper envelopes (`agent-games.proof-gatekeeper.v1`) go
   through a deterministic, fail-closed checklist:
   - the proof's verification key matches the registered key
     (otherwise `VK_SUBSTITUTION`),
   - the recipient matches the condition recipient,
   - amount is positive and within `max_transfer`,
   - the public balance meets the required minimum and covers the amount,
   - the proof has not expired (`current_block <= expiry_block`),
   - the proof reference (`proof_tx`) has never been used before
     (replay protection, persisted on disk).
   Any doubt, malformed field, or error results in REJECT — never a
   default approval.
4. **Response** — `{ decision, reason_code, proof_tx }` as JSON, signed with
   `x-agent-games-signature` over the raw response body.

## Running it

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<secret from the Agent Games dashboard> \
  node local-server.js          # listens on PORT (default 8791), POST /agent
```

The HMAC secret is issued by the platform (dashboard → your agent →
Rotate Secret) and is read from the environment only — never commit it.
See `.env.example`.

## Tests

```bash
node test.js
```

Spins the server up with a throwaway test secret and replays sample
envelopes: preflight, a valid approval, and the trap cases (VK substitution,
expiry, recipient mismatch, amount above max, balance below minimum,
insufficient balance, proof replay). 12 checks, all passing.

## Circuit artifacts

The event's Groth16 circuit (`gatekeeper.wasm`, `gatekeeper_final.zkey`,
vk_hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`)
is published by the organizers at
<https://agentgames.zkverify.io/circuits/> and is not redistributed here.

## Status

v1 — transport, authentication, and the decision engine are complete and
locally verified. Local Groth16 proof generation with snarkjs is the next
iteration.

Built by Brooklyn Faruk's agent (xbit89) for the Agent Games Creator Track.
