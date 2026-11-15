# Verify First, Trust Nothing: Building a Proof Gatekeeper for the zkVerify Agent Games

*by Brooklyn Faruk (xbit89) — Creator Track submission, Agent Games 2026*

## The brief

Agent Games (by zkVerify / Horizen Labs) pits self-hosted AI agents against each other in on-chain games. In **Proof Gatekeeper**, the platform sends your agent signed task envelopes describing a shielded transfer guarded by a zero-knowledge proof. Your agent must decide — approve or reject — and return a signed answer within 60 seconds. Approve a trap and you lose twice what a correct approval earns. The scoring punishes blind trust, so I built an agent whose first principle is: **verify first, trust nothing, fail closed.**

## The protocol, honestly

Every request arrives with an HMAC-SHA256 signature over the *raw* body. Verify before you parse — a JSON parser should never touch an unauthenticated byte. Every response is signed the same way. Before an agent may compete, the platform runs a signed **preflight** handshake; a placeholder secret fails by design.

The Gatekeeper circuit is Groth16 over BN128, with its verification key registered on zkVerify mainnet (vk hash `0x6b79…7b0`). A serious gatekeeper pins that hash and checks every task against it.

## The decision engine

The policy layer is a deterministic checklist, ordered so the most dangerous failures die first:

1. **VK substitution** — the proof's verification key is not the registered one → reject.
2. **Recipient mismatch** — the transfer's recipient differs from the conditioned recipient → reject.
3. **Amount rules** — non-positive, or above the per-task maximum → reject.
4. **Balance rules** — public balance below the required minimum, or below the amount → reject.
5. **Expiry** — the proof's expiry block has passed → reject.
6. **Replay** — a proof transaction that has been seen before → reject, forever. The seen-set is persisted, not kept in memory.

Anything malformed is rejected as malformed. There is no "probably fine" branch.

Locally, the build passes 12/12 checks: the preflight handshake, bad-signature rejection, a clean approval, replay rejection, and every trap above.

## The part nobody tweets about: hosting

The agent is useless without a public HTTPS endpoint, and getting one was the real boss fight. Quick tunnels from my sandbox were blocked by the egress proxy. The first-choice platform had quietly closed new signups. The second choice demanded a credit card before it would deploy a free instance. The agent finally went live as a **serverless function on a free tier** — with one memorable detour: the obvious project name was already taken by another participant, and the first deploy crashed because the platform's preset mistook my local dev server for the app entrypoint. Renaming one file fixed it. The platform's own signed preflight passed on the first save, and the agent flipped from UNHEALTHY to **ACTIVE**.

## What's next

Iteration two is wiring full Groth16 proof generation for the tasks that are provable — the circuit's witness layout is undocumented, so that work starts from the practice rounds' real feedback rather than guesses. The decision layer, the signatures, and the replay guard are already where they need to be.

Everything is public: **github.com/xbit89/agent-games-gatekeeper** — code, tests, and build notes. The tournament ends November 21. Verify first.
