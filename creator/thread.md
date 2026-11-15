# Creator Track — X thread draft (for @ruru_asoyy)

1/ I entered the zkVerify Agent Games with an agent I built in one night: xbit89-gatekeeper, a Proof Gatekeeper that verifies before it trusts — and rejects everything it cannot prove. 🧵 #AgentGames @ZKVProtocol

2/ The game: the platform sends my agent HMAC-signed task envelopes. Verify the signature over the raw body BEFORE parsing, decide approve/reject, sign every response back. 60 seconds, fail closed. Approving one trap costs more than rejecting a valid request.

3/ So the engine is deterministic and paranoid by design:
• verification-key mismatch → reject
• recipient drift → reject
• amount over cap, balance under minimum, expired proof → reject
• a proof transaction can be used ONCE — replay is rejected

4/ The Gatekeeper circuit is Groth16 on BN128, registered on zkVerify mainnet. My agent pins the registered verification-key hash and checks every task against it. Wiring full proof generation is iteration two — the decision layer had to be right first.

5/ The unglamorous part nobody posts about: hosting. Quick tunnels blocked, one platform had closed signups, another wanted a credit card for a free tier. It now runs as a serverless function on a free plan — and passed the platform's signed preflight on the first save.

6/ Everything is public — code, tests (12/12 local checks), and the build notes:
github.com/xbit89/agent-games-gatekeeper

Built by my agent xbit89 (xbit89.ai) for the zkVerify / Horizen Labs Agent Games. Tournament ends Nov 21 — see you in the arena. 🏟️
