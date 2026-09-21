# ClearSeal — Integrity & Authenticity Standard for LLM-Access Nodes (v0.8, public edition)

**Status:** Public edition of ClearSeal v0.8. Investigation-phase standard with one production adoption (a reference implementation on a non-root mobile platform). Deployment-specific material — node inventories, endpoint exposure, key custody locations, and owner-authorised exceptions — is deliberately omitted; each deployment keeps its own conformance record privately.
**Authors:** Scotty (ClearForge LLC) — owner: gate / approve / decide · Claude (Anthropic) — executor: audit / write / refactor
**Lineage (not dependencies):** Signed-Prompt · Prompt Fencing · Verifiable Manifest Signing for MCP · ETDI · RFC 9421 / Web Bot Auth
**License:** CC BY 4.0 — see `LICENSE`.

**One line:** *Sign → verify against a pinned reference → fail closed, at an off-box gate* — applied to every artifact that enters an LLM's context or crosses a node boundary, across a hub-and-spoke of LLM-access MCP servers, **on top of the protocol's own auth substrate rather than re-deriving it.**

> **Numbering note.** Section, decision, and adversarial-class numbers match the full v0.8 standard exactly. Where an item is deployment-specific it is marked *omitted* rather than removed and renumbered, so a citation such as "ClearSeal v0.8 §8 #11" resolves identically in either edition.

---

## Design history — what building against this standard taught it

The full standard carries a detailed changelog per version. The public edition keeps the lessons, which generalise; the incident detail does not.

- **v0.1 → v0.4.** Began as prompt integrity only; extended to MCP tool manifests; folded in 2025–26 research (ETDI, RFC 9421 / Web Bot Auth); corrected its own topology from a node mesh to hub-and-spoke.
- **v0.5 — don't re-derive what the protocol now mandates.** The MCP `2026-07-28` revision made OAuth 2.1, audience-bound tokens, protected-resource discovery and S256 PKCE mandatory. Earlier versions had specified these as ClearSeal inventions. v0.5 cites the spec as the baseline and requires conformance instead. ClearSeal's remaining job is exactly what the spec does *not* cover (§0).
- **v0.6 — a standard version is mutable until first adoption, immutable after.** Established when v0.6 was corrected while it still had zero adopters. The immutable unit is the commit, not the version label.
- **v0.7 — unpinned authority.** The same bug was fixed three times in one day before it was recognised as one bug: a security gate deciding on an input the integrity system did not cover (§8 #11). The lesson: a new invariant must be swept against *every* existing gate, not only the one that provoked it.
- **v0.8 — message provenance, and the feedback path is part of the standard.** Adds artifact class 5 (node-originated messages) and a tenth pinned field, `containment_domain`, which was invented at the reference implementation and reached the standard seven days late. A mechanism built at a reference node and not fed back upstream is a mechanism the next node re-invents — and the second invention is the one nobody audited.

---

## 0. Lane & ceiling + what the spec does *not* cover

ClearSeal authenticates *artifact, author, channel, freshness, capability*. **It never authenticates intent.** The gap between *provable* and *safe* is the width of `policy.scope`. ClearSeal makes actions provable; **capability scoping + egress/sink validation make them safe.** Signing without scoping is a well-authenticated way to get owned.

**ClearSeal is an integrity/authenticity control, not a prompt-injection defense. Believing it is one is its primary failure mode.**

**The MCP `2026-07-28` spec covers the auth substrate — and nothing above it.** The spec authenticates *who is calling and whether the token is for the right server*. It says nothing about whether the engineered prompt or the tool definition is the one you signed, nothing about caging what a tool may reach, nothing about outbound-inference integrity. So ClearSeal's un-duplicated job is:
- **Prompt-pinning** (artifact class 1) — no protocol equivalent.
- **Tool-definition pinning** (artifact class 2) — no protocol equivalent; the highest security-per-effort control here.
- **Egress / sink caging** on dangerous tools — no protocol equivalent.
- **Off-box policy gate** (`policy ⊆ grant`, Rule-of-Two) — no protocol equivalent.
- **Surface B / BYOK** outbound-inference integrity — not a protocol concern at all.

The spec took over the undifferentiated auth plumbing. **ClearSeal is the integrity + authorization-policy + caging layer sitting on a solid auth base — which is where its value always was.**

---

## B. Protocol baseline — MCP `2026-07-28`

ClearSeal **requires conformance** to the finalized spec on every public endpoint. It does not restate the spec; it depends on it. The load-bearing facts for this standard:

- **Auth is real and mandatory.** Servers MUST expose OAuth 2.0 Protected Resource Metadata (RFC 9728) at `/.well-known/oauth-protected-resource`; clients MUST send Resource Indicators (RFC 8707) so a token minted for Server A cannot be replayed at Server B; PKCE **S256 only**; issuer verification (RFC 9207) closes the mix-up / confused-deputy class — the attack a one-client-to-many-servers topology is most exposed to. Client ID Metadata Documents are preferred over Dynamic Client Registration.
- **Stateless core.** No session id, no `initialize` handshake; protocol version and capabilities travel in `_meta` per request; requests carry `Mcp-Method` / `Mcp-Name` headers so gateways route **without body inspection**.
- **Extensions framework** ships MCP Apps (UI actions traverse the same consent/audit path as tool calls) and a redesigned **Tasks** extension; **Multi-Round-Trip Requests** replace sampling/elicitation as the in-flight human-input primitive.
- **Deprecations** (12-month minimum window): Roots → Resource URIs; Sampling and Logging leave core.
- **Backward compatibility is real**, so adoption is a scheduled refactor, not a fire drill.
- **Governance.** MCP is stewarded under the Linux Foundation's Agentic AI Foundation with a formal deprecation policy — a stable baseline, which is why rebasing onto it beats hand-rolling.

**Probe, don't assume.** At the time of writing, ecosystem support lagged the spec: several framework wrappers could not yet serve `2026-07-28`, and at least one did not implement `server/discover` although the spec calls it mandatory. **A server MUST probe and record the protocol revision it actually serves**, and must not design around a capability until it is verified present in the chosen release.

**Edge SSO is not an authorization server.** An edge access gate that challenges with its own headers (a `403`, or a browser redirect) never engages a client's RFC 9728 discovery. Placing one in front of an MCP endpoint that a spec-conformant client must reach forces the credential somewhere worse — historically, into the URL (§8 #5). Keep edge SSO on non-MCP paths; put the OAuth resource-server posture on the MCP endpoint.

---

## 1. Topology → two surfaces

```
   ┌─ LLM CLIENTS (hub) ─┐    hosted clients · self-controlled agents
   │                     │
   ▼        ▼        ▼        ▼
 [node]  [node]   [node]   [node]      ← spokes: MCP servers = access points INTO each node
   │        │        │        │
   └────────┴───┬────┴────────┘
                ▼
          SHARED STATE (the real "mesh")
```

**Surface A — Inbound MCP access.** Protect each server from an unauthorized *or injected* driver. Controls: **conform to the MCP `2026-07-28` auth baseline** (OAuth 2.1 resource-server posture: 401 + RFC 9728 PRM, RFC 8707 audience binding, S256 PKCE) · tool-definition pinning · capability scoping (Rule-of-Two) · egress/sink validation on dangerous tools · sandboxing. A static bearer, and above all a credential carried in a URL, is legacy.

**Surface B — Outbound inference integrity.** Protect prompts leaving nodes that *originate* LLM calls. Controls: prompt-pin gate · BYOK (inference key off-node) · spend limits. *Nodes that make no LLM calls are exempt from Surface B.* Unaffected by the spec — outbound-inference integrity is not a protocol concern.

**Who can sign what — the honest constraint:**
- **Hosted clients** cannot hold your keys, so they cannot RFC-9421-sign tool calls. Their inbound access is OAuth-authenticated through the spec's native flow; the spec's per-request audience-bound tokens do the authenticity job for them.
- **Self-controlled clients** — agents you run, owning both ends — **can and should RFC-9421-sign.** A self-controlled agent is the natural first *full* ClearSeal client.

---

## 2. Artifact classes

| # | Artifact | Predicate | Applies to |
|---|---|---|---|
| 1 | Engineered prompt (stable) | Equality vs signed pin | Surface B nodes |
| 2 | **MCP tool definition/description** ⭐ | Equality vs approved pin; alert on drift | **Every MCP server** |
| 3 | Tool-call manifest (per-call) | Authenticity + freshness + policy⊆grant | Self-controlled clients only |
| 4 | Tool response (per-call) | Authenticity + freshness + shape | Self-controlled clients only |
| 5 | **Node-originated message** (per-message) | Authenticity + freshness + author-on-allowlist + capability-floor | Any node that speaks to the operator or another node |

Tool descriptions ARE prompts — injected verbatim into model context. Pinning them kills tool-poisoning and rug-pulls: **the highest security-per-effort control in the standard, and it works regardless of who the client is.** None of these classes is provided by the spec. Class 3's `policy⊆grant` *complements* RFC 8707 audience binding: the spec binds the token to the server; ClearSeal binds the *call* to the granted policy.

**Class 5 — node-originated message** is the outbound-to-operator mirror of class 3: the same authenticity + freshness discipline, plus an **author allowlist** (who may speak on this channel) and a **capability floor** (what a message may ask for, regardless of signature). It is the primitive under any signed node→operator channel — status alerts, health reports, breach alarms. The gap it closes has teeth: a `system`-voiced message with no way to authenticate its author is a **social-engineering primitive** — anything that can write to the delivery channel can forge a message that *looks like the infrastructure speaking* and steer the operator into a privileged action. TLS covers tampering in flight; nothing covered **origin**.

---

## 3. Controls

- **RFC 9421** for all client-side signing plumbing (Ed25519, `created`/`expires`/`nonce`, `keyid` = JWK thumbprint, `/.well-known/http-message-signatures-directory` for distribution and rotation). Never hand-roll the envelope; invent only the `policy` payload. *(Self-controlled clients only.)*
- **Inbound auth = conform to MCP `2026-07-28`, don't invent.** OAuth resource-server posture on every public endpoint: emit `401 + WWW-Authenticate` → `/.well-known/oauth-protected-resource` → a real authorization server (a hosted AS, an OAuth proxy over an existing IdP, or a self-hosted AS — decide per node). Audience-bound tokens, S256 PKCE, no token passthrough to upstream APIs. **The token rides the `Authorization` header, never the URL.**
- **Off-box gate** — an enforcement point off the node (e.g. an edge worker) holding the inference key (**BYOK**), so the gate is *enforced*, not advisory; mTLS node identity. The stateless spec lets the gate route and enforce per-tool policy on the `Mcp-Method` / `Mcp-Name` headers with no body inspection.
- **Tool-definition pinning** = hash at approval, re-verify on load, alert on drift.
- **Capability scoping = a four-rung danger ladder + orthogonal booleans.** Every tool carries a `capability_class` (`read_only` | `owned_state` | `state_change` | `arbitrary_exec`), an `untrusted_input_facing` boolean, and a narrow `scope`. The ladder and the boolean are **orthogonal axes** — any rung can be untrusted-input-facing.
  - **`owned_state`** — the tool mutates **only** data this server is the designated owner of, **and** produces no third-party, financial, physical-world, or host-configuration effect, **and** the mutation is recoverable (append-only, versioned, or trivially reconstructible). **All three clauses required.** A tool claiming this rung MUST pin a one-line `recoverability_basis` (e.g. `"append-only + supersession"`); if the basis cannot be stated in one line, the tool is not `owned_state`. The name is load-bearing: it forces the question *does this server own that state?* — which is why a tool that sends a message to a third party, or writes a device-wide clipboard, can never claim it.
  - **Rule-of-Two:** `untrusted_input_facing` AND (`state_change` | `arbitrary_exec`) ⇒ a human-in-loop obligation, discharged by an elevated human confirmation **or** by demonstrable containment. **`owned_state` auto-discharges Rule-of-Two** — containment is proven structurally by the three clauses rather than promised. This is what makes Rule-of-Two survivable: without it every owned write downstream of an untrusted read demands a confirmation, and the control gets switched off.
  - **THE PINNED TOOL OBJECT (canonical, hashed into the manifest).** `name`, `description`, `input_schema`, `capability_class`, `untrusted_input_facing`, `scope`, `privacy_sensitive`, `recoverability_basis` (null unless `owned_state`), `elevated`, and `containment_domain`. **Ten fields. This enumeration and the executable form (`canonicalFieldSet()`) MUST list the same set; if they diverge, the executable form is authoritative and this list is the bug.** `elevated` is pinned because the human-confirmation gate reads it: an allowlist held outside the manifest is authority the pinning system does not know exists (§8 #11). A gate must never decide on a property the manifest does not track — otherwise flipping that property escapes the gate without tripping pin drift.
  - **`containment_domain` — the portable form of "demonstrable containment."** Rule-of-Two offers two discharges: a human confirmation, or demonstrable containment, for which earlier versions named only *egress caging*. **On some platforms no cage holds** — measured on non-root mobile platforms with no packet filter and no per-process network namespace — and there the containment discharge silently does not exist, so every effect tool downstream of an untrusted read demands a confirmation and the control gets switched off. `containment_domain` closes that: an **enumerated set of effect-destinations (sinks)** the tool may reach, **or null**. It carries **the set itself, not a flag** — a boolean would be a *claim* the manifest hashes; the set is *the bound*, so narrowing or widening a tool's reach is pin drift by construction. **`arbitrary_exec` is refused a domain at construction**, so an arbitrary-exec tool can never discharge Rule-of-Two by containment — by construction, not by policy. Selector tools enforce the bound at call time; free-text tools enforce it structurally with a **reach test** that watches every device sink and fails when a tool's real reach exceeds its declared domain. Without that executable half the field is a comment.
- **Human-in-loop rides standard rails.** An elevated-confirmation tier for catastrophic operations targets the spec's **Multi-Round-Trip Requests** / **Tasks** extension rather than a bespoke round-trip — the same pause-ask-resume flow, protocol-native and portable.
- **Message-provenance envelope (artifact class 5).** For any message a node *originates* to the operator or another node, sign a **canonical message object** and verify it against a pinned author key before the receiver trusts or renders it.
  - **Envelope — reuse, don't reinvent.** At minimum: `sender_id` (claimed author), `origin_class` (channel / trust class), `keyid` (JWK thumbprint, for rotation), `created` + `nonce` (freshness and replay), and the `payload` (text plus a severity from a **server-side** vocabulary, never caller-chosen). RFC 9421 proper over HTTP; a detached-signature / JWS envelope with the same fields over a push channel or queue. Sign the canonical serialization (§8 #8 applies — a canonicalization gap here *is* a verification break).
  - **Verify = three gates, fail-closed at each.** (1) **Signature** valid against the pinned key for `keyid` → *authenticity*. (2) **`sender_id` on the channel's author-allowlist** → *authorization* — **a valid signature proves who spoke; an explicit allowlist decides whether they may speak here.** (3) **Requested effect within the channel's capability floor** → an effect above the floor (escalate, grant, open a maintenance window, lower a guard) is **refused regardless of a valid signature**. The signature authenticates; it does not authorise. Absence of a valid signature is not neutral — the message renders **suspect**, and that absence is itself the signal.
  - **Render, don't execute — by default.** A class-5 channel should at worst *display*. A channel that lets a message *trigger* an effect is Rule-of-Two plus capability floor, and its blast radius under a compromised-but-authorised producer is exactly what the floor bounds — keep the floor low and the producer set small.

---

## 4. Node applicability matrix — *deployment-specific, omitted*

Each deployment maintains its own matrix privately; it is an inventory of attack surface and does not belong in a public document. The template:

| Node | MCP server(s) | Exposure | Makes LLM calls? | Highest-risk tools | Surface A | Surface B | Priority |
|---|---|---|---|---|---|---|---|

**Danger tiers — scope priority within each server, most → least dangerous:** `arbitrary_exec` (`*_run_command`, container control, deploy) → `state_change` (file writes, service control, network blocking, messages to third parties, clipboard writes, destructive deletes) → `owned_state` (writes to data the server owns and can recover) → `read_only`. Scoping effort concentrates on the arbitrary-exec tier first. A destructive operation on owned data (clearing a workspace, deleting a memory) fails the recoverability clause and is not `owned_state`.

**Prioritise by compromise likelihood × blast radius.** A carried consumer device that exposes an arbitrary shell over a public endpoint belongs at the top of the list on those two factors alone.

**The matrix must be current-state-accurate.** If a deployment runs an owner-authorised exception to a control — for example, suppressing a confirmation gate for development velocity — the matrix names it. A row reading "elevated-gated" without the exception is an over-claim, which is precisely what this matrix exists to prevent.

---

## 5. Exposure policy

**Decide exposure per endpoint:**
- **Public endpoints** (reachable by hosted LLM clients) get the *full* Surface-A treatment: spec-conformant OAuth 2.1 (401 + RFC 9728 PRM, audience-bound) + tool-definition pinning + scoping. Internet-reachable; assume hostile traffic.
- **Private-overlay-only services** (a WireGuard-identity tailnet or similar, serving self-controlled clients and internal viewing) are access-controlled by the overlay's ACLs, not public OAuth. ClearSeal still adds tool-definition pinning and scoping, but the perimeter is the overlay. Cheaper, and stronger for what doesn't need public reach.
- **Anything behind neither** — a raw open port — is a finding. Close it or move it behind one of the above.

**Minimize the public surface to exactly what hosted-LLM access requires.** Hosted-client access needs public reach; self-controlled-client access does not. Ask of every public endpoint whether it needs to be public.

**A signed message makes transport a reliability choice, not a trust choice.** A class-5 message is authenticated by its signature, so the wire carrying it need not be trusted — a hostile party on the path can *drop* it but cannot forge or alter it. Choose transport for **reliability and minimal attack surface**, and tier several:
- **Tier by reliability in the node's actual position, most-reliable-first,** with fall-through driven by a failed delivery confirmation. A node on its peer's LAN may prefer LAN → private overlay → an already-exposed push channel; a remote node starts at the overlay.
- **A fallback must not re-open closed surface.** Standing up a *new* public ingress as a fallback undoes exposure-minimization. Prefer a fallback that reuses infrastructure already exposed; the signature keeps even an untrusted push channel safe to carry the message.
- **Require a delivery-confirmation handshake** — the receiver ACKs *received AND verified*, not merely *connected*. Without it delivery failure is **silent**, which is exactly how a dead channel becomes invisible.
- **Add a liveness signal.** The receiver expects a periodic signed heartbeat; its absence **alarms locally** ("channel down — I may be missing messages"). A down channel must be visible, never silently absent. A fast position probe ("am I on the home LAN?") avoids paying a primary-tier timeout on every message.

---

## 6. Key hierarchy

- **Human/approval root** → m-of-n as the North Star. Signs pins, tool-definition approvals, grants. Rare, ceremonial, event-driven rotation.
- **Node/runtime keys** — per server, non-exportable, published via the RFC 9421 directory. Sign manifests and responses (self-controlled clients). Roughly quarterly rotation. Never m-of-n.

**The custodian tension — and its general resolution.** The most convenient custodian for the human root is often the device the operator always carries — which is also the most-poppable node. Three resolutions exist: (a) hardware-back the root (a secure element or hardware token) so software compromise cannot extract it; (b) accelerate m-of-n so one popped key is not authority; (c) move custody off the exposed device. **Where the most-exposed node is also the most convenient custodian, moving custody is cheaper and stronger than hardening the exposure — and it is available far earlier than either alternative.** Recommended default: an offline root, generated off-network, the private half never leaving its custody medium; the carried device holds the **public half only** and verifies with it. Hardware-backing and m-of-n remain upgrades, off the critical path.

**Signer isolation — the signing key never sits in the layer that reads untrusted input.** A node that both processes untrusted input (an LLM or agent layer) and signs class-5 messages must not hold the key *in that layer*. Hold it in a small, auditable **signer** — its own process and user, key file `0400`/`0600`, loaded once — and let the untrusted-input layer *request* a signature over a narrow interface. The signer is a **policy chokepoint, not an oracle**: it signs only well-formed messages for author ids it controls, never arbitrary bytes. The ceiling this buys: a fully compromised untrusted-input layer can *request* a signed message (bounded by the capability floor — at worst a rendered nuisance) but **cannot exfiltrate the key** to forge freely.

**The class-5 signer holds a node/runtime key — never the human root.** Both tiers share a *design* (Ed25519, a domain-separated canonical serialization, the public half pinned at the verifier), and that similarity is exactly what invites the mistake. They are different tiers and different keys: the root is ceremonial, offline and rarely used; a class-5 signer is warm and used continuously by a running producer. Putting the root in the signer would place a ceremonial key inside a process adjacent to untrusted input — the isolation rule, inverted. **Shared design, separate keys**; a node may hold several signer keys, one per author id it controls.

**The verifier's trust anchor is itself an integrity target.** If an attacker can **rewrite the pinned author key**, they forge at will. The public-key store (`keyid → key`) must be **write-protected** — owned by the verifier, not writable at equal privilege — and validated at load. Where an equal-privilege process is in scope this is a real ceiling, not a full defence: state it, raise the bar as far as the platform allows (ownership + mode + a load-time fingerprint check), and record the residual.

---

## 7. Ratified decisions

1. Name: ClearSeal (lineage names carried for cross-reference; the spec is self-contained).
2. Signing: a single human key for proof-of-concept → m-of-n North Star, **human root only**.
3. Posture: fail closed; break-glass reserved (trigger and design pre-decided, never improvised).
4. Rotation: roughly quarterly for online keys; event-driven for the human root.
5. *Omitted — deployment-specific (audit sequencing).* General form: audit, then refactor, **one server at a time, highest compromise likelihood first**.
6. Transport for client-side signing = RFC 9421; the policy payload is ours. No hand-rolled crypto.
7. SPIFFE/SPIRE out of scope at static-node topology.
8. *Omitted — deployment-specific (topology).* General form: hub-and-spoke, a shared-state store as the real mesh, a private overlay as the internal substrate.
9. Client-side signing applies only to self-controlled clients, not hosted clients.
10. Inbound auth rebases onto MCP `2026-07-28`. Conform to its OAuth 2.1 / RFC 9728 / RFC 8707 / S256 baseline; do **not** hand-roll auth the protocol mandates.
11. *Omitted — deployment-specific (a retired interim credential bridge).* General form: an interim control ships with a **defined exit**, not just a patch — and a documented root cause is corrected when it proves wrong.
12. **Don't duplicate the substrate.** ClearSeal owns the integrity + policy + caging layer (classes 1–5, egress, off-box gate, Surface B); the spec owns transport, session model, and auth discovery.
13. **Depend on the official MCP SDK, not a framework wrapper, in the security path.** A framework is a second interpretation of the spec between you and the spec; a wrapper that cannot yet reach the current revision is that risk realised. Default: TypeScript on the official TypeScript SDK. A node may deviate for a *platform* reason, and records why.
14. **`owned_state` + pinned gate inputs.** Four-rung ladder; `untrusted_input_facing` orthogonal; **every** property a gate reads is hashed into the manifest — the ten-field canonical object in §3, `elevated` and `containment_domain` included. A gate never reads a field the manifest does not cover.
15. **Enumerate every input to every security decision.** For each gate, each input MUST be either **(a)** covered by the integrity system (pinned into the canonical hash), or **(b)** explicitly documented as out of scope **with its own named control**. There is no third category. Enforce it mechanically — `GATE_READ_FIELDS ⊆ canonicalFieldSet()` as a test that **can fail**; a comment is not a control.
16. **Node→operator messages are a signed artifact class (class 5),** verified through three fail-closed gates — signature, author-allowlist, capability-floor — before trusted or rendered. Transport is chosen for reliability, not trust (§5); the signing key is isolated from any untrusted-input layer (§6). The channel renders by default; a channel that executes is Rule-of-Two plus floor.

---

## 8. Adversarial view

1. **Injected-but-authorized client → a valid, in-scope, malicious call.** The permanent ceiling. Answer: tight scoping (Rule-of-Two) + egress/sink validation (allowlists, no private-IP SSRF, human confirmation on the irreversible). Audience-bound tokens authenticate the caller and do nothing against this.
2. **Root compromise of a node** → the gate constrains what it forwards; sandbox each server (own container, egress-restricted, DNS blocked by default); keep the blast radius small.
3. **The empirical baseline applies to you.** Equixly's 2025 offensive assessment of MCP server implementations found command injection in 43%, SSRF in 30%, and path traversal in 22%; Enkrypt AI's scan of 1,000 public MCP servers (October 2025) found critical vulnerabilities in about a third. Most servers were built fast. **Assume these classes are present in yours until an audit proves otherwise.** A signed, authenticated call into a command-injectable tool is a signed, authenticated compromise.
4. **`localhost` is not safe because it is local.** Check what each server binds to.
5. **A credential in a URL is its own finding.** A secret in a query string lands in tunnel and proxy logs — which a server's own tools may be able to read, turning a logging default into an exfiltration primitive. Header-based auth removes the antipattern entirely. The usual root cause is §B's: an edge gate that cannot speak RFC 9728 forced the credential somewhere it did not belong.
6. **The most-poppable node as key custodian** → §6, custodian tension.
7. **The gate and the human root are crown jewels** → minimal gate dependencies, reviewed deploys, a scoped and rotated deploy token, and the gate's own source held under this standard's discipline.
8. **Canonicalization gap** → a strict canonical form per artifact class. The most likely thing to bite a proof-of-concept.
9. **Alert fatigue** → re-sign on every legitimate change, so an unexplained drift alert is always an incident.
10. **Unpinned gate input** → a gate deciding on a field the manifest does not hash is escapable by flipping that field with zero pin drift. Pin every field any gate reads; enforce the subset invariant with an executable test, not a comment.
11. **UNPINNED AUTHORITY — the class, not the instance.** *A security gate's decision depends on an input the integrity system does not cover.* The system looks complete — the manifest hashes tools, the verifier quarantines drift, the tests are green — but the gate's real decision function is `f(pinned, unpinned)`. Move the unpinned argument and the outcome flips with **no drift raised**. This is not a bypass of a control; it is a control that was never watching the thing that decided.

    **Three instances, one root, found in one day:** a Rule-of-Two gate reading a tool field the manifest did not hash (`untrusted_input_facing`); a human-confirmation gate reading membership in an allowlist held outside the manifest entirely (`elevated`); and a git credential chain in which the winning credential was decided by helper-chain **order**, undeclared and unreviewed (`git -c credential.helper=X` *appends* to the chain; it does not replace it).

    **Severity ordering worth internalising:** an unpinned *field* is at least visible on the object — a reviewer reading the tool sees it sitting there untracked. An **out-of-manifest allowlist is authority the pinning system does not know exists**; nothing in the tool points at it. The set-shaped instance is strictly worse than the field-shaped one.

    **Where authority hides — sweep all five:** (1) allowlists and denylists in code; (2) environment variables that switch behaviour (strictness flags, feature flags, debug modes); (3) config files read at runtime (tunnel ingress, ACLs, firewall rules); (4) naming conventions used as logic ("any tool ending `_elevated` is elevated" derives authority from a string nobody pinned); (5) **ordering and precedence** — which rule wins. Category 5 is the one nobody audits.

    **Corollary:** hashing a *set* tells you something moved but not which member; hash the property **per subject** so drift names the subject.
12. **THE UNSPOKEN CAPABILITY — a receivable message-type or capability with no legitimate producer.** A channel is built to *honour* a message class — a severity, a command, an effect — that **nothing authorised is wired to send.** The receiver knows how to act on it; the sender side is empty. The system looks armed and complete; in truth it holds a loaded input with no legitimate finger on the trigger, so **the first thing that produces it is hostile by construction.** Sibling to #11: #11 is a gate reading an input nobody pinned; #12 is a channel honouring a message nobody is authorised to send. Fix: **decide who may produce it (the author-allowlist) before shipping the thing that receives it**, or do not receive it at all. Review corollary: for every message-type a receiver honours, name its authorised producer. A producer of "none, currently" is this finding, not a to-do.

---

## 9. Investigation-phase SOP (per MCP server)

Executor audits; owner gates. Repeat per server, highest compromise likelihood first.

1. **Inventory** — read the server source. Enumerate every tool: inputs, what it can touch, blast radius. Output: a tool table.
2. **Exposure** — how is it reached (public tunnel / private overlay / raw port)? What auth sits in front (spec-conformant OAuth 401 + PRM / bearer / edge SSO / none)? Is it publicly resolvable? Does it bind to `0.0.0.0` or `localhost`? Record whether the endpoint returns a proper `401 + protected-resource-metadata` or a non-conformant challenge. **Probe and record the protocol revision actually served.**
3. **Classify** each tool into a danger tier (`arbitrary_exec` / `state_change` / `owned_state` / `read_only`) **and** set `untrusted_input_facing` independently. For any `owned_state` claim, record the one-line `recoverability_basis`; if it cannot be stated in one line, it is not `owned_state`.
4. **Vulnerability pass** — input validation (command injection, path traversal, SSRF), secret handling, **credential-in-URL and log leakage**, `localhost` trust, egress, error verbosity.
5. **Deprecation sweep** — confirm the server relies on no deprecated protocol features (Roots, Sampling, Logging). Application-level logging to files is *not* protocol Logging and is unaffected — verify, don't assume.
6. **Enumerate gate inputs — the unpinned-authority sweep.** For every security decision the node makes (auth, capability gating, elevated confirmation, egress allowlist, rate limit), list *every* input and classify each: **pinned** / **out-of-scope-with-a-named-control** / **UNPINNED AUTHORITY (finding)**. Sweep the five hiding places in §8 #11. Anything in the third bucket is a finding however safe it looks today.
7. **Map to ClearSeal** — per tool: `capability_class`, `untrusted_input_facing`, proposed `scope`, `recoverability_basis` (if `owned_state`), `containment_domain`, Rule-of-Two verdict, human-in-loop needed, tool-definition pin applicability.
8. **Triage** — split findings into **FIX-NOW** (an open door, independent of the standard) vs **REFACTOR** (fold into ClearSeal).
9. **Report + gate** — findings and proposed refactor to the owner; nothing changes without approval.

**Deliverable per server:** a short audit report (tool table + exposure + tiers + gaps + fix-now/refactor split), then — on approval — the refactor PRs.

---

## 10. Rollout

- **P-1 — Vulnerability floor + deprecation sweep.** Scanner plus input-validation pass on the arbitrary-exec tools. *Before* securing access, make the servers worth securing.
- **P0 — Tool-definition pinning, every server.** Works regardless of client; kills poisoning and rug-pulls.
- **P1 — Conform to the MCP `2026-07-28` auth baseline** on every public endpoint; move endpoints that don't need public reach behind the private overlay.
- **P2 — Capability scoping + egress/sink + sandboxing** on the arbitrary-exec tier; add the elevated-confirmation tier via Multi-Round-Trip Requests / Tasks.
- **P3 — Surface B:** prompt-pin gate + BYOK + spend limits on inference-originating nodes.
- **P4 — Full ClearSeal for self-controlled clients:** RFC 9421 manifest and response signing; signed manifests land as events on the shared event bus, so audit and security become one layer.
- **P5 — Retrofit** of internal orchestration and observation layers, last.

---

## 11. Placement

ClearSeal sits beside a deployment's deterministic-verification and observation layers and shares their philosophy: source control as the source of truth, verification that is deterministic rather than advisory. Signed manifests and responses *are* signed events, so the audit and security layers unify on the same event bus.

*ClearSeal makes every artifact and action provable. The protocol makes the caller authentic; scoping, egress/sink validation, and sandboxing make the call safe. The audit comes before the crypto: a signed call into a broken tool is a signed compromise.*

---

## Provenance

Derived 2026-09-21 from the full ClearSeal v0.8 standard (private, deployment-specific edition) by Claude, at Scotty's direction, in a chat co-architecture session. Removed: the node inventory and its exposure detail (§4), deployment topology and sequencing (§7 #5, #8), a retired interim credential bridge and its incident record (§7 #11), key custody location (§6), an owner-authorised control exception, and one unsourced statistic (§8 #3). Every removal was generalised where the lesson survives without the detail. Section, decision and adversarial-class numbering is unchanged.
