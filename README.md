# ClearSeal

**An integrity & authenticity standard for LLM-access nodes — the MCP servers that let AI agents act on real systems.**

One discipline:

> **sign → verify against a pinned reference → fail closed, at an off-box gate** — applied to every artifact that enters an LLM's context or crosses a node boundary.

ClearSeal authenticates **artifact, author, channel, freshness, and capability**. It deliberately does **not** authenticate *intent* — it is an integrity/authenticity control, **not** a prompt-injection defense. Believing it is one is its primary failure mode (§0).

## What it adds on top of MCP

The MCP `2026-07-28` revision made OAuth 2.1 and audience-bound tokens mandatory, so ClearSeal does not re-derive auth. It owns what the protocol does not cover:

- **Tool-definition pinning** — tool descriptions are prompts; pin them and tool-poisoning and rug-pulls stop working.
- **A four-rung capability ladder** — `read_only` → `owned_state` → `state_change` → `arbitrary_exec`, with Rule-of-Two on untrusted input.
- **A ten-field pinned tool object** — every property a security gate reads is hashed, so no gate decides on something the integrity system cannot see.
- **`containment_domain`** — portable, pinnable containment for platforms where egress caging is impossible.
- **Message provenance** — signed node→operator messages, verified through signature, author-allowlist and capability-floor gates.
- **Two named failure classes** — *unpinned authority* and *the unspoken capability* — and an audit SOP that sweeps for both.

## Status

**v0.8 — current.** Investigation-phase standard, adopted in production by one reference implementation. This is the public edition: deployment-specific material is omitted, and numbering matches the full standard so citations resolve in either edition.

Read [`ClearSeal-Standard-v0.8.md`](./ClearSeal-Standard-v0.8.md).

## How it was built

Authored by Scotty (ClearForge LLC) as owner and Claude (Anthropic) as executor, and hardened by building against it: most of what is in v0.6–v0.8 was found by a builder agent implementing the standard, then fed back upstream. The design history at the top of the standard records what building taught it.

## License

[CC BY 4.0](./LICENSE). Use it, adapt it, cite it.
