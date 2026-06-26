# SkillSpector → Helmet capability matrix

Status: draft · Issue: `hlmt-88k8` · Decision context: **Helmet stays pure Rust, Option A (reference / rule-harvesting) only.**

Reference: [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) @ `2eb8447` — 64 patterns across 16 categories.

## The framing that decides everything

SkillSpector and Helmet solve **different problems** that happen to share a vocabulary:

- **Helmet** = a *content / text* defense engine. Input is always a `&str`; the `Guard` API scans text line-by-line. No file types, no AST, no repo traversal, no dependency graph. (`helmet-core` Guard: `check(&str) -> ThreatReport`.)
- **SkillSpector** = a *static code / package* analyzer. Input is a repo / zip / dir / file; it parses Python ASTs, tracks taint, runs YARA over bytes, and queries OSV.dev for vulnerable deps.

So the overlap is **not** the language (Python vs Rust) — it's the *analysis surface*. SkillSpector's value to Helmet splits cleanly:

1. **Content/prompt categories** — these map directly onto Helmet's existing L0/L1 and planned L3. This is where rule-harvesting pays off now.
2. **Code/package categories** (AST, taint, YARA, deps, manifests) — these require a **new capability surface Helmet does not have**: scanning *artifacts* (a `SKILL.md` + its scripts + its manifest) rather than a string. Adopting them means deciding whether Helmet grows a `skill scan` mode at all — a strategic question, not a porting task.

## Scope decision (2026-06-17): no AST, no code SAST

Helmet's mission is **content defense for text, prompts, and skills** — *not* judging what executable code does. A "skill" to Helmet is its **text surface**: the `SKILL.md` body, frontmatter/manifest, tool/parameter descriptions, trigger fields, and at most **regex-level string signals** over any attached scripts. All of that is text or structured text.

That settles the AST question outright: **we never need AST, taint, or dataflow.** Those exist to reason about *executable behavior* (does this variable flow into a sink, does the code match its declared capabilities) — that is a code SAST product, a different tool. Helmet is not that tool, so the entire AST/taint half of SkillSpector is **out of scope by design**, not "deferred." The regex-substitutable checks (is there an `eval(`/`subprocess` string in an attached script) survive only as *optional, noise-tolerant content signals*, never as code analysis.

New mark in the matrix below: **🚫 Out of scope** = belongs to a code SAST / malware / dependency-scanner product, not Helmet.

## Legend

| Mark | Meaning |
|------|---------|
| ✅ Covered | Helmet already does this in a shipped layer (L0/L1) |
| 🟡 Partial | Some patterns in the category are covered; others aren't |
| 🔵 Planned | On Helmet's roadmap (L2–L6 design doc) |
| 🟠 Gap (content/manifest) | Fits Helmet's text/manifest model, not yet built — cheap pure-Rust win, no AST |
| 🚫 Out of scope | Code SAST / malware / dependency scanning — needs AST/taint/bytes/deps; a different product |

## Matrix (16 categories)

| # | SkillSpector category | Patterns | Method | Helmet status | Maps to | Notes |
|---|----|---|---|---|---|---|
| 1 | Prompt Injection | P1–P5 (5) | static regex | ✅ Covered | L1 heuristics | Helmet's instruction-override / harmful-content / exfil families already cover P1–P5; Helmet arguably stronger (multilingual, flattery+redirect). |
| 7 | System Prompt Leakage | P6–P8 (3) | static regex | 🟡 Partial | L1 heuristics | P6 direct + P7 indirect = covered (system-prompt-extraction patterns). P8 tool-based exfil = partial (no tool-call model). |
| 16 | MCP Tool Poisoning | TP1–TP4 (4) | regex + 1 LLM | 🟡 Partial | L0 + L1 | TP1 hidden instructions ✅, TP2 unicode deception ✅ (L0 confusable/zero-width is a Helmet strength), TP3 param-desc injection 🟠 (needs manifest), TP4 desc-behavior mismatch 🔴 LLM-only → **drop** (no-LLM core). |
| 2 | Data Exfiltration | E1–E4 (4) | static regex | 🟡 Partial | L1 now / L3 planned | E1 external transmission + E4 context leakage = covered as content patterns. E2 env harvesting + E3 fs enumeration = code-context → L3 outbound gate (planned). |
| 8 | Memory Poisoning | MP1–MP3 (3) | static regex | 🟡 Partial | L1 | MP1 persistent-context + MP3 memory-manip overlap instruction-override family. MP2 context-window stuffing ≈ Helmet token-budget / stuffing detection. |
| 6 | Output Handling | OH1–OH3 (3) | static regex | 🔵 Planned | L3 outbound gate | Exactly the L3 charter (unvalidated/cross-context/unbounded output). Wait for L3. |
| 5 | Excessive Agency | EA1–EA4 (4) | static regex | 🟠 Gap (content) | (skill manifest) | Patterns over skill metadata/manifest, not free text. Cheap regex once a manifest-scan surface exists. |
| 9 | Tool Misuse | TM1–TM3 (3) | static regex | 🟠 Gap (content) | (skill manifest) | Same: manifest/tool-decl patterns. Pure-Rust trivial *if* manifest scanning is in scope. |
| 11 | Trigger Abuse | TR1–TR3 (3) | static regex | 🟠 Gap (content) | (skill manifest) | Over-broad / shadow / bait triggers — needs a notion of a skill "trigger" field. New surface, but regex-shaped. |
| 3 | Privilege Escalation | PE1–PE3 (3) | static regex | 🟠 Gap (manifest) | (skill script regex) | sudo/root/credential-access *strings*. Survives only as optional noise-tolerant regex over attached scripts — content signal, not code analysis. |
| 15 | MCP Least Privilege | LP1–LP4 (4) | AST + regex | 🟡 Split | (manifest) | LP2/LP3 = wildcard/missing-permission manifest regex → 🟠 in scope. LP1/LP4 = declared-vs-actual capability → 🚫 needs AST. |
| 4 | Supply Chain | SC1–SC6 (6) | regex + OSV API | 🚫 Out of scope | (dependency scanner) | Dependency/OSV/typosquat = package security, a different product. Cheap in Rust (OSV is HTTP+serde) *if* ever wanted, but not text/prompt/skill defense. |
| 14 | YARA Signatures | YR1–YR4 (4) | YARA | 🚫 Out of scope | (malware scanner) | Byte-level malware/webshell = antivirus axis. `yara-x` (pure Rust) available if ever wanted, but not Helmet's mission. |
| 10 | Rogue Agent | RA1–RA2 (2) | AST | 🚫 Out of scope | (code SAST) | Self-modification / session persistence = executable-behavior analysis → AST. Not Helmet. |
| 12 | Behavioral AST | AST1–AST8 (8) | Python AST | 🚫 Out of scope | (code SAST) | exec/eval/subprocess as *code analysis* = SAST. Only the cheap string-signal version survives as optional content regex (no AST, noise-tolerant). |
| 13 | Taint Tracking | TT1–TT5 (5) | taint/dataflow | 🚫 Out of scope | (code SAST) | Source→sink dataflow — the canonical thing AST exists for. Categorically not Helmet's job. |

### Tally (after the no-AST scope decision)

- ✅/🟡 **already in Helmet's content lane**: categories 1, 2, 7, 8, 16 (≈19 patterns) — prompt-injection & leakage core.
- 🔵 **planned, no action**: category 6 → L3 (3 patterns).
- 🟠 **cheap content/manifest gaps, no AST**: categories 5, 9, 11, PE1–3, LP2/LP3 (~15 patterns) — only blocked on a skill text/manifest scan surface; all regex/structured-parse.
- 🚫 **out of scope (code SAST / malware / deps)**: categories 4, 10, 12, 13, 14, LP1/LP4 (~25 patterns) — a *different product*. Drop, don't defer.

The harvestable set for Helmet is the ✅/🟡/🔵/🟠 buckets — **all pure text/manifest/regex, zero AST.**

## Harvestable rule set (seeds deliverable #2) — all pure text/manifest, no AST

Ranked by value/effort, within Helmet's content-defense scope:

1. **Prompt-injection / leakage rule top-ups (P1–8, MP1–3, TP1–3, E1/E4)** — *easy, immediate.* Fold the rule *ideas* into L1 heuristics; mostly already covered, harvest any phrasings Helmet lacks. Zero new surface.
2. **Unicode-deception confirmation (TP2)** — *done.* L0 confusable/zero-width already covers this; just confirm parity.
3. **Output-handling (OH1–3)** — *planned.* Route into the L3 outbound-gate charter, don't build separately.
4. **Skill-manifest checks (EA1–4, TM1–3, TR1–3, LP2/LP3, PE1–3)** — *easy, needs a thin skill/manifest text-scan surface.* All regex/structured-parse over `SKILL.md` frontmatter, tool/param descriptions, trigger fields, and (noise-tolerant) attached-script strings. **This is the one genuinely new thing**, and it's still just text parsing — no AST.

**Explicit drops:**
- **🚫 code-SAST half** — AST1–8, RA1–2, TT1–5, LP1/LP4: different product (executable-behavior analysis). Not deferred — out of scope.
- **🚫 malware/deps** — YARA (YR1–4), Supply Chain (SC1–6): antivirus / dependency-scanner axes; cheap in Rust (`yara-x`, OSV) but not text/prompt/skill defense.
- **no-LLM** — TP4 (LLM-only) and SkillSpector's stage-2 LLM semantic filter.

## Recommendation toward the decision memo

- **The AST question is closed:** Helmet defends *content* (text/prompts/skills), so AST/taint/dataflow are out of scope by design. Half of SkillSpector's taxonomy is therefore not Helmet's to reimplement.
- **Now (zero/low new scope):** harvest the prompt-injection & leakage rule ideas into L1, route output-handling into L3. Pure rule-harvesting.
- **One real decision:** whether to add a thin **skill text/manifest scan surface** (scan a `SKILL.md` + manifest + descriptions as structured text). That unlocks categories 5/9/11/PE/LP2-3 — all regex, all pure Rust, still no AST. Everything beyond that line belongs to a separate SAST/AV/dependency tool, not Helmet core.
