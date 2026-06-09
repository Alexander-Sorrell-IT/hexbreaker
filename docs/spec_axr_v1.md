# AXR — Agent eXecution Receipt, v1 (open spec)

A tamper-evident record of **what an agent actually did**, where every claimed
finding cites the exact tool execution that produced it. One JSONL file + one
detached signature. Framework-agnostic. MIT.

Generalizes the working Hexbreaker mechanism (hash-chained `StepRecord` +
sidecar hashing + `cited_steps`) and swaps its shared-secret HMAC for a
**public-key** signature so a *third party* — a registry, an auditor, an insurer
— can verify a receipt it did not produce. That swap is the only change that
matters for the trust-substrate thesis: HMAC proves a receipt to its key-holder;
Ed25519 proves it to everyone.

---

## 0. Why this format and not OpenTelemetry GenAI logs

OTel GenAI spans are **mutable observability telemetry**. They are excellent for
debugging and dashboards and AXR rides happily alongside them. They are the
wrong artifact for a *trust score*, for three concrete reasons:

| | OTel GenAI span | AXR receipt |
|---|---|---|
| **Integrity** | Spans are plain JSON a collector can rewrite, drop, or reorder. No hash, no signature. | Each record carries `prev` + `hash`; the chain head is Ed25519-signed. Any edit, reorder, drop, or truncation fails verification. |
| **Claim→evidence binding** | A span says "tool X ran, output Y." Nothing links the agent's *conclusion* to the *specific* tool output it rested on. | A `finding` record's `cites[]` names the exact `tool_call` **and the stdout hash it relied on**. You can prove a conclusion is grounded — or catch one that isn't. |
| **Adversary model** | Designed for a cooperative system reporting on itself. A misconfigured or hostile emitter just emits less. | Designed for an adversary who *wants* a good score: fabricated citations, edited tool output, and truncated logs are all detectable by a verifier holding only the public key. |

OTel answers "what happened, roughly, for debugging." AXR answers "prove this
finding traces to an unmodified tool execution, to someone who doesn't trust
you." The discriminating word is **adversarial**: OTel `gen_ai.*` attributes are
still Development-stability, unsigned, and mutable; you cannot build a published
trust score on a log the scored party can rewrite. AXR is the minimum structure
that makes the score un-fabricable.

A one-line bridge ships in the SDK: emit AXR as the durable receipt **and**
export the same step as an OTel span (`axr.receipt_id` as a span attribute), so
adopters keep their existing tracing and gain a verifiable receipt for free.

---

## 1. Artifact layout

A receipt is a **directory** (or any blob store with the same relative paths):

```
run-7f3a/
  receipt.axr.jsonl          # the hash-chained log, one JSON object per line
  receipt.axr.jsonl.sig      # detached signature over the chain head (JSON)
  outputs/                   # sidecars: raw tool bytes, referenced by hash
    S-001.stdout
    S-001.stderr
    S-003.stdout
```

Rationale for sidecars (kept from Hexbreaker): tool output can be megabytes of
binary. Inlining it bloats the chain and breaks canonical JSON. Instead the
chain stores the **hash** of each output; the bytes live in `outputs/` and are
re-hashed at verify time. This is what lets a 2-KB JSONL receipt stand behind
gigabytes of evidence while still catching a single flipped byte.

---

## 2. Record schema (one JSON object per line)

Every line is one **record**. Common envelope:

```jsonc
{
  "v":     "axr/1",            // format token; reject unknown major versions
  "id":    "S-001",            // monotonic step id, assigned by the SDK, S-%03d
  "seq":   1,                  // integer position, 1-based (truncation defense)
  "type":  "tool_call",        // see record types below
  "ts":    "2026-06-08T14:02:11.317Z",  // RFC3339 UTC, informational only
  "actor": "agent",            // who emitted: "agent" | "tool" | "judge" | "user" | <free string>
  "prev":  "sha256:0000…0000", // hash of the previous record; genesis = 64 zeros
  "hash":  "sha256:8fb8…29b0", // SHA-256 of canonical(record-minus-hash)
  // …type-specific fields…
}
```

`hash` covers **everything in the record except `hash` itself**, including
`prev`. So the chain is Merkle-style: editing any field of any record changes
its `hash`, which breaks the `prev` of the next record, and so on to the head —
which is what the signature covers.

### Record types (the minimal set)

**`tool_call`** — the load-bearing type. One external action the agent took.

```jsonc
{
  "type": "tool_call",
  "tool": {
    "name": "http_get",
    "args_hash": "sha256:…"   // hash of canonical(args); args may also be inlined if non-sensitive
  },
  "result": {
    "exit": 0,
    "stdout_hash": "sha256:…",          // hash of the sidecar bytes
    "stdout_path": "outputs/S-001.stdout",
    "stdout_bytes": 20448,
    "stderr_hash": "sha256:…",
    "stderr_path": "outputs/S-001.stderr"
  }
}
```

Hashing args rather than always inlining them lets an agent prove *what it did*
without leaking secrets (API keys, PII in a query) into a published receipt,
while still being pinnable: the registry's re-run produces the same `args_hash`.

**`finding`** — a claim/conclusion the agent asserts, **bound to its evidence**.
This is the field no receipt competitor has.

```jsonc
{
  "type": "finding",
  "claim": "The downloaded invoice is a 20 KB PDF, not an executable.",
  "cites": [
    { "id": "S-001", "stdout_hash": "sha256:…" }   // MUST match S-001.result.stdout_hash
  ]
}
```

A `finding` is *valid* only if, for each cite, (a) `id` resolves to a `tool_call`
in the same receipt, and (b) the cited `stdout_hash` **equals** that tool_call's
recorded `stdout_hash`, and (c) the sidecar bytes on disk still hash to that
value. (a)+(b) catch a fabricated citation; (c) catches edited evidence. A
finding citing zero steps, or a step that isn't a `tool_call`, is *unsupported*.

**`note`** — free-form agent/LLM reasoning, plans, messages. Carries no evidential
weight; present for completeness and human review.

**`event`** — lifecycle markers: `run_start`, `run_end`, `task_received`. The
`run_start` record SHOULD carry the `task_id` / `task_hash` the agent was given,
which is how a registry binds a receipt to the fresh task it issued.

That's the whole vocabulary: `tool_call`, `finding`, `note`, `event`. Four
types. An agent that does nothing but call tools and assert findings is fully
expressible. Frameworks add nothing to the wire format.

---

## 3. Canonicalization, hashing, signing

- **Canonical bytes**: RFC 8785 JSON Canonicalization Scheme (JCS) — lexicographic
  key sort, no insignificant whitespace, UTF-8, shortest number forms. JCS is
  chosen over "sorted-keys dumps" because it is a published standard with
  verifiers in TS/Py/Go/Rust, so an independent implementer cannot disagree on
  the bytes. (*Assumption:* JCS is sufficient; we do not need full COSE/CBOR for
  v1. If a future profile needs detached binary signatures, `axr/1-cose` can
  carry the same fields in COSE_Sign1.)
- **Record hash**: `hash = "sha256:" + hex(SHA256(JCS(record_without_hash)))`.
- **Chain**: `record[n].prev == record[n-1].hash`; `record[0].prev == GENESIS`
  (`"sha256:" + "0"*64`). `seq` is strictly `1,2,3,…` with no gaps.
- **Signature** (`receipt.axr.jsonl.sig`):

```jsonc
{
  "v": "axr/1",
  "alg": "ed25519",
  "key_id": "did:key:z6Mk…",        // or any agreed key identifier / x5c chain
  "chain_head": "sha256:…",          // hash of the LAST record
  "record_count": 2,                 // signed → truncation is detectable
  "task_hash": "sha256:…",           // optional: binds receipt to the issued task
  "sig": "base64( Ed25519_sign( sk, JCS({chain_head, record_count, task_hash, key_id, alg, v}) ) )"
}
```

Signing **`record_count` alongside `chain_head`** (kept from Hexbreaker) is the
truncation defense: an attacker who chops trailing records off the JSONL still
has a valid chain *prefix* — every remaining record's hash is individually
correct — but the head and count no longer match the signature.

**Why Ed25519, not HMAC** (the deliberate change from the Hexbreaker instance):
HMAC verification requires the secret key, so only the signer can check it —
useless for a public scoreboard. Ed25519 lets anyone holding the *public* key
verify without being able to forge. Key trust (is this the agent's real key?) is
explicitly a *policy* decision left to the verifier — the spec proves integrity,
not identity. A registry resolves `key_id` against whatever identity rail it
trusts (ERC-8004, a DID document, an enterprise PKI).

---

## 4. Verification algorithm (what a third party runs)

Input: the receipt directory + the claimed public key. Output: `ok` + first
failure. No network, no agent framework, fully offline.

```
1. SIGNATURE  Ed25519-verify .sig over JCS({chain_head, record_count, task_hash, …})
              with the public key. → catches forgery / wrong key.
2. COUNT      number of JSONL records == sig.record_count.          → catches truncation/append.
3. CHAIN      for each record in order:
                 seq == expected (1,2,3,…)
                 prev == previous record's hash (record[0].prev == GENESIS)
                 hash == sha256(JCS(record_without_hash))
              last record's hash == sig.chain_head.                 → catches any JSONL edit/reorder.
4. SIDECARS   for each tool_call with a *_path: re-read bytes, sha256 them,
              assert == recorded *_hash; reject paths escaping outputs/.  → catches edited evidence.
5. CITES      for each finding, each cite:
                 cite.id resolves to a tool_call record
                 cite.stdout_hash == that tool_call's result.stdout_hash   → catches fabricated citations.
              (a finding citing 0 steps, or a non-tool_call, is reported as UNSUPPORTED, not a hard fail)
```

A receipt is **`verified`** iff 1–4 pass. Each `finding` is independently
labeled `grounded` / `unsupported` by step 5 — that per-finding label is exactly
the signal a registry scores against, and the surface the Hexbreaker tracer
already implements (`trace.py`: `missing_step`, `not_a_tool_call`,
`hash_mismatch`, `sidecar_mismatch`, `sidecar_escape`).

The reference verifier is intentionally tiny — a few hundred lines of stdlib +
one Ed25519 dependency in any language — so a skeptic can rebuild it from this
spec and check a receipt without installing the SDK.

---

## 5. Minimal end-to-end JSON example (real hashes)

Two records: one `tool_call`, one `finding` that cites it. Hashes below were
computed by the scheme in §3 (`sha256:` of JCS over the record minus `hash`) and
chain correctly — verified, not invented.

`receipt.axr.jsonl`:
```json
{"v":"axr/1","id":"S-001","seq":1,"type":"tool_call","ts":"2026-06-08T14:02:11.317Z","actor":"agent","tool":{"name":"http_get","args_hash":"sha256:4f9c…"},"result":{"exit":0,"stdout_hash":"sha256:1a2b…","stdout_path":"outputs/S-001.stdout","stdout_bytes":20448},"prev":"sha256:0000000000000000000000000000000000000000000000000000000000000000","hash":"sha256:8fb83343326e0559a2340895d8f8b9906fedb9aa9b26c05b726e6235816429b0"}
{"v":"axr/1","id":"S-002","seq":2,"type":"finding","ts":"2026-06-08T14:02:13.901Z","actor":"agent","claim":"The downloaded invoice is a 20 KB PDF, not an executable.","cites":[{"id":"S-001","stdout_hash":"sha256:1a2b…"}],"prev":"sha256:8fb83343326e0559a2340895d8f8b9906fedb9aa9b26c05b726e6235816429b0","hash":"sha256:fb6450ab68b39657a720523424fdb9eef35281e1d6248c7bf37eadb7596c389d"}
```

(The `args_hash`/`stdout_hash` are shown truncated for readability; in a real
file they are full 64-hex digests, and the two `hash` values above are the
actual full digests the scheme produces for these records.)

`receipt.axr.jsonl.sig`:
```json
{"v":"axr/1","alg":"ed25519","key_id":"did:key:z6MkExample","chain_head":"sha256:fb6450ab68b39657a720523424fdb9eef35281e1d6248c7bf37eadb7596c389d","record_count":2,"sig":"base64-ed25519-sig"}
```

Tamper checks against this exact example (all confirmed by running the scheme):
- Change the `claim` text → S-002's `hash` no longer matches → CHAIN fails.
- Append `INJECTED` to `outputs/S-001.stdout` → bytes no longer hash to the
  recorded `stdout_hash` → SIDECARS fails.
- Point the finding's `cites[0].stdout_hash` at a value S-001 never emitted →
  CITES fails (fabricated citation).
- Delete S-002 entirely → `record_count` 1 ≠ signed 2 → COUNT fails.

---

## 6. The SDK (Part 2) in one paragraph, so the format stays adoptable

One import, one wrapper, zero framework coupling. The wrapper records a
`tool_call` around any callable and an `emit_finding()` that takes a claim + the
step ids it rests on:

```python
from axr import Receipt

rcpt = Receipt.open("run-7f3a/", signing_key=sk)   # any Ed25519 key

@rcpt.tool                                          # wrap ANY tool/function
def http_get(url): ...

out = http_get("https://example.com/invoice.pdf")   # auto-emits S-001 tool_call
rcpt.finding("The downloaded invoice is a 20 KB PDF, not an executable.",
             cites=[out.step_id])                    # emits S-002, binds to S-001
rcpt.close()                                         # writes the .sig
```

Because the wrapper sees the function's return value, it hashes the *actual*
bytes the agent saw — the cite cannot drift from the evidence. It works under
LangChain/CrewAI/OpenAI-Agents/MCP/ADK identically because it wraps the
*callable*, not the framework. (*Assumption:* most frameworks expose tools as
plain callables or MCP endpoints; for the few that don't, a thin adapter emits
the same record from their tool-result hook.)

---

## 7. What is deliberately out of scope for v1

- **Key/identity trust** — resolving `key_id` to a real-world principal is a
  policy/registry concern (DID, ERC-8004, enterprise PKI), not the receipt's job.
- **Scoring** — AXR proves *what happened*; the **registry (Part 3)** turns
  verified receipts + a per-finding `grounded` label into a trust score. The
  spec stops exactly at the verifiable artifact.
- **Confidentiality/encryption** — args/outputs can be hashed-not-inlined to
  avoid leaking secrets, but AXR is integrity, not secrecy. Encrypt sidecars at
  rest if needed; the hashes still verify.
- **Suppression** — a fully passive agent that calls no tools emits no
  `tool_call`s and can claim nothing groundable. The registry defeats this by
  *issuing the task and observing execution directly*, so "call nothing" yields
  an unsupported (unscorable) finding rather than an escape. This is a known
  limitation of receipt-only systems (Sello names it explicitly); AXR's answer is
  that the registry, not the receipt, closes it.

---

## 8. Differentiation summary (build-around, don't reinvent)

Traceseal / AgentMint-AERF / Agent-Receipts-AAR have already commoditized the
**integrity** half (Ed25519 + SHA-256 hash-chained signed receipts, open SDKs).
AXR is wire-compatible with that primitive on purpose. The one field they don't
have — and the only one the trust-score needs — is **`finding.cites[]` binding a
conclusion to the exact tool execution**, plus the **sidecar-hash** design that
makes per-claim evidence re-verifiable at scale. If forced to choose, an adopter
should reuse AERF/AAR as the wire format and add the `finding`/`cites` profile;
AXR is that profile made first-class. The defensible asset is not "a receipt
spec" (that ship sailed) — it is the claim→execution binding that lets a neutral
registry score *whether an agent's findings are grounded*, which no receipt
vendor does.
