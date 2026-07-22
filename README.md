# @clawdreyhepburn/openclaw-ovid-me

**The security desk that checks every AI helper's ID badge — and stops it from doing anything its badge doesn't allow.**

This is a plugin for [OpenClaw](https://github.com/openclaw/openclaw) (an AI agent runtime). Its companion plugin, [openclaw-ovid](https://github.com/clawdreyhepburn/openclaw-ovid), gives each AI helper ("sub-agent") a signed ID badge listing what it's allowed to do. **This plugin is the part that actually reads those badges at runtime and blocks off-badge actions.**

You do **not** need any security or identity background to read this. Everything is explained from scratch.

---

## Table of contents

- [The 30-second version](#the-30-second-version)
- [Why this exists](#why-this-exists)
- [The core idea in one picture](#the-core-idea-in-one-picture)
- [Install](#install)
- [The three modes (start safe, tighten later)](#the-three-modes-start-safe-tighten-later)
- [Worked example](#worked-example)
- [The extra safety check: "you can't give away more than you have"](#the-extra-safety-check-you-cant-give-away-more-than-you-have)
- [The audit trail and dashboard](#the-audit-trail-and-dashboard)
- [Configuration](#configuration)
- [Command-line tools](#command-line-tools)
- [How it fits with its sibling plugins](#how-it-fits-with-its-sibling-plugins)
- [FAQ](#faq)

---

## The 30-second version

- AI assistants spawn smaller **helper agents** to do parts of a job.
- By default, every helper inherits the assistant's *full* power — far more than its task needs.
- The companion plugin stamps each helper with a **badge** listing its allowed actions.
- **This plugin checks that badge before every action the helper takes**, and blocks anything the badge doesn't cover.
- It starts in a safe "watch but don't block" mode so you can see what *would* happen before you turn on real enforcement.

---

## Why this exists

Give an AI assistant a task like *"resolve this support ticket,"* and it may spawn a helper to *"look up the customer's account settings."* In most systems, that helper quietly receives the assistant's entire set of credentials — the same access keys, the same permissions, the same reach. A helper that only needed to *read one setting* now also has the power to *change security configuration*, *delete records*, or *run commands*.

The task got smaller. The power didn't. That mismatch is where accidents and abuse live.

The fix is an old, well-proven idea: **give each worker exactly the authority its job requires, and check that limit at the door.** This plugin is the "check at the door" part. Every time a badged helper tries to do something, this plugin asks a simple question:

> *"Does this helper's badge actually permit this specific action?"*

If yes, it proceeds. If no, this plugin can log it, warn, or block it outright — your choice.

---

## The core idea in one picture

```
   Helper agent wants to do something (e.g. run a command)
                        │
                        ▼
        ┌───────────────────────────────┐
        │        THIS PLUGIN             │
        │  (the security desk)           │
        │                                │
        │  1. Look at the helper's badge │
        │  2. Read its list of allowed   │
        │     actions (its "mandate")    │
        │  3. Does the badge permit THIS │
        │     exact action?              │
        └───────────────┬───────────────┘
                        │
             ┌──────────┴───────────┐
             ▼                      ▼
        YES: allow             NO: log / warn / block
        the action             (depending on your mode)
```

The badge itself is created and signed by the companion plugin, [openclaw-ovid](https://github.com/clawdreyhepburn/openclaw-ovid). This plugin never has to trust the helper's word about who it is — the badge is cryptographically signed and traceable back to you, so it can't be faked.

---

## Install

```bash
# Recommended full stack
openclaw plugins install @clawdreyhepburn/openclaw-ovid      # issues badges
openclaw plugins install @clawdreyhepburn/openclaw-ovid-me   # checks badges (this plugin)
openclaw plugins install @clawdreyhepburn/carapace           # deployment ceiling
openclaw carapace setup
```

Or just the OVID pair:

```bash
openclaw plugins install @clawdreyhepburn/openclaw-ovid-me
openclaw plugins install @clawdreyhepburn/openclaw-ovid
```

OpenClaw picks plugins up automatically. **By default this plugin starts in `dry-run` mode**, which watches and logs but never blocks — so installing it can't break your workflow. You opt into real blocking when you're ready (see next section).

If the forensics dashboard fails after a Node upgrade with a `better-sqlite3` / `NODE_MODULE_VERSION` error, rebuild the native binding in the ovid-me install (`npm rebuild better-sqlite3`). Evaluation still works without SQLite; only the dashboard/structured audit store needs it.

---

## The three modes (start safe, tighten later)

You control how strict this plugin is with one setting, `mandateMode`:

| Mode | What it does | When to use it |
|---|---|---|
| **`dry-run`** *(default)* | Checks every action and **logs** the decision, but **always lets it proceed.** Nothing is ever blocked. | Start here. Run it for a while and read the logs to see what *would* be blocked, without risk. |
| **`enforce`** | Checks every action and **actually blocks** anything the badge doesn't allow. | Turn this on once the dry-run logs look clean — i.e., legitimate work isn't getting flagged. |
| **`shadow`** | Enforces your *current* rules while simultaneously testing a *candidate* new rule set, so you can compare before switching. | For carefully migrating from one policy to another. |

The recommended path is simple: **install in `dry-run`, watch the logs for a bit, then flip to `enforce` once you're confident normal work isn't being caught.** This is the difference between a system that *works correctly* and one you've *seen work correctly* — and you want the second before you let it block anything.

---

## Worked example

Say a helper was badged to *read and search only*. Here are two actions it might attempt, and what this plugin does in **enforce** mode:

```
Helper action: read the file ./src/index.ts
   → badge allows "read"? YES
   → decision: ALLOW  ✅  (recorded as "allow-proven")

Helper action: run the command  rm -rf /
   → badge allows "exec"? NO — badge only has read + search
   → decision: DENY   ⛔  (recorded, and in enforce mode, blocked)
```

In **dry-run** mode, that second action would still be *allowed to run*, but the log would clearly show it *would have been denied* — your early-warning signal.

---

## The extra safety check: "you can't give away more than you have"

There's a subtle failure this plugin also guards against. Suppose a helper that can only *read* tries to spawn its *own* helper and grant it the power to *write* and *run commands*. That would be a worker handing out more authority than it was ever given — a way to sneak past the limits.

This plugin can mathematically **prove** that a new helper's permissions are a genuine *subset* of its parent's, at the moment the badge is created. If the proof fails, the spawn still proceeds, but that helper's later actions are recorded in the audit log as **`allow-unproven`** instead of `allow-proven` — a clear, searchable signal that something granted authority it couldn't justify, so you can review it. (Turning a failed proof into an actual *block* is opt-in: set `subsetProof: 'required'` with a configured policy source.)

- It does this using a **formal proof engine** (a program that reasons about the permission rules the way a mathematician proves a theorem — no guessing, no pattern-matching).
- If that proof engine isn't installed on your machine, this plugin **degrades gracefully**: it falls back to a simpler, more conservative check rather than crashing. (By default this proof step is off; you switch it on with the `subsetProof` setting.)

You don't have to understand the proof machinery to benefit from it. The takeaway: **authority can only ever narrow as it's delegated down the chain, never widen — and that can be proven, not just hoped.**

---

## The audit trail and dashboard

Every decision this plugin makes is recorded — who did what, when, and whether it was allowed or denied. This gives you a complete, after-the-fact record of everything your AI helpers did and were permitted to do.

Two places this lands:

- A structured database at `~/.ovid/audit.db` (and optionally a plain-text log).
- A built-in **web dashboard** you can open in a browser to see the whole picture — which helpers ran, their permission chains, and every allow/deny.

```bash
openclaw ovid-me dashboard    # starts the dashboard, then open the printed URL
```

By default the dashboard runs at `http://localhost:19831` and is bound to your own machine only.

---

## Configuration

All settings are optional; sensible defaults are shown.

| Setting | Default | What it means |
|---|---|---|
| `mandateMode` | `dry-run` | `dry-run` (log only), `enforce` (block), or `shadow` (compare). See [modes](#the-three-modes-start-safe-tighten-later). |
| `subsetProof` | `off` | `required`, `advisory`, or `off`. Whether to prove a child's permissions are a subset of its parent's (the "can't give away more than you have" check). |
| `enforcementFailure` | `closed` | If a check itself errors out, do we fail `closed` (deny — safest) or `open` (allow)? |
| `auditLog` | *(unset)* | Optional path for a plain-text (JSONL) log of every decision. |
| `auditDb` | `~/.ovid/audit.db` | Where the structured audit database lives (powers the dashboard). |
| `dashboardPort` | `19831` | Port for the web dashboard. |
| `authzenPort` | `19832` | Port for the built-in standards-based decision API (see note below). |
| `authzenEnabled` | `true` | Whether to start that decision API at all. |

> **Heads-up:** by default this plugin also starts a small local API server (on port `19832`) that answers permission questions in a standard format called **AuthZEN** (an open industry protocol for asking "is this action allowed?"). It's bound to your own machine. If you don't need it, set `authzenEnabled: false`.

> A note on defaults: the plugin's runtime default for `mandateMode` is `dry-run`, so installing it cannot break existing workflows — it watches and logs but blocks nothing until you opt in. Once you've reviewed the dry-run logs and confirmed normal work isn't being flagged, set `mandateMode: "enforce"` explicitly to turn on real blocking.

---

## Command-line tools

```bash
openclaw ovid-me status      # Show current mode, config, and audit stats
openclaw ovid-me dashboard   # Launch the forensics dashboard
```

And three tools your assistant can call directly:

- **`ovid_evaluate`** — ask "would this specific action be allowed under this badge?"
- **`ovid_shadow`** — compare two different permission sets against the same test actions, side by side.
- **`ovid_audit`** — query the audit database (what happened, when, allowed or denied).

---

## How it fits with its sibling plugins

Picture a secure building:

```
   Carapace                openclaw-ovid            openclaw-ovid-me
   (the building's     →    (the badge printer:  →   (the security desk —
    master rulebook,        stamps each helper        THIS PLUGIN — checks
    set by YOU: what's      with its allowed          every badge at every
    allowed at all)         actions)                  door, allows or denies)
```

- **[Carapace](https://github.com/clawdreyhepburn/carapace)** — the absolute limits *you* set as the human. No badge can exceed them (e.g. "nothing may ever run `rm`, full stop").
- **[openclaw-ovid](https://github.com/clawdreyhepburn/openclaw-ovid)** — the badge printer. Creates and signs each helper's ID and permissions.
- **openclaw-ovid-me** *(you are here)* — the security desk. Reads each badge and enforces it on every action.

**Both checks must pass for an action to run.** Carapace enforces what you the human permit at all; this plugin enforces what the helper's parent actually delegated. A helper with a generous badge still can't punch through the human's ceiling, and a helper under a permissive ceiling still can't exceed its own badge.

For the underlying evaluation library (the Cedar policy engine, the audit system, the proof machinery), see **[@clawdreyhepburn/ovid-me](https://github.com/clawdreyhepburn/ovid-me)**. For the badge/identity format itself, see **[@clawdreyhepburn/ovid](https://github.com/clawdreyhepburn/ovid)**.

---

## FAQ

**Will installing this break my current setup?**
No. It defaults to a watch-only posture (`dry-run` is the recommended starting config) — it logs decisions but blocks nothing until you deliberately switch to `enforce`.

**What's a "mandate"?**
Just the plain list of actions a helper is allowed to do, written on its badge. This plugin's whole job is checking actions against that list.

**What is "Cedar"?**
The small permission language the rules are written in — created by Amazon, designed to be precise and analyzable. You mostly don't interact with it directly through this plugin; the badge-issuing companion handles writing the rules.

**Do I need the formal proof engine?**
No. It's an optional extra check (`subsetProof`). Without it, the plugin still enforces every badge normally; it just uses a simpler method for the "can't give away more than you have" guarantee, and it never crashes if the proof engine is missing.

**What does "OVID-ME" mean?**
**OVID** is the ID-badge format (**O**penClaw **V**erifiable **I**dentity **D**ocument). **ME** is **M**andate **E**valuation — the checking of what each badge permits. So: "the thing that evaluates what OVID badges allow."

---

## License

Apache-2.0
