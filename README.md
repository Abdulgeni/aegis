<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=200&section=header&text=Aegis&fontSize=90&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Dependency%20vulnerability%20scanner%20for%20lock%20files%2C%20powered%20by%20OSV.dev&descAlignY=58&descSize=16" />

<a href="https://github.com/Abdulgeni/aegis/actions/workflows/ci.yml">
  <img src="https://github.com/Abdulgeni/aegis/actions/workflows/ci.yml/badge.svg" alt="CI" />
</a>
<img src="https://img.shields.io/badge/python-3.11%20%7C%203.12-blue?logo=python&logoColor=white" alt="Python" />
<img src="https://img.shields.io/badge/tests-460-brightgreen?logo=pytest&logoColor=white" alt="Tests" />
<img src="https://img.shields.io/badge/rules-OSV%20%2B%20GHSA%20%2B%20CVE-orange" alt="Sources" />
<img src="https://img.shields.io/badge/outputs-table%20%7C%20json%20%7C%20sarif%20%7C%20markdown-purple" alt="Outputs" />
<img src="https://img.shields.io/badge/license-MIT-green" alt="License" />

<br /><br />

<a href="#-installation">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=800&color=2C5364&center=true&vCenter=true&width=800&lines=Finds+CVEs+in+your+lock+files+before+they+find+you;Batch+queries+against+OSV.dev+%E2%80%94+one+call+per+thousand+packages;Verifies+applicability+locally+with+PEP+440+%26+semver;Outputs+table%2C+JSON%2C+SARIF%2C+or+Markdown;Drops+straight+into+GitHub+Code+Scanning" alt="Typing SVG" />
</a>

</div>

---

<div align="center">

### 🛡️ A production-grade supply-chain scanner that runs in one command

</div>

```bash
aegis scan                                  # scan the current directory
aegis scan ./backend --fail-on high         # exit 1 if any finding is HIGH or worse
aegis scan . --output sarif --out aegis.sarif
aegis audit requests==2.31.0                # one-off lookup
aegis ignore CVE-2024-1234 --until 2026-12-31
```

<div align="center">

_Point it at a project; it walks the tree, reads every lock file and manifest, queries OSV for known vulnerabilities, verifies each match locally, and produces a prioritized remediation report._

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Deep scan

- **Lock files preferred over manifests** — exact versions, not guesses
- **Multi-ecosystem** — PyPI, npm, Go in one run
- **Applicability re-verified locally** with the ecosystem's own version rules
- **Direct vs transitive** dependency tracking
- **Line numbers** preserved for SARIF code-scanning links

</td>
<td width="50%" valign="top">

### 🌐 OSV.dev as source of truth

- **Package-and-version keyed** — no CPE guessing, no fuzzy product matching
- **Batch endpoint** (`/v1/querybatch`) — one HTTP call per thousand packages
- **Two-tier SQLite cache** — 24h TTL, zero network on a cache hit
- **Optional NVD enrichment** for CVEs with no CVSS in OSV
- **Polite by default** — 4 concurrent requests, exponential backoff

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🎯 Actionable remediation

- **Minimum safe fixed version** computed per finding
- **`safe_upgrade` flag** when a fix does not cross a major boundary
- **Ecosystem-specific commands** — `pip`, `poetry`, `npm`, `yarn`, `go get`
- **Transitive findings** suggest upgrading the parent, plus override/constraint alternatives
- **Group-fixable** findings share a `group_id` for batch fixes

</td>
<td width="50%" valign="top">

### 📊 Four output formats

- **Table** — rich, color-coded, NO_COLOR aware
- **JSON** — schema-versioned, deterministic
- **SARIF 2.1.0** — drop-in for GitHub Code Scanning
- **Markdown** — ticket-ready, size-budgeted for PR comments
- **Byte-identical** for identical inputs — no timestamps, no dict-order flakiness

</td>
</tr>
<tr>
<td width="50%" valign="top">

### ⚙️ Config that respects you

- **`.aegis.yaml`** discovered upward, stops at `.git`
- **Ignore rules** match by any alias, honor `until`
- **Expired ignores warn**, **unused ignores INFO** — never silent
- **`extra="forbid"`** — typos fail loudly
- **Env only for paths and secrets** — `AEGIS_CACHE_DIR`, `NVD_API_KEY`

</td>
<td width="50%" valign="top">

### 🚀 CI-ready

- **Exit codes**: `0` clean, `1` findings, `2` tool error
- **`--fail-on`** gate for pipelines
- **`--strict`** for teams that want `2` on partial OSV failures
- **Composite GitHub Action** with env-var input passing (injection-safe)
- **SARIF upload** runs even when the scan exits 1

</td>
</tr>
</table>

---

## 🔄 How It Works

```
┌────────────────────────────────────────────────────────────────────────┐
│                            aegis scan .                                │
└──────────────┬─────────────────────────────────────────────────────────┘
               ▼
       ┌───────────────┐   ManifestFile(path, ecosystem, kind)
       │  Discovery    │──► warnings: unreadable, oversized, symlink escape
       └───────┬───────┘
               ▼
       ┌───────────────┐   Dependency(name, version, ecosystem, direct, line)
       │   Parsing     │──► warnings: parse failure, "unpinned manifest"
       └───────┬───────┘
               ▼
       ┌───────────────┐   lock preferred over manifest per (dir, ecosystem)
       │  Resolution   │──► INFO: "preferring poetry.lock over pyproject.toml"
       └───────┬───────┘
               ▼
       ┌───────────────┐   cache hit ──► IDs + records, zero network
       │  OSV lookup   │   miss      ──► POST /v1/querybatch (chunked)
       │  (+ NVD opt)  │             ──► GET  /v1/vulns/{id} (deduped)
       └───────┬───────┘──► warnings: "N dependencies not checked"
               ▼
       ┌───────────────┐   local re-verification: name + ecosystem + ranges
       │   Matching    │──► unverified findings kept with unverified=True
       └───────┬───────┘   CVSS vector ──► severity band
               ▼
       ┌───────────────┐   min safe fix, no_fix, unresolved, safe_upgrade,
       │  Remediation  │   transitive path, group-fixable, suggested commands
       │   + ranking   │   rank: severity > direct > distance > name > id
       └───────┬───────┘
               ▼
       ┌───────────────┐   table | json | sarif | markdown
       │  Reporters    │──► stdout or --out
       └───────────────┘   exit 0 / 1 / 2
```

---

## 🚀 Installation

```bash
pip install -e ".[dev]"       # development
pip install "aegis-audit"     # from PyPI, once published
```

For `aegis ignore` to preserve comments in `.aegis.yaml`:

```bash
pip install "aegis-audit[edit]"
```

**Requires Python 3.11 or newer.**

---

## 🎬 Quick Start

<table>
<tr>
<td width="50%">

### Scan a project

```bash
aegis scan
```

Walks the current directory, produces a table.

</td>
<td width="50%">

### Fail CI on HIGH

```bash
aegis scan ./backend --fail-on high
```

Exit code `1` when any finding is HIGH or worse.

</td>
</tr>
<tr>
<td width="50%">

### SARIF for Code Scanning

```bash
aegis scan . --output sarif --out aegis.sarif
```

Schema-valid SARIF 2.1.0.

</td>
<td width="50%">

### Markdown for a ticket

```bash
aegis scan . --output markdown --out audit.md
```

Executive summary + per-finding detail.

</td>
</tr>
<tr>
<td width="50%">

### Single-package lookup

```bash
aegis audit requests==2.31.0
aegis audit axios@1.6.0 --ecosystem npm
```

No config needed.

</td>
<td width="50%">

### Explain one vuln

```bash
aegis explain CVE-2024-1234
```

Full OSV record: aliases, severity, ranges, references.

</td>
</tr>
<tr>
<td width="50%">

### Add an ignore

```bash
aegis ignore CVE-2024-1234 \
  --reason "mitigated by network ACL" \
  --until 2026-12-31
```

Preserves comments if `ruamel.yaml` is installed.

</td>
<td width="50%">

### See what's ignored

```bash
aegis list-ignores
```

Active and expired rules, with reasons.

</td>
</tr>
</table>

### Command Options

| Flag | Description |
|:---|:---|
| `--output`, `-o` | `table` \| `json` \| `sarif` \| `markdown` |
| `--out` | Write the report to this file instead of stdout |
| `--fail-on` | Exit `1` if any finding is at or above this severity |
| `--ecosystem` | `pypi` \| `npm` \| `go` — restrict to one ecosystem |
| `--only-direct` | Skip transitive dependencies |
| `--config` | Path to a `.aegis.yaml` file |
| `--no-cache` | Skip OSV cache reads and writes |
| `--strict` | Exit `2` on partial OSV failures |

### Exit Codes

| Code | Meaning |
|:---:|:---|
| `0` | Clean (or all findings below `--fail-on`) |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage error, config error, or a scan tool error |

_With `--strict`, incomplete results also exit `2`._

---

## 📦 Supported Lock Files

| Ecosystem | Files |
|:---|:---|
| **PyPI** | `requirements.txt`, `requirements-*.txt`, `requirements/*.txt`, `pyproject.toml` (PEP 621 + PEP 735 + Poetry), `poetry.lock` |
| **npm** | `package.json`, `package-lock.json` (v2/v3) |
| **Go** | `go.mod` |

Discovered but not yet parsed (they appear as INFO warnings):
`Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`.

**Lock files are preferred over manifests.** When both exist for the same directory and ecosystem, the lock is scanned and the manifest is only consulted to tell direct from transitive dependencies.

---

## 🧠 How Matching Works

<table>
<tr>
<td width="12%" align="center"><b>1</b></td>
<td>

Every resolved dependency is queried against OSV's batch endpoint — **one HTTP call per thousand packages**, chunked transparently.

</td>
</tr>
<tr>
<td align="center"><b>2</b></td>
<td>

Full advisory records are fetched once per unique vuln ID and cached. **Two-tier SQLite**: `(ecosystem, name, version) → [vuln_ids]` and `vuln_id → record`. 24h TTL by default.

</td>
</tr>
<tr>
<td align="center"><b>3</b></td>
<td>

Applicability is **re-verified locally** using the ecosystem's own version ordering — PEP 440 for PyPI, semver for npm, semver with `v`-prefix for Go. This catches ecosystem-mismatch edge cases and lets us compute fix versions precisely.

</td>
</tr>
<tr>
<td align="center"><b>4</b></td>
<td>

Findings are **deduplicated** by `(vuln_id, ecosystem, package, version)`, **ranked** by `severity > direct-before-transitive > upgrade-distance > name > vuln_id`, and **tagged with a computed safe fixed version** where possible.

</td>
</tr>
</table>

### Severity

Severity comes from the **CVSS vector** when OSV provides one and it is scorable (v3.0 and v3.1 today; v4 yields `UNKNOWN` with an explicit warning). Otherwise the **GHSA text label** is used, with `MODERATE` normalized to `MEDIUM`.

| Band | CVSS |
|:---:|:---:|
| 🔴 **CRITICAL** | 9.0 – 10.0 |
| 🟠 **HIGH** | 7.0 – 8.9 |
| 🟡 **MEDIUM** | 4.0 – 6.9 |
| 🔵 **LOW** | 0.1 – 3.9 |
| ⚪ **UNKNOWN** | not scored |

### Remediation

For each finding, Aegis computes the **minimum safe fixed version**: the maximum `fixed` event across applicable ranges, re-verified against every affected range of the vuln.

- **`no_fix`** — an applicable range has no `fixed` event
- **`unresolved`** — the candidate fix lands in another vulnerable window
- **`safe_upgrade`** — the fix does not cross a major boundary

Transitive findings suggest upgrading the direct parent, with override/constraint alternatives:

```
pip install "requests>=2.32.0"
pip install --upgrade "requests-toolbelt"
echo "requests>=2.32.0" >> constraints.txt
```

---

## ⚙️ Configuration

A `.aegis.yaml` is discovered **upward from the scan path**, stopping at the first `.git` directory. Every key is validated; typos fail loudly.

```yaml
severity_threshold: low        # do not report below this severity
fail_on: high                  # exit 1 if any finding is at or above this severity

ignore:
  - id: CVE-2024-1234
    package: requests
    reason: "Mitigated by network ACL, tracked in SEC-42"
    until: 2026-12-31
  - id: GHSA-xxxx-yyyy-zzzz
    reason: "Not exploitable in our usage"

ecosystem:
  include: [PyPI, npm]
  exclude: [Go]

cache:
  directory: null              # default: $AEGIS_CACHE_DIR, else ~/.cache/aegis
  ttl_hours: 24

network:
  timeout_s: 30
  max_concurrency: 4
  nvd_enrichment: false        # NVD is used only for CVSS enrichment

discovery:
  max_file_size_mb: 10
  include_dirs: []             # re-enable a normally-skipped directory name
```

**Precedence:** CLI flags > config file > environment > defaults.

The environment participates **only** for `AEGIS_CACHE_DIR` (a path) and `NVD_API_KEY` (a secret); it never sets any other config key.

### Ignore Rules

An ignore rule matches a finding when its `id` equals the finding's `vuln_id` **or any alias**. Adding `--package` restricts the match to one normalized package name.

- An `until` in the past stops suppressing and surfaces as a **warning**.
- An ignore that matches nothing surfaces as **INFO**, so stale entries are visible rather than silent.

```bash
aegis ignore CVE-2024-1234 --package requests --reason "not exploitable here"
aegis ignore GHSA-xxxx-yyyy-zzzz --until 2026-12-31
aegis list-ignores
```

`aegis ignore` uses `ruamel.yaml` round-trip mode to preserve comments and formatting. Without `ruamel.yaml`, it appends a clearly-fenced `ignore:` block only if the file does not already contain one; otherwise it **refuses**, so a hand-written config is never clobbered.

---

## 🚀 GitHub Action

Add a workflow that uses the composite action:

```yaml
name: Dependency audit

on: [pull_request, push]

permissions:
  contents: read
  security-events: write

jobs:
  aegis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Abdulgeni/aegis@main
        with:
          path: '.'
          fail-on: 'high'
          output: 'sarif'
          output-file: 'aegis.sarif'
          upload-sarif: 'true'
```

Findings appear under the repository's **Security → Code scanning** tab with severity, file, line, and remediation.

### Action Inputs

| Input | Default | Notes |
|:---|:---|:---|
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | Severity threshold that fails the step |
| `output` | `sarif` | `table` \| `json` \| `sarif` \| `markdown` |
| `output-file` | `aegis.sarif` | Where to write the report |
| `upload-sarif` | `true` | Upload SARIF via `github/codeql-action/upload-sarif` |
| `extra-args` | *(none)* | Extra args to `aegis scan` |
| `install-from-pypi` | *(none)* | Version to install from PyPI (empty = install from git) |
| `install-git-ref` | `main` | Git ref used when `install-from-pypi` is empty |

> **Security note:** inputs are passed through environment variables, never interpolated directly into the shell, to prevent script injection from crafted repository names or path values.

---

## 🚧 Limitations

Explicit non-goals for v1, so users can judge whether Aegis fits their needs:

- **CVSS v4 is not scored.** v4 uses FIRST's macrovector lookup tables; Aegis returns `UNKNOWN` with a warning rather than approximating. v3.0 and v3.1 are fully supported.
- **No auto-fix.** Aegis only reports. It never modifies `pyproject.toml`, `package.json`, or lock files.
- **Four lock formats are discovered but not parsed:** `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`. They appear as INFO warnings.
- **No version resolution.** Aegis reads the versions the lock files already declare; it does not resolve a dependency tree from scratch.
- **Pre-release versions are matched, but not preferred.** A finding for a pre-release candidate is reported alongside the stable one if OSV lists both.
- **Distribution-backported fixes are not considered.** OSV matches on upstream versions; a Debian or Alpine backport of a fix will still show as vulnerable. This is the same caveat every OSV-based tool carries.
- **No SARIF multi-location results.** A finding with multiple lock-file sources produces one SARIF result pointing at the first source (sorted).

---

## 🛠️ Development

```bash
git clone https://github.com/Abdulgeni/aegis.git
cd aegis
python -m venv .venv && source .venv/Scripts/activate    # Windows Git Bash
pip install -e ".[dev]"
pytest -q
ruff check .
mypy src
```

### Project Layout

```
src/aegis/
  core/          models, config, discovery, errors, ignores
  parsers/       lock-file and manifest parsers + registry
  versions/      PEP 440 / semver / OSV range evaluation
  osv/           OSV HTTP client, SQLite cache, CVSS scoring, lookup orchestration
  enrichment/    optional NVD enrichment
  matching.py    dependency + vuln → Finding
  remediation/   fix computation, commands, ranking, grouping
  reporters/     table, JSON, SARIF, Markdown
  auditor.py     pipeline orchestration (dependency-injected stages)
  commands.py    framework-free command logic
  cli.py         Typer shell
```

Tests do not touch the network. All HTTP is faked via injectable session protocols.

### Why OSV (and not just NVD)

OSV is keyed by **package ecosystem and version ranges** — a query is `("PyPI", "requests", "2.31.0")`, and the response tells you which advisories apply, with precise vulnerable ranges. NVD is keyed by CPE and needs fuzzy product matching, which produces false positives and false negatives.

Aegis uses OSV as its source of truth and only calls NVD as an **optional enrichment** when OSV has no CVSS score (off by default).

---

## 📜 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2c5364,50:203a43,100:0f2027&height=120&section=footer" />

**Built with 🐍 Python, 🛡️ OSV.dev, and 🌐 httpx**

_If Aegis helped you ship safer dependencies, consider giving it a ⭐_

</div>