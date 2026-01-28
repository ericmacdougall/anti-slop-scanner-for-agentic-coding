#!/usr/bin/env bash
#
# ███████╗██╗      ██████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
# ██╔════╝██║     ██╔═══██╗██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
# ███████╗██║     ██║   ██║██████╔╝    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
# ╚════██║██║     ██║   ██║██╔═══╝     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╝
# ███████║███████╗╚██████╔╝██║         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
# ╚══════╝╚══════╝ ╚═════╝ ╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
#
# SLOP SCANNER ULTIMATE v6.3.0 — RELEASE CERTIFICATION EDITION
# "If it passes, I'm personally signing off that this can ship to a million customers"
#
# ═══════════════════════════════════════════════════════════════════════════════
# v6.0.0 PHILOSOPHY: PROVE IT WORKS, DON'T JUST SCAN FOR SMELLS
# ═══════════════════════════════════════════════════════════════════════════════
#
# Previous versions hid landmines with truncation, checked for test files but
# not test results, and could leak secrets into reports. v6.0 fixes this by
# treating the scanner like a release gate where YOUR NAME is on the box.
#
# NEW in v6.0.0 - Release Certification Mode:
#
#   FULL COVERAGE (no hidden truncation):
#   - Parallel file scanning across ALL source files
#   - Issues capped at 100K (sanity limit), not hidden
#   - Explicit warnings if any truncation occurs
#   - Directory-stratified sampling to avoid bias
#
#   SECRET REDACTION (don't create new incidents):
#   - Detected secrets redacted in all output
#   - Evidence snippets sanitized
#   - Reports safe to commit/share
#
#   PROOF OF LIFE (actually run the thing):
#   - Build verification (does it compile?)
#   - Test execution (do tests PASS, not just exist?)
#   - Typecheck validation (tsc, mypy, pyright)
#   - Lint enforcement (not just warnings)
#
#   GOLD RECORD CONTRACT (what does "done" mean?):
#   - goldrecord.yaml defines completeness contract
#   - User flows, API contracts, test coverage thresholds
#   - Fail if contract undefined or underspecified
#
#   RELEASE DOSSIER (evidence package):
#   - Machine-readable pass/fail with evidence
#   - Traceability: requirement → code → test → doc
#   - SBOM, vulnerability report, coverage report
#
# Usage:
#   ./slop-scanner-ultimate.sh [--fast|--deep|--certify] [OPTIONS]
#
#   --certify    Release certification mode (strictest, for shipping)
#   --deep       Full analysis with LLM agents
#   --fast       Quick scan, skip heavy tools
#
#   --no-bootstrap    Skip tool installation
#   --no-plan         Skip remediation plan generation
#   --no-llm          Skip LLM analysis
#   --no-build        Skip build verification
#   --no-tests        Skip test execution
#
# Environment Variables:
#   SLOP_CERTIFY_MODE=1           # Enable release certification mode
#   SLOP_FULL_COVERAGE=1          # Scan ALL files (no truncation)
#   SLOP_REDACT_SECRETS=1         # Redact secrets in output
#   SLOP_ENABLE_BUILD_CHECK=1     # Verify build works
#   SLOP_ENABLE_TEST_RUN=1        # Verify tests pass
#   SLOP_REQUIRE_GOLDRECORD=1     # Require goldrecord.yaml
#   SLOP_PARALLEL_AGENTS=4        # Concurrent LLM agents
#
# Outputs:
#   - cleanup-<timestamp>.md in repo root
#   - .gatekeeper/plans/slop-<timestamp>/ (remediation plan)
#   - .gatekeeper/dossier-<timestamp>/ (release evidence, if --certify)
#

set -Eeuo pipefail

VERSION="6.3.0"

########################################
# Configuration (env vars with smart defaults)
########################################
SLOP_BOOTSTRAP="${SLOP_BOOTSTRAP:-1}"
SLOP_LOCAL_DEPS="${SLOP_LOCAL_DEPS:-1}"   # Install to local dir, not global (safe for laptops)
SLOP_ENABLE_CLAUDE="${SLOP_ENABLE_CLAUDE:-1}"
SLOP_ENABLE_GEMINI="${SLOP_ENABLE_GEMINI:-1}"
SLOP_ENABLE_PLAN="${SLOP_ENABLE_PLAN:-1}"

# Tool enables
SLOP_ENABLE_BIOME="${SLOP_ENABLE_BIOME:-1}"
SLOP_ENABLE_RUFF="${SLOP_ENABLE_RUFF:-1}"
SLOP_ENABLE_KNIP="${SLOP_ENABLE_KNIP:-1}"
SLOP_ENABLE_SEMGREP="${SLOP_ENABLE_SEMGREP:-1}"
SLOP_ENABLE_BANDIT="${SLOP_ENABLE_BANDIT:-1}"
SLOP_ENABLE_VULTURE="${SLOP_ENABLE_VULTURE:-1}"
SLOP_ENABLE_DEPCRUISE="${SLOP_ENABLE_DEPCRUISE:-1}"
SLOP_ENABLE_GITLEAKS="${SLOP_ENABLE_GITLEAKS:-1}"
SLOP_ENABLE_OSV="${SLOP_ENABLE_OSV:-1}"
SLOP_ENABLE_ACTIONLINT="${SLOP_ENABLE_ACTIONLINT:-1}"
SLOP_ENABLE_GITSIZER="${SLOP_ENABLE_GITSIZER:-1}"
SLOP_ENABLE_LYCHEE="${SLOP_ENABLE_LYCHEE:-1}"
SLOP_ENABLE_TYPOS="${SLOP_ENABLE_TYPOS:-1}"
SLOP_ENABLE_SLOPSQUATTING="${SLOP_ENABLE_SLOPSQUATTING:-1}"

# Slopsquatting - private registry support
SLOP_PRIVATE_SCOPES="${SLOP_PRIVATE_SCOPES:-}"  # Comma-separated: @mycorp,@internal
SLOP_SKIP_REGISTRY_CHECK="${SLOP_SKIP_REGISTRY_CHECK:-}"  # Comma-separated package names to skip

# LLM retry configuration (handle 429 rate limits)
SLOP_LLM_MAX_RETRIES="${SLOP_LLM_MAX_RETRIES:-3}"
SLOP_LLM_RETRY_DELAY="${SLOP_LLM_RETRY_DELAY:-5}"  # Initial delay in seconds
SLOP_LLM_BACKOFF_MULT="${SLOP_LLM_BACKOFF_MULT:-2}"  # Exponential backoff multiplier

# ═══════════════════════════════════════════════════════════════════════════════
# v6.1 RELEASE CERTIFICATION MODE ("Burn to CD" mode)
# ═══════════════════════════════════════════════════════════════════════════════
# When SLOP_CERTIFY_MODE=1, the scanner operates as if you're personally signing
# off on a release that ships to a million customers:
#   - NO truncation (scan ALL files, report ALL issues)
#   - Require goldrecord.yaml contract (what does "done" mean?)
#   - Require tests actually PASS (not just exist)
#   - Require build actually WORKS
#   - Secret redaction in all output
#   - Generate release dossier with evidence
#   - FAIL HARD on any incomplete/faked/underdocumented state
SLOP_CERTIFY_MODE="${SLOP_CERTIFY_MODE:-0}"

# Full coverage (no hidden truncation that hides landmines)
SLOP_FULL_COVERAGE="${SLOP_FULL_COVERAGE:-1}"         # Scan ALL files via parallel workers
SLOP_WARN_ON_TRUNCATE="${SLOP_WARN_ON_TRUNCATE:-1}"   # Emit blocker if any truncation occurs
SLOP_MAX_ISSUES_HARD_LIMIT="${SLOP_MAX_ISSUES_HARD_LIMIT:-100000}"  # Sanity cap only

# Secret redaction (don't create new security incidents in reports)
SLOP_REDACT_SECRETS="${SLOP_REDACT_SECRETS:-1}"       # Redact detected secrets in output
SLOP_REDACT_EVIDENCE="${SLOP_REDACT_EVIDENCE:-1}"     # Redact evidence snippets too

# Proof of life (actually run the thing)
SLOP_ENABLE_BUILD_CHECK="${SLOP_ENABLE_BUILD_CHECK:-1}"   # Run build and verify it works
SLOP_ENABLE_TEST_RUN="${SLOP_ENABLE_TEST_RUN:-1}"         # Run tests and verify they pass
SLOP_ENABLE_TYPECHECK="${SLOP_ENABLE_TYPECHECK:-1}"       # Run typecheck (tsc, mypy, etc.)
SLOP_ENABLE_LINT_CHECK="${SLOP_ENABLE_LINT_CHECK:-1}"     # Run linter and verify clean
SLOP_ENABLE_RUNTIME_CHECK="${SLOP_ENABLE_RUNTIME_CHECK:-0}"  # Spin up and healthcheck (optional)
SLOP_BUILD_TIMEOUT="${SLOP_BUILD_TIMEOUT:-600}"           # 10 min build timeout
SLOP_TEST_TIMEOUT="${SLOP_TEST_TIMEOUT:-900}"             # 15 min test timeout

# Gold record contract enforcement
SLOP_REQUIRE_GOLDRECORD="${SLOP_REQUIRE_GOLDRECORD:-0}"   # Require goldrecord.yaml
SLOP_GOLDRECORD_FILE="${SLOP_GOLDRECORD_FILE:-goldrecord.yaml}"
SLOP_GENERATE_CONTRACT="${SLOP_GENERATE_CONTRACT:-0}"     # Auto-generate contract
SLOP_REGENERATE_CONTRACT="${SLOP_REGENERATE_CONTRACT:-0}" # Regenerate existing contract

# Safety
SLOP_ALLOW_UNSAFE_RUNTIME="${SLOP_ALLOW_UNSAFE_RUNTIME:-0}"  # Allow custom start commands (DANGEROUS on untrusted code)

# Execution
SLOP_JOBS="${SLOP_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
SLOP_USE_PARALLEL="${SLOP_USE_PARALLEL:-1}"

# Isolated environments
SLOP_ISOLATED="${SLOP_ISOLATED:-1}"
SLOP_VENV_DIR=""
SLOP_NPM_PREFIX=""

# ═══════════════════════════════════════════════════════════════════════════════
# TOKEN BUDGETING & CHUNKING (for massive repos)
# ═══════════════════════════════════════════════════════════════════════════════
SLOP_TOKEN_BUDGET_ANALYSIS="${SLOP_TOKEN_BUDGET_ANALYSIS:-12000}"
SLOP_TOKEN_BUDGET_PLANNING="${SLOP_TOKEN_BUDGET_PLANNING:-14000}"
SLOP_TOKEN_BUDGET_REVIEW="${SLOP_TOKEN_BUDGET_REVIEW:-8000}"
SLOP_CHARS_PER_TOKEN="${SLOP_CHARS_PER_TOKEN:-4}"

SLOP_MAX_FILES_PER_CHUNK="${SLOP_MAX_FILES_PER_CHUNK:-50}"
SLOP_MAX_ISSUES_PER_CHUNK="${SLOP_MAX_ISSUES_PER_CHUNK:-100}"
SLOP_MAX_TASKS_PER_STAGE="${SLOP_MAX_TASKS_PER_STAGE:-12}"

SLOP_PARALLEL_AGENTS="${SLOP_PARALLEL_AGENTS:-4}"
SLOP_PLAN_ITERATIONS="${SLOP_PLAN_ITERATIONS:-3}"
SLOP_ENABLE_PLAN_REVIEW="${SLOP_ENABLE_PLAN_REVIEW:-1}"
SLOP_MAX_MATCHES_PER_RULE="${SLOP_MAX_MATCHES_PER_RULE:-999999}"  # No practical limit
SLOP_MAX_TOTAL_ISSUES="${SLOP_MAX_TOTAL_ISSUES:-100000}"          # No practical limit

# Claude - use strongest models
SLOP_CLAUDE_API_KEY="${SLOP_CLAUDE_API_KEY:-}"
SLOP_CLAUDE_MODEL="${SLOP_CLAUDE_MODEL:-claude-sonnet-4-5-20250514}"
SLOP_CLAUDE_MODEL_PLANNING="${SLOP_CLAUDE_MODEL_PLANNING:-claude-opus-4-5-20250514}"
SLOP_CLAUDE_MAX_TOKENS="${SLOP_CLAUDE_MAX_TOKENS:-16000}"

# Claude Code CLI settings
SLOP_CLAUDE_CODE_MAX_TURNS="${SLOP_CLAUDE_CODE_MAX_TURNS:-15}"
SLOP_CLAUDE_CODE_BUDGET="${SLOP_CLAUDE_CODE_BUDGET:-5.00}"

# Gemini / Vertex
SLOP_GCP_PROJECT="${SLOP_GCP_PROJECT:-}"
SLOP_VERTEX_LOCATION="${SLOP_VERTEX_LOCATION:-us-central1}"
SLOP_GEMINI_MODEL="${SLOP_GEMINI_MODEL:-gemini-2.5-pro-preview-05-06}"

# Auth state
CLAUDE_AUTH_METHOD=""
VERTEX_AUTH_METHOD=""
VERTEX_ACCESS_TOKEN=""

# Config file paths
GATEKEEPER_ENV=".gatekeeper.env"
GATEKEEPER_VERTEX_KEY=".gatekeeper.vertex.json"

########################################
# CLI
########################################
MODE="standard"
SHOW_HELP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --certify)
      # Release certification mode - strictest settings
      MODE="certify"
      SLOP_CERTIFY_MODE=1
      SLOP_FULL_COVERAGE=1
      SLOP_REDACT_SECRETS=1
      SLOP_ENABLE_BUILD_CHECK=1
      SLOP_ENABLE_TEST_RUN=1
      SLOP_ENABLE_TYPECHECK=1
      SLOP_REQUIRE_GOLDRECORD=1
      shift ;;
    --deep) MODE="deep"; shift ;;
    --fast) 
      MODE="fast"
      SLOP_ENABLE_CLAUDE=0
      SLOP_ENABLE_GEMINI=0
      SLOP_ENABLE_PLAN=0
      SLOP_ENABLE_SEMGREP=0
      SLOP_ENABLE_DEPCRUISE=0
      SLOP_ENABLE_BUILD_CHECK=0
      SLOP_ENABLE_TEST_RUN=0
      shift ;;
    --generate-contract|--init)
      # Generate goldrecord.yaml from repo analysis
      SLOP_GENERATE_CONTRACT=1
      MODE="deep"  # Need deep analysis for good inference
      shift ;;
    --regenerate-contract|--refresh)
      # Regenerate/update existing goldrecord.yaml
      SLOP_REGENERATE_CONTRACT=1
      SLOP_GENERATE_CONTRACT=1
      MODE="deep"
      shift ;;
    --no-bootstrap) SLOP_BOOTSTRAP=0; shift ;;
    --no-llm) SLOP_ENABLE_CLAUDE=0; SLOP_ENABLE_GEMINI=0; shift ;;
    --no-claude) SLOP_ENABLE_CLAUDE=0; shift ;;
    --no-gemini) SLOP_ENABLE_GEMINI=0; shift ;;
    --no-plan) SLOP_ENABLE_PLAN=0; shift ;;
    --no-build) SLOP_ENABLE_BUILD_CHECK=0; shift ;;
    --no-tests) SLOP_ENABLE_TEST_RUN=0; shift ;;
    --no-redact) SLOP_REDACT_SECRETS=0; shift ;;
    --full-coverage) SLOP_FULL_COVERAGE=1; shift ;;
    --claude-api) SLOP_CLAUDE_API_KEY="$2"; shift 2 ;;
    --gemini-project) SLOP_GCP_PROJECT="$2"; shift 2 ;;
    --jobs) SLOP_JOBS="$2"; shift 2 ;;
    -h|--help) SHOW_HELP=1; shift ;;
    *) echo "Unknown: $1" >&2; SHOW_HELP=1; shift ;;
  esac
done

if [[ "$SHOW_HELP" == "1" ]]; then
  cat <<'EOF'
SLOP SCANNER ULTIMATE v6.3.0 — RELEASE CERTIFICATION EDITION
"If it passes, I'm personally signing off that this can ship"

Usage:
  ./slop-scanner-ultimate.sh [options]

MODES:
  --certify           Release certification mode (STRICTEST)
                      - Scans ALL files (no truncation)
                      - Requires goldrecord.yaml contract (v1 or v2 schema)
                      - Executes contract-defined commands
                      - Enforces placeholder policy and test integrity
                      - Generates release attestation with evidence hashes
  --deep              Full analysis with LLM agents
  --fast              Quick scan, minimal tools, no LLM

CONTRACT GENERATION (bootstrap your goldrecord.yaml):
  --generate-contract, --init
                      Auto-generate goldrecord.yaml (v2 schema) from repo analysis
                      Uses LLM to infer user flows, features, and API contracts
                      Detects npm scripts and generates command definitions
                      Output is clearly marked with TODO for human review
  --regenerate-contract, --refresh
                      Update existing goldrecord.yaml with new discoveries
                      Preserves human edits, adds newly discovered flows

OPTIONS:
  --no-bootstrap      Skip dependency installation
  --no-llm            Disable all LLM backends
  --no-claude         Disable Claude
  --no-gemini         Disable Gemini
  --no-plan           Skip remediation plan generation
  --no-build          Skip build verification
  --no-tests          Skip test execution
  --no-redact         Don't redact secrets in output (dangerous!)
  --full-coverage     Scan ALL files (default in --certify)
  --claude-api KEY    Override Claude API key
  --gemini-project ID Override GCP project for Vertex AI
  --jobs N            Parallel jobs (default: nproc)

ENVIRONMENT VARIABLES:
  SLOP_LOCAL_DEPS=1        Install tools locally, not globally (safe for laptops)
  SLOP_CACHE_DIR=/path     Enable LLM response caching (saves $$)
  SLOP_CACHE_TTL=86400     Cache TTL in seconds (default: 24h)
  SLOP_PRIVATE_SCOPES=@mycorp,@internal
                           Skip registry validation for private npm scopes
  SLOP_SKIP_REGISTRY_CHECK=pkg1,pkg2
                           Skip registry validation for specific packages
  SLOP_LLM_MAX_RETRIES=3   Max retries on rate limit (429)
  SLOP_LLM_RETRY_DELAY=5   Initial retry delay in seconds
  SLOP_LLM_BACKOFF_MULT=2  Exponential backoff multiplier
  SLOP_ALLOW_UNSAFE_RUNTIME=1
                           Allow custom start commands in runtime check
                           ⚠️  DANGEROUS: Only use in ephemeral CI environments!

TOOL CATEGORIES:
  AI SLOP DETECTION:
    - KarpeSlop patterns (hallucinated imports, any-abuse, vibe coding)
    - SloppyLint patterns (mutable defaults, bare except, hedging)
    - Placeholder/stub detection with confidence scoring

  SLOPSQUATTING DEFENSE:
    - Validates package.json dependencies against npm registry
    - Validates requirements.txt against PyPI registry
    - Detects hallucinated/non-existent packages
    - Supports private scopes (SLOP_PRIVATE_SCOPES)

  FAST LINTING:
    - Biome (JS/TS/JSON/CSS) - 425+ rules, 10-100x faster than ESLint
    - Ruff (Python) - 800+ rules, 10-100x faster than Flake8

  DEAD CODE DETECTION:
    - Knip (JS/TS) - unused files, exports, dependencies
    - Vulture (Python) - unused functions, classes, variables

  SECURITY SCANNING:
    - Semgrep - SAST with 2000+ rules
    - Bandit - Python security linter
    - Gitleaks - secrets detection

  DEPENDENCY ANALYSIS:
    - dependency-cruiser - circular dependencies, orphans
    - OSV-Scanner - known vulnerabilities in dependencies

  CODE QUALITY:
    - actionlint - GitHub Actions validation
    - git-sizer - repo health metrics
    - lychee - broken link detection
    - typos - spell checking in code/docs

Authentication (auto-detected):
  Claude:
    1. Claude Code CLI (if installed and authenticated)
    2. SLOP_CLAUDE_API_KEY environment variable
    3. .gatekeeper.env file with CLAUDE_API_TOKEN=

  Vertex AI (Gemini):
    1. Application Default Credentials
    2. .gatekeeper.vertex.json service account key
    3. gcloud user credentials

Models Used:
  Claude:  claude-sonnet-4-5-20250514 (analysis)
           claude-opus-4-5-20250514 (planning)
  Gemini:  gemini-2.5-pro-preview-05-06

Outputs:
  cleanup-<timestamp>.md                    Comprehensive scan report
  .gatekeeper/plans/slop-<timestamp>/       Remediation plan
      ├── overview.md
      ├── stage-1.md ... stage-N.md
      └── progress.md
EOF
  exit 0
fi

########################################
# Utilities
########################################
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

say()  { printf "${GREEN}[slop]${NC} %s\n" "$*" >&2; }
warn() { printf "${YELLOW}[slop]${NC} %s\n" "$*" >&2; }
die()  { printf "${RED}[slop][FATAL]${NC} %s\n" "$*" >&2; exit 1; }
plan() { printf "${CYAN}[plan]${NC} %s\n" "$*" >&2; }
tool() { printf "${PURPLE}[tool]${NC} %s\n" "$*" >&2; }

need_cmd() { command -v "$1" >/dev/null 2>&1; }

is_git_repo() { git rev-parse --show-toplevel >/dev/null 2>&1; }

repo_root() {
  if is_git_repo; then
    git rev-parse --show-toplevel
  else
    pwd
  fi
}

ts_utc() { date -u +"%Y%m%dT%H%M%SZ"; }

has_files() {
  local pattern="$1"
  find . -maxdepth 5 -type f -name "$pattern" ! -path "*/node_modules/*" ! -path "*/.git/*" 2>/dev/null | head -1 | grep -q .
}

########################################
# Parallel execution helper
########################################
run_parallel() {
  # Run functions in parallel using GNU parallel or background jobs
  # Usage: run_parallel func1 func2 func3 ...
  local funcs=("$@")
  
  if [[ "$SLOP_USE_PARALLEL" != "1" ]] || [[ "${#funcs[@]}" -lt 2 ]]; then
    # Sequential execution
    for fn in "${funcs[@]}"; do
      "$fn" || true
    done
    return 0
  fi

  if need_cmd parallel; then
    # Use GNU parallel for better resource management
    export -f "${funcs[@]}" 2>/dev/null || true
    # Export all needed variables and functions
    export ISSUES_JSONL WORKDIR MODE VERSION SLOP_REDACT_SECRETS
    export SLOP_LLM_MAX_RETRIES SLOP_LLM_RETRY_DELAY SLOP_LLM_BACKOFF_MULT
    export -f say warn die emit_issue redact_secrets repo_root is_git_repo has_files need_cmd curl_with_retry clean_json 2>/dev/null || true
    
    printf '%s\n' "${funcs[@]}" | parallel -j "$SLOP_JOBS" --halt never '{}' 2>/dev/null || {
      # Fallback to background jobs if parallel fails
      local pids=()
      for fn in "${funcs[@]}"; do
        "$fn" &
        pids+=($!)
      done
      for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
      done
    }
  else
    # Fallback: background jobs with manual wait
    local pids=()
    for fn in "${funcs[@]}"; do
      "$fn" &
      pids+=($!)
    done
    for pid in "${pids[@]}"; do
      wait "$pid" 2>/dev/null || true
    done
  fi
}

########################################
# Clean JSON from LLM responses
# Strips markdown code fences and extracts valid JSON
########################################
clean_json() {
  local input="$1"
  
  # Use Python for reliable extraction of JSON from chatty LLM output
  # Handles: "Here is the analysis: ```json {...}```" and similar patterns
  python3 -c "
import sys
import re
import json

content = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()

# Strip markdown code fences first
content = re.sub(r'^\`\`\`json\s*', '', content, flags=re.MULTILINE)
content = re.sub(r'^\`\`\`\s*$', '', content, flags=re.MULTILINE)
content = re.sub(r'\`\`\`$', '', content)

# Try to find a valid JSON object or array
# Look for the first { or [ and match to closing } or ]
patterns = [
    r'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',  # Simple nested objects
    r'(\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\])',  # Simple nested arrays
]

# Try direct parse first (cleanest case)
try:
    parsed = json.loads(content.strip())
    print(json.dumps(parsed))
    sys.exit(0)
except:
    pass

# Extract JSON using regex
for pattern in patterns:
    matches = re.findall(pattern, content, re.DOTALL)
    for match in matches:
        try:
            parsed = json.loads(match)
            print(json.dumps(parsed))
            sys.exit(0)
        except:
            continue

# Last resort: find anything between first { and last }
brace_match = re.search(r'\{.*\}', content, re.DOTALL)
if brace_match:
    try:
        parsed = json.loads(brace_match.group(0))
        print(json.dumps(parsed))
        sys.exit(0)
    except:
        pass

# Give up, return empty object
print('{}')
" "$input" 2>/dev/null || echo "{}"
}

# Wrapper to sanitize LLM output files
sanitize_llm_json() {
  local input_file="$1"
  local output_file="$2"
  
  if [[ -f "$input_file" ]]; then
    clean_json "$(cat "$input_file")" > "$output_file"
  else
    echo "{}" > "$output_file"
  fi
}

########################################
# LLM API call with retry and backoff
########################################
curl_with_retry() {
  local url="$1"
  local data="$2"
  local output_file="$3"
  local auth_header="$4"
  local content_type="${5:-application/json}"
  
  local attempt=0
  local delay="$SLOP_LLM_RETRY_DELAY"
  local max_retries="$SLOP_LLM_MAX_RETRIES"
  
  while [[ $attempt -lt $max_retries ]]; do
    ((attempt++))
    
    local http_code
    http_code=$(curl -s -w "%{http_code}" \
      -X POST "$url" \
      -H "Content-Type: $content_type" \
      -H "$auth_header" \
      -d "$data" \
      -o "$output_file" \
      --max-time 120 2>/dev/null)
    
    case "$http_code" in
      200|201)
        return 0
        ;;
      429)
        # Rate limited - exponential backoff
        if [[ $attempt -lt $max_retries ]]; then
          warn "Rate limited (429), retrying in ${delay}s (attempt $attempt/$max_retries)"
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        else
          warn "Rate limited after $max_retries attempts"
          return 1
        fi
        ;;
      500|502|503|504)
        # Server error - retry with backoff
        if [[ $attempt -lt $max_retries ]]; then
          warn "Server error ($http_code), retrying in ${delay}s (attempt $attempt/$max_retries)"
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        else
          warn "Server errors after $max_retries attempts"
          return 1
        fi
        ;;
      *)
        # Other errors - fail immediately
        warn "API error: HTTP $http_code"
        return 1
        ;;
    esac
  done
  
  return 1
}

########################################
# Bootstrap (Ubuntu/Debian root)
########################################
apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1 || true
}

pip_install() {
  if [[ "$SLOP_LOCAL_DEPS" == "1" ]]; then
    # Install to local venv
    local venv_dir="$WORKDIR/.venv"
    if [[ ! -d "$venv_dir" ]]; then
      python3 -m venv "$venv_dir" 2>/dev/null || true
    fi
    if [[ -d "$venv_dir" ]]; then
      "$venv_dir/bin/pip" install --quiet "$@" 2>/dev/null || true
      # Add to PATH for this session
      export PATH="$venv_dir/bin:$PATH"
    else
      # Fallback to user install
      pip install --quiet --user "$@" 2>/dev/null || true
    fi
  else
    # Global install (CI mode)
    pip install --quiet --break-system-packages "$@" 2>/dev/null || pip install --quiet "$@" 2>/dev/null || true
  fi
}

npm_install_global() {
  if [[ "$SLOP_LOCAL_DEPS" == "1" ]]; then
    # Install to local node_modules
    local npm_dir="$WORKDIR/.npm-local"
    mkdir -p "$npm_dir"
    npm install --prefix "$npm_dir" "$@" >/dev/null 2>&1 || true
    # Add to PATH for this session
    export PATH="$npm_dir/node_modules/.bin:$PATH"
  else
    # Global install (CI mode)
    npm install -g "$@" >/dev/null 2>&1 || true
  fi
}

########################################
# Early Requirements Check (Fail Fast)
########################################
check_requirements() {
  local missing=()
  local warnings=()
  
  # Always required
  need_cmd rg || missing+=("ripgrep (rg)")
  need_cmd jq || missing+=("jq")
  need_cmd python3 || missing+=("python3")
  need_cmd curl || missing+=("curl")
  
  # Mode-specific requirements
  if [[ "$MODE" == "deep" ]] || [[ "$SLOP_ENABLE_PLAN" == "1" ]]; then
    if [[ -z "$SLOP_CLAUDE_API_KEY" ]] && [[ -z "$ANTHROPIC_API_KEY" ]] && [[ "$SLOP_ENABLE_CLAUDE" == "1" ]]; then
      if [[ "$SLOP_ENABLE_GEMINI" != "1" ]] || [[ -z "$SLOP_GCP_PROJECT" ]]; then
        warnings+=("No LLM API keys configured (ANTHROPIC_API_KEY or SLOP_GCP_PROJECT)")
      fi
    fi
  fi
  
  # Optional tools - warn if enabled but missing
  [[ "$SLOP_ENABLE_GITLEAKS" == "1" ]] && ! need_cmd gitleaks && warnings+=("gitleaks not found (secrets scanning disabled)")
  [[ "$SLOP_ENABLE_SEMGREP" == "1" ]] && ! need_cmd semgrep && warnings+=("semgrep not found (SAST disabled)")
  
  # Report missing required tools
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}ERROR: Missing required tools:${NC}" >&2
    for tool in "${missing[@]}"; do
      echo "  - $tool" >&2
    done
    echo "" >&2
    echo "Run with SLOP_BOOTSTRAP=1 as root to auto-install, or install manually." >&2
    exit 1
  fi
  
  # Report warnings
  if [[ ${#warnings[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Warnings:${NC}" >&2
    for w in "${warnings[@]}"; do
      echo "  - $w" >&2
    done
    echo "" >&2
  fi
}

########################################
# LLM Response Caching
# Hash content, cache results to avoid re-calling LLMs
########################################
SLOP_CACHE_DIR="${SLOP_CACHE_DIR:-}"  # Set to enable caching
SLOP_CACHE_TTL="${SLOP_CACHE_TTL:-86400}"  # 24 hours default

cache_key() {
  local content="$1"
  local model="$2"
  echo -n "${content}${model}" | sha256sum | cut -d' ' -f1
}

cache_get() {
  [[ -z "$SLOP_CACHE_DIR" ]] && return 1
  local key="$1"
  local cache_file="$SLOP_CACHE_DIR/$key.json"
  
  if [[ -f "$cache_file" ]]; then
    # Check TTL
    local file_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo 0)))
    if [[ $file_age -lt $SLOP_CACHE_TTL ]]; then
      cat "$cache_file"
      return 0
    fi
  fi
  return 1
}

cache_set() {
  [[ -z "$SLOP_CACHE_DIR" ]] && return 0
  local key="$1"
  local value="$2"
  
  mkdir -p "$SLOP_CACHE_DIR"
  echo "$value" > "$SLOP_CACHE_DIR/$key.json"
}

bootstrap() {
  [[ "$SLOP_BOOTSTRAP" == "1" ]] || return 0
  
  say "Bootstrapping dependencies..."

  # Core tools
  if [[ "$(id -u)" == "0" ]]; then
    apt-get update -qq >/dev/null 2>&1
    apt_install ca-certificates curl jq git ripgrep python3 python3-pip coreutils findutils gawk parallel graphviz

    # fd-find
    if ! need_cmd fd && ! need_cmd fdfind; then
      apt_install fd-find
      need_cmd fdfind && ln -sf "$(which fdfind)" /usr/local/bin/fd
    fi

    # Node.js
    if ! need_cmd node; then
      curl -fsSL https://deb.nodesource.com/setup_20.x 2>/dev/null | bash - >/dev/null 2>&1
      apt_install nodejs
    fi
  fi

  # Python tools
  if [[ "$SLOP_ENABLE_RUFF" == "1" ]] && ! need_cmd ruff; then
    pip_install ruff
  fi
  
  if [[ "$SLOP_ENABLE_BANDIT" == "1" ]] && ! need_cmd bandit; then
    pip_install bandit
  fi
  
  if [[ "$SLOP_ENABLE_VULTURE" == "1" ]] && ! need_cmd vulture; then
    pip_install vulture
  fi
  
  if [[ "$SLOP_ENABLE_SEMGREP" == "1" ]] && ! need_cmd semgrep; then
    pip_install semgrep
  fi

  # Node tools
  if need_cmd npm; then
    if [[ "$SLOP_ENABLE_BIOME" == "1" ]] && ! need_cmd biome; then
      npm_install_global @biomejs/biome
    fi
    
    if [[ "$SLOP_ENABLE_KNIP" == "1" ]] && ! need_cmd knip; then
      npm_install_global knip
    fi
    
    if [[ "$SLOP_ENABLE_DEPCRUISE" == "1" ]] && ! need_cmd depcruise; then
      npm_install_global dependency-cruiser
    fi
  fi

  # Rust tools (via cargo or prebuilt)
  if [[ "$SLOP_ENABLE_GITLEAKS" == "1" ]] && ! need_cmd gitleaks; then
    if need_cmd brew; then
      brew install gitleaks >/dev/null 2>&1 || true
    elif [[ "$(id -u)" == "0" ]]; then
      curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz 2>/dev/null | tar -xz -C /usr/local/bin gitleaks 2>/dev/null || true
    fi
  fi

  if [[ "$SLOP_ENABLE_LYCHEE" == "1" ]] && ! need_cmd lychee; then
    if need_cmd cargo; then
      cargo install lychee >/dev/null 2>&1 || true
    fi
  fi

  if [[ "$SLOP_ENABLE_TYPOS" == "1" ]] && ! need_cmd typos; then
    if need_cmd cargo; then
      cargo install typos-cli >/dev/null 2>&1 || true
    fi
  fi

  if [[ "$SLOP_ENABLE_ACTIONLINT" == "1" ]] && ! need_cmd actionlint; then
    if [[ "$(id -u)" == "0" ]]; then
      curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash 2>/dev/null | bash -s -- -b /usr/local/bin 2>/dev/null || true
    fi
  fi

  if [[ "$SLOP_ENABLE_GITSIZER" == "1" ]] && ! need_cmd git-sizer; then
    if need_cmd brew; then
      brew install git-sizer >/dev/null 2>&1 || true
    fi
  fi

  if [[ "$SLOP_ENABLE_OSV" == "1" ]] && ! need_cmd osv-scanner; then
    if need_cmd go; then
      go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null || true
    fi
  fi

  say "Bootstrap complete"
}

########################################
# Smart Auth Detection
########################################
detect_claude_auth() {
  say "Detecting Claude authentication..."

  local root
  root="$(repo_root)"

  if need_cmd claude; then
    if claude --version >/dev/null 2>&1; then
      CLAUDE_AUTH_METHOD="claude-code"
      say "  ✓ Claude Code CLI available"
      return 0
    fi
  fi

  if [[ -n "$SLOP_CLAUDE_API_KEY" ]]; then
    CLAUDE_AUTH_METHOD="api-key"
    say "  ✓ Using SLOP_CLAUDE_API_KEY from environment"
    return 0
  fi

  if [[ -f "$root/$GATEKEEPER_ENV" ]]; then
    local key
    key=$(grep -E '^CLAUDE_API_TOKEN=' "$root/$GATEKEEPER_ENV" 2>/dev/null | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    if [[ -n "$key" ]]; then
      SLOP_CLAUDE_API_KEY="$key"
      CLAUDE_AUTH_METHOD="gatekeeper-env"
      say "  ✓ Using CLAUDE_API_TOKEN from $GATEKEEPER_ENV"
      return 0
    fi
    key=$(grep -E '^ANTHROPIC_API_KEY=' "$root/$GATEKEEPER_ENV" 2>/dev/null | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    if [[ -n "$key" ]]; then
      SLOP_CLAUDE_API_KEY="$key"
      CLAUDE_AUTH_METHOD="gatekeeper-env"
      say "  ✓ Using ANTHROPIC_API_KEY from $GATEKEEPER_ENV"
      return 0
    fi
  fi

  CLAUDE_AUTH_METHOD=""
  warn "  ✗ No Claude authentication found"
  return 1
}

detect_vertex_auth() {
  say "Detecting Vertex AI authentication..."

  local root
  root="$(repo_root)"

  if need_cmd gcloud; then
    local token
    token=$(gcloud auth application-default print-access-token 2>/dev/null) || token=""
    
    if [[ -n "$token" ]] && [[ "$token" != *"error"* ]]; then
      VERTEX_ACCESS_TOKEN="$token"
      VERTEX_AUTH_METHOD="adc"
      
      if [[ -z "$SLOP_GCP_PROJECT" ]]; then
        SLOP_GCP_PROJECT=$(gcloud config get-value project 2>/dev/null) || SLOP_GCP_PROJECT=""
      fi
      
      if [[ -n "$SLOP_GCP_PROJECT" ]]; then
        say "  ✓ Using Application Default Credentials (project: $SLOP_GCP_PROJECT)"
        return 0
      fi
    fi
  fi

  if [[ -f "$root/$GATEKEEPER_VERTEX_KEY" ]]; then
    if jq -e '.type == "service_account"' "$root/$GATEKEEPER_VERTEX_KEY" >/dev/null 2>&1; then
      if [[ -z "$SLOP_GCP_PROJECT" ]]; then
        SLOP_GCP_PROJECT=$(jq -r '.project_id // ""' "$root/$GATEKEEPER_VERTEX_KEY" 2>/dev/null)
      fi

      if need_cmd gcloud; then
        if gcloud auth activate-service-account --key-file="$root/$GATEKEEPER_VERTEX_KEY" >/dev/null 2>&1; then
          VERTEX_ACCESS_TOKEN=$(gcloud auth print-access-token 2>/dev/null) || VERTEX_ACCESS_TOKEN=""
          
          if [[ -n "$VERTEX_ACCESS_TOKEN" ]] && [[ -n "$SLOP_GCP_PROJECT" ]]; then
            VERTEX_AUTH_METHOD="service-account"
            say "  ✓ Using service account from $GATEKEEPER_VERTEX_KEY"
            return 0
          fi
        fi
      fi
    fi
  fi

  VERTEX_AUTH_METHOD=""
  warn "  ✗ No Vertex AI authentication found"
  return 1
}

detect_all_auth() {
  say "Detecting available authentication methods..."
  echo ""
  
  if [[ "$SLOP_ENABLE_CLAUDE" == "1" ]]; then
    detect_claude_auth || true
  fi
  
  if [[ "$SLOP_ENABLE_GEMINI" == "1" ]]; then
    detect_vertex_auth || true
  fi
  
  echo ""
  
  if [[ -z "$CLAUDE_AUTH_METHOD" ]]; then
    SLOP_ENABLE_CLAUDE=0
  fi
  
  if [[ -z "$VERTEX_AUTH_METHOD" ]]; then
    SLOP_ENABLE_GEMINI=0
  fi
  
  if [[ "$SLOP_ENABLE_CLAUDE" == "0" ]] && [[ "$SLOP_ENABLE_GEMINI" == "0" ]]; then
    warn "No LLM authentication available. Running tool scans only."
    SLOP_ENABLE_PLAN=0
  fi
}

########################################
# Issue JSONL emission
########################################
emit_issue() {
  local source="$1" category="$2" severity="$3" file="$4" line="$5" 
  local title="$6" evidence="$7" why="$8" confidence="$9" fix="${10:-}"
  
  # Redact secrets from evidence if enabled
  if [[ "$SLOP_REDACT_SECRETS" == "1" ]]; then
    evidence=$(redact_secrets "$evidence")
  fi
  
  # Fast JSON escaping in pure bash (avoids spawning jq for every issue)
  # This is ~100x faster than calling jq for every line
  # Escape backslashes first, then quotes, then newlines
  title=${title//\\/\\\\}
  title=${title//\"/\\\"}
  title=${title//$'\n'/\\n}
  title=${title//$'\r'/}
  title=${title//$'\t'/\\t}
  
  evidence=${evidence//\\/\\\\}
  evidence=${evidence//\"/\\\"}
  evidence=${evidence//$'\n'/\\n}
  evidence=${evidence//$'\r'/}
  evidence=${evidence//$'\t'/\\t}
  
  why=${why//\\/\\\\}
  why=${why//\"/\\\"}
  why=${why//$'\n'/\\n}
  why=${why//$'\r'/}
  why=${why//$'\t'/\\t}
  
  fix=${fix//\\/\\\\}
  fix=${fix//\"/\\\"}
  fix=${fix//$'\n'/\\n}
  fix=${fix//$'\r'/}
  fix=${fix//$'\t'/\\t}
  
  file=${file//\\/\\\\}
  file=${file//\"/\\\"}
  
  # Validate numeric fields (default to safe values if invalid)
  [[ "$line" =~ ^[0-9]+$ ]] || line=1
  [[ "$confidence" =~ ^[0-9.]+$ ]] || confidence="0.5"
  
  # Append directly to file using printf (fast!)
  printf '{"source":"%s","category":"%s","severity":"%s","file":"%s","line":%s,"title":"%s","evidence":"%s","why":"%s","confidence":%s,"fix":"%s"}\n' \
    "$source" "$category" "$severity" "$file" "$line" "$title" "$evidence" "$why" "$confidence" "$fix" >> "$ISSUES_JSONL"
}

########################################
# SECRET REDACTION (don't create new security incidents)
########################################
redact_secrets() {
  local text="$1"
  
  # Common secret patterns to redact
  # API keys, tokens, passwords, private keys
  echo "$text" | sed \
    -e 's/\(api[_-]*key["\x27]*[[:space:]]*[:=][[:space:]]*["\x27]*\)[^"\x27[:space:]]*/\1[REDACTED]/gi' \
    -e 's/\(secret[_-]*key["\x27]*[[:space:]]*[:=][[:space:]]*["\x27]*\)[^"\x27[:space:]]*/\1[REDACTED]/gi' \
    -e 's/\(password["\x27]*[[:space:]]*[:=][[:space:]]*["\x27]*\)[^"\x27[:space:]]*/\1[REDACTED]/gi' \
    -e 's/\(token["\x27]*[[:space:]]*[:=][[:space:]]*["\x27]*\)[^"\x27[:space:]]*/\1[REDACTED]/gi' \
    -e 's/\(auth[_-]*token["\x27]*[[:space:]]*[:=][[:space:]]*["\x27]*\)[^"\x27[:space:]]*/\1[REDACTED]/gi' \
    -e 's/sk-[a-zA-Z0-9]\{20,\}/sk-[REDACTED]/g' \
    -e 's/sk_live_[a-zA-Z0-9]\{20,\}/sk_live_[REDACTED]/g' \
    -e 's/sk_test_[a-zA-Z0-9]\{20,\}/sk_test_[REDACTED]/g' \
    -e 's/ghp_[a-zA-Z0-9]\{36,\}/ghp_[REDACTED]/g' \
    -e 's/gho_[a-zA-Z0-9]\{36,\}/gho_[REDACTED]/g' \
    -e 's/AKIA[A-Z0-9]\{16\}/AKIA[REDACTED]/g' \
    -e 's/-----BEGIN.*PRIVATE KEY-----/[PRIVATE_KEY_REDACTED]/g' \
    -e 's/eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/[JWT_REDACTED]/g'
}

########################################
# GOLDRECORD CONTRACT VALIDATION (v2)
# Supports both simple format and GPT's rigorous format
########################################
validate_goldrecord() {
  say "Validating goldrecord contract..."
  local root
  root="$(repo_root)"
  
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  
  if [[ ! -f "$goldrecord_file" ]]; then
    if [[ "$SLOP_REQUIRE_GOLDRECORD" == "1" ]] || [[ "$SLOP_CERTIFY_MODE" == "1" ]]; then
      emit_issue "local/goldrecord" "contract" "blocker" "$SLOP_GOLDRECORD_FILE" 1 \
        "Missing goldrecord.yaml contract" "No goldrecord.yaml found" \
        "Release certification requires a goldrecord.yaml defining what 'done' means" 0.99 \
        "Run './slop-scanner-ultimate.sh --init' to generate one"
      return 1
    fi
    return 0
  fi
  
  say "  Found goldrecord.yaml, validating structure..."
  
  # Parse and validate goldrecord.yaml - supports both v1 (GPT) and simple format
  python3 - "$goldrecord_file" "$ISSUES_JSONL" "$root" <<'PYTHON'
import sys
import json
import os
import re
import subprocess
from pathlib import Path

goldrecord_file = sys.argv[1]
issues_file = sys.argv[2]
repo_root = sys.argv[3]

def emit(sev, title, evidence, why, conf, fix, file=None, line=1):
    issue = {
        "source": "local/goldrecord",
        "category": "contract",
        "severity": sev,
        "file": file or goldrecord_file,
        "line": line,
        "title": title,
        "evidence": str(evidence)[:300],
        "why": why,
        "confidence": conf,
        "fix": fix
    }
    with open(issues_file, 'a') as f:
        f.write(json.dumps(issue) + '\n')

try:
    import yaml
    with open(goldrecord_file, 'r') as f:
        contract = yaml.safe_load(f) or {}
except ImportError:
    emit("high", "PyYAML not installed", "Cannot parse YAML without PyYAML",
         "Install PyYAML for full contract validation", 0.8,
         "pip install pyyaml")
    contract = {}
except Exception as e:
    emit("blocker", "Invalid goldrecord.yaml", str(e),
         "Cannot parse goldrecord.yaml contract", 0.99,
         "Fix YAML syntax errors")
    sys.exit(1)

# Detect contract version
is_v2 = 'version' in contract or 'repo' in contract or 'commands' in contract
contract_version = contract.get('version', 1 if is_v2 else 0)

print(f"  Contract format: {'v2 (rigorous)' if is_v2 else 'v1 (simple)'}")

# ═══════════════════════════════════════════════════════════════════════════════
# V2 CONTRACT VALIDATION (GPT's rigorous format)
# ═══════════════════════════════════════════════════════════════════════════════
if is_v2:
    # === REPO SECTION ===
    repo = contract.get('repo', {})
    if not repo:
        emit("high", "Missing 'repo' section", "Contract should define repo metadata",
             "Repo metadata helps identify and validate the project", 0.85,
             "Add repo: section with name, description, owners")
    else:
        if not repo.get('name'):
            emit("high", "Missing repo.name", "repo.name is required",
                 "Project name is needed for identification", 0.8, "Add repo.name")
        if not repo.get('owners'):
            emit("medium", "No repo.owners", "repo.owners is empty",
                 "Ownership helps accountability", 0.7, "Add repo.owners list")
    
    # === RELEASE SECTION ===
    release = contract.get('release', {})
    if release.get('require_git_clean', False):
        # Check for uncommitted changes
        try:
            result = subprocess.run(['git', 'status', '--porcelain'], 
                                    capture_output=True, text=True, cwd=repo_root)
            if result.stdout.strip():
                emit("blocker", "Git working directory not clean",
                     f"Uncommitted changes: {result.stdout[:100]}",
                     "Contract requires git clean state for release", 0.95,
                     "Commit or stash all changes before release")
        except:
            pass
    
    if release.get('require_tag_regex'):
        tag_regex = release['require_tag_regex']
        try:
            result = subprocess.run(['git', 'describe', '--tags', '--exact-match', 'HEAD'],
                                    capture_output=True, text=True, cwd=repo_root)
            tag = result.stdout.strip()
            if not tag:
                emit("blocker", "No git tag on HEAD", "HEAD is not tagged",
                     "Contract requires a version tag for release", 0.9,
                     f"Create tag matching: {tag_regex}")
            elif not re.match(tag_regex, tag):
                emit("blocker", f"Git tag doesn't match pattern",
                     f"Tag '{tag}' doesn't match '{tag_regex}'",
                     "Tag must match required pattern", 0.95,
                     f"Create tag matching: {tag_regex}")
        except:
            pass
    
    # === COMMANDS SECTION (validate commands exist) ===
    commands = contract.get('commands', {})
    for cmd_type in ['build', 'lint', 'typecheck', 'unit_tests']:
        cmd_list = commands.get(cmd_type, [])
        if not cmd_list:
            emit("high", f"No {cmd_type} commands defined",
                 f"commands.{cmd_type} is empty",
                 f"Contract should define {cmd_type} commands", 0.8,
                 f"Add commands.{cmd_type} with at least one command")
    
    # === QUALITY SECTION ===
    quality = contract.get('quality', {})
    
    # Coverage thresholds
    cov_thresholds = quality.get('coverage_thresholds', {})
    if cov_thresholds:
        for metric, threshold in cov_thresholds.items():
            if threshold < 50:
                emit("high", f"Low {metric} coverage threshold: {threshold}%",
                     f"coverage_thresholds.{metric} = {threshold}",
                     "Coverage below 50% indicates insufficient testing", 0.8,
                     f"Set coverage_thresholds.{metric} to at least 70")
    
    # Placeholder policy - validate patterns compile
    placeholder_policy = quality.get('placeholder_policy', {})
    forbid_patterns = placeholder_policy.get('forbid_patterns', [])
    for pattern in forbid_patterns:
        try:
            re.compile(pattern)
        except re.error as e:
            emit("blocker", f"Invalid placeholder regex: {pattern}",
                 str(e), "Regex pattern doesn't compile", 0.95,
                 "Fix the regex pattern syntax")
    
    # === PRODUCT SECTION ===
    product = contract.get('product', {})
    
    # User flows
    user_flows = product.get('user_flows', [])
    if not user_flows:
        emit("blocker", "No user_flows defined",
             "product.user_flows is empty",
             "Contract must define user journeys to verify", 0.95,
             "Add product.user_flows with at least core functionality")
    
    for flow in user_flows:
        flow_id = flow.get('id', 'unknown')
        
        # Test requirements
        test_reqs = flow.get('test_requirements', {})
        e2e = test_reqs.get('e2e', {})
        if e2e.get('required') and not e2e.get('test_id'):
            emit("high", f"Flow {flow_id}: e2e required but no test_id",
                 "test_requirements.e2e.required=true but test_id missing",
                 "Cannot verify flow without test identifier", 0.85,
                 f"Add test_requirements.e2e.test_id to flow {flow_id}")
        
        # Code anchors - verify files exist
        code_anchors = flow.get('code_anchors', [])
        for anchor in code_anchors:
            # Simple glob check
            anchor_path = os.path.join(repo_root, anchor.replace('**/', '').replace('*', ''))
            parent = os.path.dirname(anchor_path)
            if parent and not os.path.exists(parent):
                emit("medium", f"Code anchor path doesn't exist: {anchor}",
                     f"Flow {flow_id} references non-existent path",
                     "Code anchors should point to real code", 0.7,
                     f"Update code_anchors in flow {flow_id}")
    
    # Features
    features = product.get('features', [])
    for feature in features:
        feat_id = feature.get('id', 'unknown')
        if feature.get('must_have') and not feature.get('code_anchors'):
            emit("high", f"Feature {feat_id}: must_have but no code_anchors",
                 "must_have=true but code_anchors missing",
                 "Cannot trace feature to implementation", 0.8,
                 f"Add code_anchors to feature {feat_id}")
    
    # API
    api = product.get('api', {})
    openapi = api.get('openapi', {})
    if openapi.get('required'):
        spec_path = openapi.get('spec_path', '')
        if spec_path and not os.path.exists(os.path.join(repo_root, spec_path)):
            emit("blocker", f"OpenAPI spec not found: {spec_path}",
                 f"product.api.openapi.spec_path = '{spec_path}' but file missing",
                 "Contract requires OpenAPI spec but it doesn't exist", 0.95,
                 f"Create OpenAPI spec at {spec_path}")
    
    # === OPS SECTION ===
    ops = contract.get('ops', {})
    health = ops.get('health', {})
    if health.get('required') and not health.get('url'):
        emit("high", "Health check required but no URL",
             "ops.health.required=true but url missing",
             "Cannot verify health without endpoint", 0.85,
             "Add ops.health.url")
    
    # === DOCS SECTION ===
    docs = contract.get('docs', {})
    required_files = docs.get('required_files', [])
    for doc_path in required_files:
        full_path = os.path.join(repo_root, doc_path)
        if not os.path.exists(full_path):
            emit("high", f"Required doc missing: {doc_path}",
                 f"docs.required_files includes '{doc_path}' but not found",
                 "Contract requires this documentation", 0.9,
                 f"Create {doc_path}")
    
    # Gate settings
    gate = contract.get('gate', {})
    print(f"  Gate settings: strict_discovery={gate.get('strict_discovery', False)}, fail_on_warnings={gate.get('fail_on_warnings', True)}")

# ═══════════════════════════════════════════════════════════════════════════════
# V1 CONTRACT VALIDATION (Simple format - backward compatible)
# ═══════════════════════════════════════════════════════════════════════════════
else:
    # Simple format validation
    required_fields = ['app_type', 'user_flows']
    recommended_fields = ['api_contract', 'test_coverage', 'docs_contract']
    
    for field in required_fields:
        if field not in contract:
            emit("blocker", f"Missing required field: {field}",
                 f"goldrecord.yaml must define '{field}'",
                 f"Contract is underspecified without {field}",
                 0.95, f"Add '{field}:' section to goldrecord.yaml")
    
    for field in recommended_fields:
        if field not in contract:
            emit("high", f"Missing recommended field: {field}",
                 f"goldrecord.yaml should define '{field}'",
                 f"Good contracts include {field}",
                 0.8, f"Add '{field}:' section to goldrecord.yaml")
    
    user_flows = contract.get('user_flows', [])
    if not user_flows:
        emit("blocker", "No user flows defined",
             "user_flows is empty or missing",
             "Contract must specify at least one user flow to verify",
             0.95, "Add user flows with: id, name, preconditions, steps")
    
    for i, flow in enumerate(user_flows):
        if not isinstance(flow, dict):
            continue
        for ff in ['id', 'name', 'steps']:
            if ff not in flow:
                emit("high", f"User flow {i+1} missing '{ff}'",
                     f"Flow is incomplete without {ff}",
                     "Each user flow needs id, name, and steps",
                     0.85, f"Add '{ff}' to user flow {i+1}")

# Summary
if is_v2:
    flows = contract.get('product', {}).get('user_flows', [])
    features = contract.get('product', {}).get('features', [])
    cmds = sum(len(v) for v in contract.get('commands', {}).values())
    print(f"  Validated: {len(flows)} flows, {len(features)} features, {cmds} commands")
else:
    flows = contract.get('user_flows', [])
    print(f"  Validated: {len(flows)} user flows")
PYTHON
}

########################################
# EXECUTE CONTRACT COMMANDS
########################################
execute_contract_commands() {
  local cmd_type="$1"  # build, lint, typecheck, unit_tests, etc.
  
  say "Executing contract commands: $cmd_type"
  local root
  root="$(repo_root)"
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  
  [[ -f "$goldrecord_file" ]] || return 0
  
  python3 - "$goldrecord_file" "$cmd_type" "$root" "$ISSUES_JSONL" "$WORKDIR" <<'PYTHON'
import sys
import json
import subprocess
import os
import time
import re

goldrecord_file = sys.argv[1]
cmd_type = sys.argv[2]
repo_root = sys.argv[3]
issues_file = sys.argv[4]
workdir = sys.argv[5]

def emit(sev, title, evidence, why, conf, fix, file=None):
    issue = {
        "source": "local/contract-cmd",
        "category": "contract",
        "severity": sev,
        "file": file or goldrecord_file,
        "line": 1,
        "title": title,
        "evidence": str(evidence)[:500],
        "why": why,
        "confidence": conf,
        "fix": fix
    }
    with open(issues_file, 'a') as f:
        f.write(json.dumps(issue) + '\n')

try:
    import yaml
    with open(goldrecord_file, 'r') as f:
        contract = yaml.safe_load(f) or {}
except:
    print(f"  Cannot parse contract for command execution")
    sys.exit(0)

# Check if this is v2 format
if 'commands' not in contract:
    print(f"  No commands section in contract (v1 format)")
    sys.exit(0)

commands = contract.get('commands', {}).get(cmd_type, [])
if not commands:
    print(f"  No {cmd_type} commands defined")
    sys.exit(0)

print(f"  Running {len(commands)} {cmd_type} command(s)...")

# Evidence directory
evidence_dir = os.path.join(workdir, 'cmd_evidence')
os.makedirs(evidence_dir, exist_ok=True)

for cmd_def in commands:
    cmd_id = cmd_def.get('id', 'UNKNOWN')
    cmd_name = cmd_def.get('name', cmd_type)
    cmd = cmd_def.get('cmd', '')
    cwd = cmd_def.get('cwd', './')
    timeout = cmd_def.get('timeout_seconds', 600)
    
    if not cmd:
        continue
    
    full_cwd = os.path.join(repo_root, cwd)
    print(f"    [{cmd_id}] {cmd_name}: {cmd}")
    
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=full_cwd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        elapsed = time.time() - start
        
        # Save evidence
        evidence_file = os.path.join(evidence_dir, f"{cmd_id}.log")
        with open(evidence_file, 'w') as f:
            f.write(f"=== {cmd_id}: {cmd_name} ===\n")
            f.write(f"Command: {cmd}\n")
            f.write(f"CWD: {full_cwd}\n")
            f.write(f"Exit code: {result.returncode}\n")
            f.write(f"Duration: {elapsed:.2f}s\n")
            f.write(f"\n=== STDOUT ===\n{result.stdout}\n")
            f.write(f"\n=== STDERR ===\n{result.stderr}\n")
        
        if result.returncode != 0:
            # Command failed
            emit("blocker", f"Contract command failed: {cmd_id}",
                 f"{cmd}\nExit: {result.returncode}\n{result.stderr[-300:]}",
                 f"{cmd_name} failed - contract violation",
                 0.95, f"Fix issues in {cmd_name} to pass contract")
            print(f"    ✗ FAILED (exit {result.returncode})")
        else:
            print(f"    ✓ passed ({elapsed:.1f}s)")
            
            # Parse coverage if specified
            parse_def = cmd_def.get('parse', {})
            if parse_def.get('kind') == 'regex':
                pattern = parse_def.get('pattern', '')
                match = re.search(pattern, result.stdout)
                if match:
                    groups = match.groupdict()
                    for key, value in groups.items():
                        print(f"      Parsed {key}: {value}")
                        # Store for threshold checking
                        parsed_file = os.path.join(workdir, 'parsed_values.json')
                        try:
                            with open(parsed_file, 'r') as f:
                                parsed = json.load(f)
                        except:
                            parsed = {}
                        parsed[f"{cmd_id}.{key}"] = float(value) if value else 0
                        with open(parsed_file, 'w') as f:
                            json.dump(parsed, f)
                            
    except subprocess.TimeoutExpired:
        emit("blocker", f"Contract command timed out: {cmd_id}",
             f"{cmd}\nTimeout after {timeout}s",
             "Command exceeded allowed time", 0.95,
             f"Optimize {cmd_name} or increase timeout")
        print(f"    ✗ TIMEOUT ({timeout}s)")
    except Exception as e:
        emit("blocker", f"Contract command error: {cmd_id}",
             str(e), "Command execution failed", 0.9,
             "Check command syntax and dependencies")
        print(f"    ✗ ERROR: {e}")

print(f"  {cmd_type} commands complete")
PYTHON
}

########################################
# PLACEHOLDER POLICY ENFORCEMENT
########################################
enforce_placeholder_policy() {
  say "Enforcing placeholder policy..."
  local root
  root="$(repo_root)"
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  
  [[ -f "$goldrecord_file" ]] || return 0
  
  python3 - "$goldrecord_file" "$root" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json
import os
import re
from pathlib import Path

goldrecord_file = sys.argv[1]
repo_root = sys.argv[2]
issues_file = sys.argv[3]

def emit(sev, title, evidence, why, conf, fix, file, line=1):
    issue = {
        "source": "local/placeholder-policy",
        "category": "contract",
        "severity": sev,
        "file": file,
        "line": line,
        "title": title,
        "evidence": str(evidence)[:200],
        "why": why,
        "confidence": conf,
        "fix": fix
    }
    with open(issues_file, 'a') as f:
        f.write(json.dumps(issue) + '\n')

try:
    import yaml
    with open(goldrecord_file, 'r') as f:
        contract = yaml.safe_load(f) or {}
except:
    sys.exit(0)

quality = contract.get('quality', {})
policy = quality.get('placeholder_policy', {})

if not policy:
    sys.exit(0)

forbid_patterns = policy.get('forbid_patterns', [])
ignore_paths = policy.get('ignore_paths', [])
allowlist_file = policy.get('allowlist_file', '')

if not forbid_patterns:
    sys.exit(0)

# Load allowlist if exists
allowlist = []
if allowlist_file:
    allowlist_path = os.path.join(repo_root, allowlist_file)
    if os.path.exists(allowlist_path):
        with open(allowlist_path, 'r') as f:
            allowlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Compile patterns
compiled_forbid = []
for p in forbid_patterns:
    try:
        compiled_forbid.append((p, re.compile(p, re.IGNORECASE)))
    except:
        pass

compiled_ignore = []
for p in ignore_paths:
    # Convert glob to regex
    regex = p.replace('**/', '.*').replace('*', '[^/]*')
    try:
        compiled_ignore.append(re.compile(regex))
    except:
        pass

def should_ignore(path):
    for pattern in compiled_ignore:
        if pattern.search(path):
            return True
    return False

def is_allowlisted(line, filepath):
    for pattern in allowlist:
        try:
            if re.search(pattern, line) or re.search(pattern, filepath):
                return True
        except:
            pass
    return False

# Scan files
violations = 0
max_violations = 50

for root_dir, dirs, files in os.walk(repo_root):
    # Skip common non-source directories
    dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'dist', 'build']]
    
    for filename in files:
        if violations >= max_violations:
            break
            
        # Only check source files
        if not any(filename.endswith(ext) for ext in ['.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.rs', '.java', '.rb', '.md']):
            continue
        
        filepath = os.path.join(root_dir, filename)
        relpath = os.path.relpath(filepath, repo_root)
        
        if should_ignore(relpath):
            continue
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if violations >= max_violations:
                        break
                    
                    for pattern_str, pattern in compiled_forbid:
                        if pattern.search(line):
                            if not is_allowlisted(line, relpath):
                                emit("blocker", f"Forbidden placeholder: {pattern_str}",
                                     line.strip()[:100],
                                     "Contract placeholder policy violation",
                                     0.95, f"Remove or allowlist this placeholder",
                                     relpath, line_num)
                                violations += 1
                                break
        except:
            pass

if violations > 0:
    print(f"  Found {violations} placeholder policy violations")
else:
    print(f"  No placeholder policy violations")
PYTHON
}

########################################
# TEST INTEGRITY CHECKS
########################################
check_test_integrity() {
  say "Checking test integrity..."
  local root
  root="$(repo_root)"
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  
  [[ -f "$goldrecord_file" ]] || return 0
  
  python3 - "$goldrecord_file" "$root" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json
import os
import re

goldrecord_file = sys.argv[1]
repo_root = sys.argv[2]
issues_file = sys.argv[3]

def emit(sev, title, evidence, why, conf, fix, file, line=1):
    issue = {
        "source": "local/test-integrity",
        "category": "test-coverage",
        "severity": sev,
        "file": file,
        "line": line,
        "title": title,
        "evidence": str(evidence)[:200],
        "why": why,
        "confidence": conf,
        "fix": fix
    }
    with open(issues_file, 'a') as f:
        f.write(json.dumps(issue) + '\n')

try:
    import yaml
    with open(goldrecord_file, 'r') as f:
        contract = yaml.safe_load(f) or {}
except:
    sys.exit(0)

quality = contract.get('quality', {})
integrity = quality.get('test_integrity', {})

forbid_skip = integrity.get('forbid_skip_tokens', False)
forbid_only = integrity.get('forbid_only_tokens', False)
forbid_trivial = integrity.get('forbid_trivial_assertions', False)

if not any([forbid_skip, forbid_only, forbid_trivial]):
    sys.exit(0)

# Patterns to detect
skip_patterns = [
    (r'\.skip\s*\(', '.skip()'),
    (r'@pytest\.mark\.skip', '@pytest.mark.skip'),
    (r'@unittest\.skip', '@unittest.skip'),
    (r'it\.skip\s*\(', 'it.skip()'),
    (r'test\.skip\s*\(', 'test.skip()'),
    (r'xdescribe\s*\(', 'xdescribe()'),
    (r'xit\s*\(', 'xit()'),
]

only_patterns = [
    (r'\.only\s*\(', '.only()'),
    (r'it\.only\s*\(', 'it.only()'),
    (r'test\.only\s*\(', 'test.only()'),
    (r'describe\.only\s*\(', 'describe.only()'),
    (r'fdescribe\s*\(', 'fdescribe()'),
    (r'fit\s*\(', 'fit()'),
]

trivial_patterns = [
    (r'expect\s*\(\s*true\s*\)\s*\.\s*toBe\s*\(\s*true\s*\)', 'expect(true).toBe(true)'),
    (r'assert\s+True\s*$', 'assert True'),
    (r'expect\s*\(\s*1\s*\)\s*\.\s*toBe\s*\(\s*1\s*\)', 'expect(1).toBe(1)'),
    (r'assertEquals\s*\(\s*1\s*,\s*1\s*\)', 'assertEquals(1, 1)'),
]

violations = 0
max_violations = 30

for root_dir, dirs, files in os.walk(repo_root):
    dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor', '__pycache__']]
    
    for filename in files:
        if violations >= max_violations:
            break
            
        # Only check test files
        if not any(x in filename.lower() for x in ['test', 'spec']):
            continue
        if not filename.endswith(('.ts', '.tsx', '.js', '.jsx', '.py')):
            continue
        
        filepath = os.path.join(root_dir, filename)
        relpath = os.path.relpath(filepath, repo_root)
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    if violations >= max_violations:
                        break
                    
                    if forbid_skip:
                        for pattern, name in skip_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                emit("blocker", f"Skipped test: {name}",
                                     line.strip()[:100],
                                     "Contract forbids skipped tests",
                                     0.95, "Remove skip or fix the test",
                                     relpath, line_num)
                                violations += 1
                                break
                    
                    if forbid_only:
                        for pattern, name in only_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                emit("blocker", f"Exclusive test: {name}",
                                     line.strip()[:100],
                                     "Contract forbids .only() tests",
                                     0.95, "Remove .only() before release",
                                     relpath, line_num)
                                violations += 1
                                break
                    
                    if forbid_trivial:
                        for pattern, name in trivial_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                emit("high", f"Trivial assertion: {name}",
                                     line.strip()[:100],
                                     "Contract forbids trivial assertions",
                                     0.85, "Replace with meaningful assertion",
                                     relpath, line_num)
                                violations += 1
                                break
        except:
            pass

if violations > 0:
    print(f"  Found {violations} test integrity violations")
else:
    print(f"  Test integrity checks passed")
PYTHON
}

########################################
# GENERATE ATTESTATION
########################################
generate_attestation() {
  [[ "$SLOP_CERTIFY_MODE" == "1" ]] || return 0
  
  say "Generating release attestation..."
  local root
  root="$(repo_root)"
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  local ts
  ts="$(ts_utc)"
  
  python3 - "$goldrecord_file" "$root" "$WORKDIR" "$ISSUES_JSONL" "$ts" "$VERSION" <<'PYTHON'
import sys
import json
import os
import hashlib
import subprocess
from datetime import datetime

goldrecord_file = sys.argv[1]
repo_root = sys.argv[2]
workdir = sys.argv[3]
issues_file = sys.argv[4]
timestamp = sys.argv[5]
scanner_version = sys.argv[6]

# Count issues
blocker_count = 0
total_count = 0
try:
    with open(issues_file, 'r') as f:
        for line in f:
            total_count += 1
            if '"severity":"blocker"' in line:
                blocker_count += 1
except:
    pass

# Get git info
git_sha = "unknown"
git_branch = "unknown"
try:
    result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                           capture_output=True, text=True, cwd=repo_root)
    git_sha = result.stdout.strip()
    result = subprocess.run(['git', 'branch', '--show-current'],
                           capture_output=True, text=True, cwd=repo_root)
    git_branch = result.stdout.strip()
except:
    pass

# Hash evidence files
evidence_hashes = {}
evidence_dir = os.path.join(workdir, 'cmd_evidence')
if os.path.exists(evidence_dir):
    for filename in os.listdir(evidence_dir):
        filepath = os.path.join(evidence_dir, filename)
        if os.path.isfile(filepath):
            with open(filepath, 'rb') as f:
                evidence_hashes[filename] = hashlib.sha256(f.read()).hexdigest()

# Hash goldrecord
goldrecord_hash = ""
if os.path.exists(goldrecord_file):
    with open(goldrecord_file, 'rb') as f:
        goldrecord_hash = hashlib.sha256(f.read()).hexdigest()

# Create attestation
attestation = {
    "schema_version": "1.0",
    "scanner_version": scanner_version,
    "timestamp": datetime.utcnow().isoformat() + "Z",
    "repo": {
        "path": repo_root,
        "git_sha": git_sha,
        "git_branch": git_branch
    },
    "contract": {
        "path": goldrecord_file,
        "sha256": goldrecord_hash
    },
    "result": {
        "certified": blocker_count == 0,
        "total_issues": total_count,
        "blocker_count": blocker_count
    },
    "evidence": {
        "files": evidence_hashes
    }
}

# Write attestation
attestation_file = os.path.join(workdir, 'attestation.json')
with open(attestation_file, 'w') as f:
    json.dump(attestation, f, indent=2)

# Also write to repo if certified
if blocker_count == 0:
    evidence_dir = os.path.join(repo_root, '.goldrecord', 'evidence')
    os.makedirs(evidence_dir, exist_ok=True)
    output_file = os.path.join(evidence_dir, f'attestation-{timestamp}.json')
    with open(output_file, 'w') as f:
        json.dump(attestation, f, indent=2)
    print(f"  Attestation written to: {output_file}")
else:
    print(f"  Attestation generated (not certified - {blocker_count} blockers)")

print(f"  SHA: {git_sha[:12]}, Issues: {total_count}, Blockers: {blocker_count}")
PYTHON
}

########################################
# GOLDRECORD CONTRACT GENERATION (Auto-bootstrap)
########################################
generate_goldrecord_contract() {
  say "Generating goldrecord.yaml contract from repo analysis..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  local existing_contract=""
  
  # Check if regenerating
  if [[ "$SLOP_REGENERATE_CONTRACT" == "1" ]] && [[ -f "$goldrecord_file" ]]; then
    say "  Regenerating: will merge with existing contract"
    existing_contract=$(cat "$goldrecord_file")
  elif [[ -f "$goldrecord_file" ]] && [[ "$SLOP_REGENERATE_CONTRACT" != "1" ]]; then
    warn "goldrecord.yaml already exists. Use --regenerate-contract to update it."
    popd >/dev/null
    return 0
  fi
  
  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 1: Gather repo intelligence
  # ═══════════════════════════════════════════════════════════════════════════
  say "  Phase 1: Gathering repo intelligence..."
  
  local repo_intel="$WORKDIR/repo_intel.json"
  
  python3 - "$root" "$repo_intel" <<'PYTHON'
import sys
import os
import re
import json
from pathlib import Path

root = sys.argv[1]
output_file = sys.argv[2]

intel = {
    "app_type": "unknown",
    "name": "",
    "description": "",
    "frameworks": [],
    "routes": [],
    "endpoints": [],
    "components": [],
    "test_files": [],
    "env_vars": [],
    "integrations": [],
    "db_models": [],
    "readme_content": "",
    "package_scripts": {}
}

def read_file(path, max_lines=500):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[:max_lines]
            return ''.join(lines)
    except:
        return ""

# === Detect app type and name ===
if os.path.exists(os.path.join(root, 'package.json')):
    try:
        with open(os.path.join(root, 'package.json'), 'r') as f:
            pkg = json.load(f)
        intel['name'] = pkg.get('name', '')
        intel['description'] = pkg.get('description', '')
        intel['package_scripts'] = pkg.get('scripts', {})
        
        deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
        
        # Detect frameworks
        if 'next' in deps:
            intel['frameworks'].append('nextjs')
            intel['app_type'] = 'web'
        if 'react' in deps:
            intel['frameworks'].append('react')
            intel['app_type'] = 'web'
        if 'express' in deps:
            intel['frameworks'].append('express')
            intel['app_type'] = 'api'
        if 'fastify' in deps:
            intel['frameworks'].append('fastify')
            intel['app_type'] = 'api'
        if '@nestjs/core' in deps:
            intel['frameworks'].append('nestjs')
            intel['app_type'] = 'api'
        if 'electron' in deps:
            intel['frameworks'].append('electron')
            intel['app_type'] = 'desktop'
        if 'react-native' in deps:
            intel['frameworks'].append('react-native')
            intel['app_type'] = 'mobile'
        
        # Detect integrations
        if 'stripe' in deps:
            intel['integrations'].append({'name': 'stripe', 'type': 'payments'})
        if '@auth/core' in deps or 'next-auth' in deps:
            intel['integrations'].append({'name': 'next-auth', 'type': 'auth'})
        if '@prisma/client' in deps:
            intel['integrations'].append({'name': 'prisma', 'type': 'database'})
        if 'mongodb' in deps or 'mongoose' in deps:
            intel['integrations'].append({'name': 'mongodb', 'type': 'database'})
        if '@sendgrid/mail' in deps:
            intel['integrations'].append({'name': 'sendgrid', 'type': 'email'})
        if 'resend' in deps:
            intel['integrations'].append({'name': 'resend', 'type': 'email'})
        if '@aws-sdk' in str(deps):
            intel['integrations'].append({'name': 'aws', 'type': 'cloud'})
            
    except Exception as e:
        pass

elif os.path.exists(os.path.join(root, 'pyproject.toml')):
    intel['app_type'] = 'api'
    intel['frameworks'].append('python')
    content = read_file(os.path.join(root, 'pyproject.toml'))
    if 'fastapi' in content.lower():
        intel['frameworks'].append('fastapi')
    if 'django' in content.lower():
        intel['frameworks'].append('django')
        intel['app_type'] = 'web'
    if 'flask' in content.lower():
        intel['frameworks'].append('flask')

elif os.path.exists(os.path.join(root, 'Cargo.toml')):
    intel['app_type'] = 'cli'
    intel['frameworks'].append('rust')
    content = read_file(os.path.join(root, 'Cargo.toml'))
    if 'actix' in content or 'axum' in content:
        intel['app_type'] = 'api'
        intel['frameworks'].append('actix' if 'actix' in content else 'axum')

elif os.path.exists(os.path.join(root, 'go.mod')):
    intel['app_type'] = 'api'
    intel['frameworks'].append('go')

# === Read README ===
for readme in ['README.md', 'readme.md', 'README.txt', 'README']:
    readme_path = os.path.join(root, readme)
    if os.path.exists(readme_path):
        intel['readme_content'] = read_file(readme_path, 200)
        break

# === Scan for routes and endpoints ===
for root_dir, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in [
        'node_modules', '.git', 'dist', 'build', 'target', '.venv', '__pycache__'
    ]]
    
    for filename in files:
        filepath = os.path.join(root_dir, filename)
        relpath = os.path.relpath(filepath, root)
        
        # Detect test files
        if 'test' in filename.lower() or 'spec' in filename.lower():
            if filename.endswith(('.ts', '.tsx', '.js', '.jsx', '.py')):
                intel['test_files'].append(relpath)
                continue
        
        # Skip non-source
        if not filename.endswith(('.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.rs')):
            continue
        
        content = read_file(filepath, 200)
        
        # Next.js pages/app router
        if '/pages/' in relpath or '/app/' in relpath:
            if filename in ['page.tsx', 'page.ts', 'page.js'] or relpath.startswith('pages/'):
                route = '/' + relpath.replace('pages/', '').replace('app/', '')
                route = re.sub(r'\[([^\]]+)\]', r':\1', route)
                route = re.sub(r'/(page|index)\.(tsx?|jsx?)$', '', route)
                route = route.rstrip('/') or '/'
                intel['routes'].append({'path': route, 'file': relpath})
        
        # API routes
        api_matches = re.findall(
            r'(app|router|server)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
            content, re.IGNORECASE
        )
        for match in api_matches:
            intel['endpoints'].append({
                'method': match[1].upper(),
                'path': match[2],
                'file': relpath
            })
        
        # Next.js API routes
        if '/api/' in relpath and filename.endswith(('.ts', '.js')):
            route = '/' + relpath.replace('pages/', '').replace('app/', '')
            route = re.sub(r'/route\.(ts|js)$', '', route)
            route = re.sub(r'\[([^\]]+)\]', r':\1', route)
            intel['endpoints'].append({
                'method': 'HANDLER',
                'path': route,
                'file': relpath
            })
        
        # React components
        if filename.endswith(('.tsx', '.jsx')) and '/components/' in relpath:
            intel['components'].append(relpath)

# === Scan env files for required vars ===
for env_file in ['.env.example', '.env.sample', '.env.template', '.env.local.example']:
    env_path = os.path.join(root, env_file)
    if os.path.exists(env_path):
        content = read_file(env_path)
        vars_found = re.findall(r'^([A-Z][A-Z0-9_]+)=', content, re.MULTILINE)
        intel['env_vars'].extend(vars_found)

# === Scan Prisma schema for models ===
prisma_path = os.path.join(root, 'prisma', 'schema.prisma')
if os.path.exists(prisma_path):
    content = read_file(prisma_path)
    models = re.findall(r'model\s+(\w+)\s*\{', content)
    intel['db_models'] = models

# Deduplicate
intel['routes'] = list({r['path']: r for r in intel['routes']}.values())
intel['endpoints'] = list({f"{e['method']}:{e['path']}": e for e in intel['endpoints']}.values())
intel['test_files'] = list(set(intel['test_files']))[:50]  # Cap at 50
intel['env_vars'] = list(set(intel['env_vars']))

with open(output_file, 'w') as f:
    json.dump(intel, f, indent=2)

print(f"Gathered: {len(intel['routes'])} routes, {len(intel['endpoints'])} endpoints, {len(intel['test_files'])} test files")
PYTHON

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 2: LLM Analysis to infer user flows
  # ═══════════════════════════════════════════════════════════════════════════
  say "  Phase 2: LLM analysis to infer user flows..."
  
  local llm_analysis="$WORKDIR/llm_analysis.json"
  local repo_intel_content
  repo_intel_content=$(cat "$repo_intel")
  
  # Read some key source files for context
  local source_samples=""
  while IFS= read -r f; do
    [[ -f "$f" ]] && source_samples+="=== $f ===\n$(head -60 "$f")\n\n"
  done < <(find . -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.py" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" \
    | grep -E "(page|route|api|auth|user|login|signup|dashboard|home)" | head -10)
  
  local llm_prompt="You are analyzing a codebase to generate a goldrecord.yaml contract.

REPO INTELLIGENCE:
$repo_intel_content

KEY SOURCE FILES:
$source_samples

Based on this analysis, infer the user flows this application supports.
Think about:
1. What can users DO with this app? (login, signup, create things, view things, etc.)
2. What are the critical paths that MUST work for the product to be useful?
3. What API endpoints support each user flow?
4. What test files might cover each flow?

Output ONLY valid JSON with this structure:
{
  \"inferred_app_type\": \"web|api|cli|mobile|lib\",
  \"inferred_description\": \"One-line description of what this app does\",
  \"user_flows\": [
    {
      \"id\": \"flow-id\",
      \"name\": \"Human readable name\",
      \"description\": \"What this flow accomplishes\",
      \"confidence\": 0.0-1.0,
      \"preconditions\": [\"list of preconditions\"],
      \"steps\": [\"step 1\", \"step 2\"],
      \"expected_results\": [\"result 1\"],
      \"ui_routes\": [\"/route\"],
      \"api_calls\": [\"METHOD /path\"],
      \"inferred_test_files\": [\"path/to/test\"]
    }
  ],
  \"inferred_integrations\": [
    {\"name\": \"service\", \"type\": \"payments|auth|email|storage\", \"env_var\": \"VAR_NAME\"}
  ],
  \"recommended_test_coverage\": 70,
  \"notes\": \"Any observations about the codebase quality or completeness\"
}"

  # Call Claude for analysis
  local llm_response="$WORKDIR/llm_response.json"
  
  if [[ -n "$SLOP_CLAUDE_API_KEY" ]] || [[ -n "$CLAUDE_AUTH_METHOD" ]]; then
    say "    Using Claude for flow inference..."
    
    if call_claude "$llm_prompt" "$llm_response" "$SLOP_CLAUDE_MODEL_PLANNING" 2>/dev/null; then
      # Extract JSON from response using robust sanitizer
      local raw_llm
      raw_llm=$(jq -r '.content[0].text // "{}"' "$llm_response" 2>/dev/null)
      clean_json "$raw_llm" > "$llm_analysis"
    else
      echo '{"user_flows":[],"notes":"LLM analysis failed"}' > "$llm_analysis"
    fi
  else
    say "    No LLM available, using heuristic flow generation..."
    echo '{"user_flows":[],"notes":"No LLM available for inference"}' > "$llm_analysis"
  fi
  
  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 3: Generate goldrecord.yaml (v2 schema)
  # ═══════════════════════════════════════════════════════════════════════════
  say "  Phase 3: Generating goldrecord.yaml (v2 schema)..."
  
  python3 - "$repo_intel" "$llm_analysis" "$goldrecord_file" "$existing_contract" <<'PYTHON'
import sys
import json
import os
from datetime import datetime

repo_intel_file = sys.argv[1]
llm_analysis_file = sys.argv[2]
output_file = sys.argv[3]
existing_contract = sys.argv[4] if len(sys.argv) > 4 else ""

# Load data
try:
    with open(repo_intel_file, 'r') as f:
        intel = json.load(f)
except:
    intel = {}

try:
    with open(llm_analysis_file, 'r') as f:
        llm = json.load(f)
except:
    llm = {"user_flows": []}

# Parse existing contract if regenerating
existing_flows = {}
existing_features = {}
if existing_contract:
    try:
        import yaml
        existing = yaml.safe_load(existing_contract)
        if existing:
            # Handle v2 format
            product = existing.get('product', {})
            for flow in product.get('user_flows', []):
                if isinstance(flow, dict) and 'id' in flow:
                    existing_flows[flow['id']] = flow
            for feat in product.get('features', []):
                if isinstance(feat, dict) and 'id' in feat:
                    existing_features[feat['id']] = feat
            # Handle v1 format
            for flow in existing.get('user_flows', []):
                if isinstance(flow, dict) and 'id' in flow:
                    existing_flows[flow['id']] = flow
    except:
        pass

# Detect primary language
primary_lang = "typescript"
frameworks = intel.get('frameworks', [])
if 'python' in frameworks or 'fastapi' in frameworks or 'django' in frameworks:
    primary_lang = "python"
elif 'go' in frameworks:
    primary_lang = "go"
elif 'rust' in frameworks:
    primary_lang = "rust"

# Detect runtime targets
runtime_targets = []
app_type = llm.get('inferred_app_type', intel.get('app_type', 'web'))
if app_type in ['web', 'mobile', 'desktop']:
    runtime_targets.append(app_type)
if intel.get('endpoints'):
    runtime_targets.append('api')
if not runtime_targets:
    runtime_targets = ['web']

# Build goldrecord YAML (v2 schema)
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
L = []  # yaml lines

L.append("# Goldrecord Contract (Auto-generated)")
L.append("#")
L.append("# Purpose: A machine-verifiable contract that defines what 'done' means.")
L.append("# The release gate MUST fail-closed unless every requirement is satisfied.")
L.append("#")
L.append(f"# Generated: {timestamp}")
L.append("# ⚠️  Items marked TODO require human review and completion.")
L.append("")
L.append("version: 1")
L.append("")

# === REPO SECTION ===
L.append("repo:")
name = intel.get('name', 'my-product')
L.append(f'  name: "{name}"')
desc = llm.get('inferred_description', intel.get('description', 'TODO: Add description'))
L.append(f'  description: "{desc}"')
L.append('  owners: ["TODO@example.com"]  # TODO: Add real owners')
L.append(f'  primary_language: "{primary_lang}"')
L.append('  repo_type: "single"  # TODO: Change to "monorepo" if applicable')
L.append(f'  runtime_targets: {json.dumps(runtime_targets)}')
L.append("")

# === RELEASE SECTION ===
L.append("release:")
L.append("  require_git_clean: true")
L.append("  require_no_untracked: true")
L.append('  require_commit_message_token: "[release]"  # TODO: Customize')
L.append('  require_tag_regex: "^v\\\\d+\\\\.\\\\d+\\\\.\\\\d+$"')
L.append('  evidence_dir: ".goldrecord/evidence"')
L.append("")

# === COMMANDS SECTION ===
L.append("# Commands executed by the gate. Keep them deterministic.")
L.append("commands:")

scripts = intel.get('package_scripts', {})

# Bootstrap - check for lockfile to decide npm ci vs npm install
L.append("  bootstrap:")
if os.path.exists('package-lock.json'):
    L.append("    - id: BOOTSTRAP_1")
    L.append('      name: "Install deps (clean)"')
    L.append('      cmd: "npm ci"')
    L.append('      # Note: npm ci requires package-lock.json in sync. Use "npm install" if this fails.')
elif os.path.exists('yarn.lock'):
    L.append("    - id: BOOTSTRAP_1")
    L.append('      name: "Install deps (yarn)"')
    L.append('      cmd: "yarn install --frozen-lockfile"')
elif os.path.exists('pnpm-lock.yaml'):
    L.append("    - id: BOOTSTRAP_1")
    L.append('      name: "Install deps (pnpm)"')
    L.append('      cmd: "pnpm install --frozen-lockfile"')
elif os.path.exists('package.json'):
    # No lockfile - use npm install (npm ci would fail)
    L.append("    - id: BOOTSTRAP_1")
    L.append('      name: "Install deps"')
    L.append('      cmd: "npm install"')
    L.append('      # Note: Consider using "npm ci" after generating package-lock.json for reproducible builds')
elif os.path.exists('requirements.txt') or os.path.exists('pyproject.toml'):
    L.append("    - id: BOOTSTRAP_1")
    L.append('      name: "Install deps"')
    if os.path.exists('requirements.txt'):
        L.append('      cmd: "pip install -r requirements.txt"')
    else:
        L.append('      cmd: "pip install -e ."')
elif os.path.exists('Gemfile.lock'):
    L.append("    - id: BOOTSTRAP_1")
    L.append('      name: "Install deps (bundler)"')
    L.append('      cmd: "bundle install"')
elif os.path.exists('go.mod'):
    L.append("    - id: BOOTSTRAP_1")
    L.append('      name: "Install deps (go)"')
    L.append('      cmd: "go mod download"')
else:
    L.append("    []  # TODO: Add bootstrap command")
L.append("")

# Build
L.append("  build:")
if 'build' in scripts:
    L.append("    - id: BUILD_1")
    L.append('      name: "Build"')
    L.append('      cmd: "npm run build"')
else:
    L.append("    []  # TODO: Add build command")
L.append("")

# Lint
L.append("  lint:")
if 'lint' in scripts:
    L.append("    - id: LINT_1")
    L.append('      name: "Lint"')
    L.append('      cmd: "npm run lint"')
elif primary_lang == 'python':
    L.append("    - id: LINT_1")
    L.append('      name: "Lint"')
    L.append('      cmd: "ruff check ."')
else:
    L.append("    []  # TODO: Add lint command")
L.append("")

# Typecheck
L.append("  typecheck:")
if 'typecheck' in scripts or 'type-check' in scripts:
    L.append("    - id: TYPE_1")
    L.append('      name: "Typecheck"')
    cmd = 'npm run typecheck' if 'typecheck' in scripts else 'npm run type-check'
    L.append(f'      cmd: "{cmd}"')
elif primary_lang == 'typescript':
    L.append("    - id: TYPE_1")
    L.append('      name: "Typecheck"')
    L.append('      cmd: "npx tsc --noEmit"')
elif primary_lang == 'python':
    L.append("    - id: TYPE_1")
    L.append('      name: "Typecheck"')
    L.append('      cmd: "mypy ."')
else:
    L.append("    []  # TODO: Add typecheck command")
L.append("")

# Unit tests
L.append("  unit_tests:")
if 'test' in scripts:
    L.append("    - id: TEST_UNIT_1")
    L.append('      name: "Unit tests"')
    L.append('      cmd: "npm test -- --ci"')
elif primary_lang == 'python':
    L.append("    - id: TEST_UNIT_1")
    L.append('      name: "Unit tests"')
    L.append('      cmd: "pytest tests/unit"')
else:
    L.append("    []  # TODO: Add unit test command")
L.append("")

# Integration tests
L.append("  integration_tests:")
if 'test:integration' in scripts:
    L.append("    - id: TEST_INT_1")
    L.append('      name: "Integration tests"')
    L.append('      cmd: "npm run test:integration"')
else:
    L.append("    []  # TODO: Add integration test command")
L.append("")

# E2E tests
L.append("  e2e_tests:")
if 'test:e2e' in scripts:
    L.append("    - id: TEST_E2E_1")
    L.append('      name: "E2E tests"')
    L.append('      cmd: "npm run test:e2e"')
else:
    L.append("    []  # TODO: Add e2e test command")
L.append("")

# Coverage
L.append("  coverage:")
if 'test:coverage' in scripts or 'coverage' in scripts:
    L.append("    - id: COV_1")
    L.append('      name: "Coverage"')
    cmd = 'npm run test:coverage' if 'test:coverage' in scripts else 'npm run coverage'
    L.append(f'      cmd: "{cmd}"')
    L.append('      parse:')
    L.append('        kind: "regex"')
    L.append('        pattern: "All files\\\\s*\\\\|\\\\s*(?P<lines>[0-9.]+)"')
else:
    L.append("    []  # TODO: Add coverage command")
L.append("")

# Security
L.append("  security:")
L.append("    - id: SEC_1")
L.append('      name: "Secrets scan"')
L.append('      cmd: "gitleaks detect --redact --verbose"')
L.append("    - id: SEC_2")
L.append('      name: "Dependency vulnerabilities"')
if primary_lang in ['typescript', 'javascript']:
    L.append('      cmd: "npm audit --audit-level=high"')
elif primary_lang == 'python':
    L.append('      cmd: "pip-audit"')
else:
    L.append('      cmd: "echo TODO: Add vuln scan"')
L.append("")

# === QUALITY SECTION ===
L.append("# Quality gates")
L.append("quality:")
L.append("  coverage_thresholds:")
L.append("    lines: 80  # TODO: Adjust threshold")
L.append("    branches: 70")
L.append("    functions: 80")
L.append("    statements: 80")
L.append("")
L.append("  placeholder_policy:")
L.append("    forbid_patterns:")
L.append('      - "\\\\bTODO\\\\b"')
L.append('      - "\\\\bFIXME\\\\b"')
L.append('      - "\\\\bHACK\\\\b"')
L.append('      - "not implemented"')
L.append('      - "throw new Error\\\\(\\"TODO\\""')
L.append('    allowlist_file: ".goldrecord/allowlist.regex"')
L.append("    ignore_paths:")
L.append('      - "**/node_modules/**"')
L.append('      - "**/dist/**"')
L.append('      - "**/build/**"')
L.append("")
L.append("  test_integrity:")
L.append("    forbid_skip_tokens: true")
L.append("    forbid_only_tokens: true")
L.append("    forbid_trivial_assertions: true")
L.append("")

# === PRODUCT SECTION ===
L.append("# Product definition - what the app MUST do")
L.append("product:")

# User personas
L.append("  user_personas:")
L.append("    - id: P1")
L.append('      name: "Primary User"  # TODO: Define real persona')
L.append('      goals: ["TODO: Add user goals"]')
L.append("")

# Features (inferred from routes/endpoints)
L.append("  features:")
features_added = set()

# Auth feature if detected
routes = intel.get('routes', [])
endpoints = intel.get('endpoints', [])
all_paths = [r.get('path', '') for r in routes] + [e.get('path', '') for e in endpoints]

if any('/login' in p.lower() or '/signup' in p.lower() or '/auth' in p.lower() for p in all_paths):
    L.append("    - id: F_AUTH")
    L.append('      name: "Authentication"')
    L.append('      description: "Users can sign up, log in, and log out"')
    L.append("      must_have: true")
    L.append('      owned_by: "TODO@example.com"')
    L.append("      code_anchors:")
    L.append('        - "src/auth/**"  # TODO: Verify paths')
    L.append("      docs_anchors:")
    L.append('        - "docs/features/auth.md"  # TODO: Create')
    features_added.add('auth')
    L.append("")

# Core features from LLM
llm_flows = llm.get('user_flows', [])
for flow in llm_flows[:5]:  # Limit to 5
    flow_id = flow.get('id', '').upper().replace('-', '_')
    if flow_id and flow_id not in features_added:
        L.append(f"    - id: F_{flow_id}")
        L.append(f'      name: "{flow.get("name", "TODO")}"')
        L.append(f'      description: "{flow.get("description", "TODO")}"')
        conf = flow.get('confidence', 0.5)
        if conf < 0.7:
            L.append(f'      # TODO: Review (confidence: {conf:.0%})')
        L.append("      must_have: true")
        L.append('      owned_by: "TODO@example.com"')
        L.append("      code_anchors:")
        L.append('        - "TODO: Add code paths"')
        L.append("      docs_anchors:")
        L.append('        - "TODO: Add doc references"')
        features_added.add(flow_id)
        L.append("")

if not features_added:
    L.append("    - id: F_CORE")
    L.append('      name: "TODO: Core Feature"')
    L.append('      description: "TODO: Describe core functionality"')
    L.append("      must_have: true")
    L.append('      owned_by: "TODO@example.com"')
    L.append("      code_anchors: []")
    L.append("      docs_anchors: []")
    L.append("")

# User flows
L.append("  user_flows:")
for flow in llm_flows[:5]:
    flow_id = flow.get('id', 'FLOW_1').upper().replace('-', '_')
    L.append(f"    - id: {flow_id}")
    L.append(f'      name: "{flow.get("name", "TODO")}"')
    L.append("      persona_id: P1")
    
    preconds = flow.get('preconditions', ['User is logged in'])
    L.append("      preconditions:")
    for p in preconds[:3]:
        L.append(f'        - "{p}"')
    
    steps = flow.get('steps', ['TODO'])
    L.append("      steps:")
    for s in steps[:5]:
        L.append(f'        - "{s}"')
    
    results = flow.get('expected_results', flow.get('expected_outcomes', ['TODO']))
    L.append("      expected_outcomes:")
    for r in results[:3]:
        L.append(f'        - "{r}"')
    
    L.append("      test_requirements:")
    L.append("        e2e:")
    L.append("          required: true")
    L.append(f'          test_id: "{flow_id.lower()}"  # grep-able test identifier')
    L.append("          min_assertions: 3")
    L.append("      docs_requirements:")
    L.append("        required: true")
    L.append(f'        doc_id: "{flow_id}"')
    L.append("")

if not llm_flows:
    L.append("    - id: FLOW_MAIN")
    L.append('      name: "TODO: Main User Flow"')
    L.append("      persona_id: P1")
    L.append("      preconditions:")
    L.append('        - "TODO"')
    L.append("      steps:")
    L.append('        - "TODO"')
    L.append("      expected_outcomes:")
    L.append('        - "TODO"')
    L.append("      test_requirements:")
    L.append("        e2e:")
    L.append("          required: true")
    L.append('          test_id: "main_flow"')
    L.append("          min_assertions: 3")
    L.append("      docs_requirements:")
    L.append("        required: true")
    L.append('        doc_id: "FLOW_MAIN"')
    L.append("")

# UI Routes
L.append("  ui_routes:")
for i, route in enumerate(routes[:10]):
    path = route.get('path', '/')
    route_id = f"ROUTE_{i+1}"
    L.append(f"    - id: {route_id}")
    L.append(f'      route: "{path}"')
    L.append("      must_exist: true")
    L.append("      flow_ids: []  # TODO: Link to flows")
    L.append("")

if not routes:
    L.append("    []  # TODO: Add UI routes")
L.append("")

# API
L.append("  api:")
L.append("    openapi:")
L.append("      required: true")
L.append('      spec_path: "openapi.yaml"  # TODO: Verify or create')
L.append("")
L.append("    endpoints:")
for i, ep in enumerate(endpoints[:10]):
    method = ep.get('method', 'GET')
    path = ep.get('path', '/')
    ep_id = f"API_{i+1}"
    L.append(f"      - id: {ep_id}")
    L.append(f"        method: {method}")
    L.append(f'        path: "{path}"')
    L.append("        must_exist: true")
    L.append(f'        contract_test_id: "api_{i+1}"')
    L.append("        docs_required: true")
    L.append("")

if not endpoints:
    L.append("      []  # TODO: Add API endpoints")
L.append("")

# === OPS SECTION ===
L.append("# Runtime/deployment requirements")
L.append("ops:")
L.append("  health:")
L.append("    required: true")
L.append('    url: "http://localhost:3000/health"  # TODO: Verify')
L.append("    expected_status: 200")
L.append("")
L.append("  startup:")
if 'start' in scripts:
    L.append('    cmd: "npm run start"')
elif 'dev' in scripts:
    L.append('    cmd: "npm run dev"')
elif primary_lang == 'python':
    L.append('    cmd: "python -m uvicorn main:app"  # TODO: Verify')
else:
    L.append('    cmd: "TODO: Add start command"')
L.append('    cwd: "./"')
L.append("    timeout_seconds: 180")
L.append("")
L.append("  env:")
L.append("    env_example_required: true")
L.append('    env_example_path: ".env.example"')
L.append("    docs_required: true")
L.append("    docs_paths:")
L.append('      - "docs/ops/env.md"  # TODO: Create')
L.append("")

# === DOCS SECTION ===
L.append("# Documentation requirements")
L.append("docs:")
L.append("  required_files:")
L.append('    - "README.md"')
L.append('    - "SECURITY.md"  # TODO: Create')
L.append('    - "docs/ARCHITECTURE.md"  # TODO: Create')
L.append('    - "docs/USER_FLOWS.md"  # TODO: Create')
L.append("")
L.append("  require_feature_ids_in_docs: true")
L.append("  require_flow_ids_in_docs: true")
L.append("")

# === GATE SECTION ===
L.append("# Gate behavior")
L.append("gate:")
L.append("  fail_on_warnings: true")
L.append("  strict_discovery: true")
L.append("  produce_attestation: true")
L.append("")

# Notes
notes = llm.get('notes', '')
if notes:
    L.append("# ═══════════════════════════════════════════════════════════════════════════════")
    L.append("# ANALYSIS NOTES")
    L.append("# ═══════════════════════════════════════════════════════════════════════════════")
    L.append(f"# {notes}")
    L.append("")

# Write file
with open(output_file, 'w') as f:
    f.write('\n'.join(L))

print(f"Generated goldrecord.yaml (v2 schema) with {len(llm_flows)} flows")
PYTHON

  say "  ✓ Generated: $goldrecord_file"
  say ""
  say "  ⚠️  IMPORTANT: Review the generated contract!"
  say "     - Items marked with TODO need human verification"
  say "     - Add missing user flows for complete coverage"
  say "     - Verify test_files paths are correct"
  say "     - Run --certify after completing the contract"
  say ""
  
  popd >/dev/null
}

########################################
# PROOF OF LIFE: BUILD VERIFICATION
########################################
run_build_check() {
  [[ "$SLOP_ENABLE_BUILD_CHECK" == "1" ]] || return 0
  
  say "Verifying build works..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  local build_success=0
  local build_output="$WORKDIR/build_output.log"
  
  # Detect build system and run build
  if [[ -f "package.json" ]]; then
    # Node.js project
    say "  Detected Node.js project, running build..."
    
    # Check for build script
    if jq -e '.scripts.build' package.json >/dev/null 2>&1; then
      if timeout "$SLOP_BUILD_TIMEOUT" npm run build > "$build_output" 2>&1; then
        build_success=1
        say "  ✓ npm run build succeeded"
      else
        emit_issue "local/build-check" "build" "blocker" "package.json" 1 \
          "Build failed: npm run build" "$(tail -20 "$build_output" | head -c 500)" \
          "Code that doesn't build cannot ship" 0.99 \
          "Fix build errors shown above"
      fi
    else
      emit_issue "local/build-check" "build" "high" "package.json" 1 \
        "No build script defined" "package.json has no scripts.build" \
        "Production projects should have a build script" 0.85 \
        "Add a build script to package.json"
    fi
    
    # TypeScript check
    if [[ -f "tsconfig.json" ]] && [[ "$SLOP_ENABLE_TYPECHECK" == "1" ]]; then
      say "  Running TypeScript typecheck..."
      if need_cmd tsc || need_cmd npx; then
        if timeout 300 npx tsc --noEmit > "$WORKDIR/tsc_output.log" 2>&1; then
          say "  ✓ TypeScript typecheck passed"
        else
          local tsc_errors
          tsc_errors=$(grep -c "error TS" "$WORKDIR/tsc_output.log" 2>/dev/null || echo "unknown")
          emit_issue "local/build-check" "type-safety" "blocker" "tsconfig.json" 1 \
            "TypeScript errors: $tsc_errors" "$(tail -15 "$WORKDIR/tsc_output.log" | head -c 500)" \
            "Type errors indicate incomplete or incorrect code" 0.95 \
            "Fix all TypeScript errors before release"
        fi
      fi
    fi
    
  elif [[ -f "pyproject.toml" ]] || [[ -f "setup.py" ]]; then
    # Python project
    say "  Detected Python project..."
    
    # Type check with mypy/pyright
    if [[ "$SLOP_ENABLE_TYPECHECK" == "1" ]]; then
      if need_cmd mypy; then
        say "  Running mypy typecheck..."
        if timeout 300 mypy . --ignore-missing-imports > "$WORKDIR/mypy_output.log" 2>&1; then
          say "  ✓ mypy typecheck passed"
        else
          local mypy_errors
          mypy_errors=$(grep -c "error:" "$WORKDIR/mypy_output.log" 2>/dev/null || echo "unknown")
          emit_issue "local/build-check" "type-safety" "high" "." 1 \
            "mypy type errors: $mypy_errors" "$(tail -15 "$WORKDIR/mypy_output.log" | head -c 500)" \
            "Type errors indicate potential bugs" 0.8 \
            "Fix type errors or add type: ignore comments with justification"
        fi
      fi
    fi
    
    build_success=1  # Python doesn't always have a build step
    
  elif [[ -f "Cargo.toml" ]]; then
    # Rust project
    say "  Detected Rust project, running cargo build..."
    if timeout "$SLOP_BUILD_TIMEOUT" cargo build --release > "$build_output" 2>&1; then
      build_success=1
      say "  ✓ cargo build succeeded"
    else
      emit_issue "local/build-check" "build" "blocker" "Cargo.toml" 1 \
        "Build failed: cargo build" "$(tail -20 "$build_output" | head -c 500)" \
        "Code that doesn't build cannot ship" 0.99 \
        "Fix compilation errors"
    fi
    
  elif [[ -f "go.mod" ]]; then
    # Go project
    say "  Detected Go project, running go build..."
    if timeout "$SLOP_BUILD_TIMEOUT" go build ./... > "$build_output" 2>&1; then
      build_success=1
      say "  ✓ go build succeeded"
    else
      emit_issue "local/build-check" "build" "blocker" "go.mod" 1 \
        "Build failed: go build" "$(tail -20 "$build_output" | head -c 500)" \
        "Code that doesn't build cannot ship" 0.99 \
        "Fix compilation errors"
    fi
  else
    say "  No recognized build system, skipping build check"
  fi
  
  popd >/dev/null
}

########################################
# PROOF OF LIFE: TEST EXECUTION
########################################
run_test_execution() {
  [[ "$SLOP_ENABLE_TEST_RUN" == "1" ]] || return 0
  
  say "Verifying tests pass..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  local test_output="$WORKDIR/test_output.log"
  local tests_ran=0
  local tests_passed=0
  
  # Detect test framework and run tests
  if [[ -f "package.json" ]]; then
    if jq -e '.scripts.test' package.json >/dev/null 2>&1; then
      local test_cmd
      test_cmd=$(jq -r '.scripts.test' package.json)
      
      # Skip if test script is just "echo" or "exit 0" (fake test)
      if [[ "$test_cmd" == "echo"* ]] || [[ "$test_cmd" == "exit 0"* ]] || [[ "$test_cmd" == '""' ]]; then
        emit_issue "local/test-run" "test-coverage" "blocker" "package.json" 1 \
          "Fake test script detected" "scripts.test = $test_cmd" \
          "Test script that does nothing is not testing" 0.95 \
          "Replace with actual test runner (jest, vitest, mocha)"
      else
        say "  Running: npm test..."
        tests_ran=1
        if timeout "$SLOP_TEST_TIMEOUT" npm test > "$test_output" 2>&1; then
          tests_passed=1
          say "  ✓ npm test passed"
        else
          local exit_code=$?
          emit_issue "local/test-run" "test-coverage" "blocker" "package.json" 1 \
            "Tests failed (exit code: $exit_code)" "$(tail -30 "$test_output" | head -c 800)" \
            "Failing tests indicate broken functionality" 0.99 \
            "Fix failing tests before release"
        fi
      fi
    else
      emit_issue "local/test-run" "test-coverage" "high" "package.json" 1 \
        "No test script defined" "package.json has no scripts.test" \
        "Production projects must have tests" 0.9 \
        "Add a test script to package.json"
    fi
    
  elif [[ -f "pyproject.toml" ]] || [[ -f "pytest.ini" ]] || [[ -f "setup.py" ]]; then
    if need_cmd pytest; then
      say "  Running: pytest..."
      tests_ran=1
      if timeout "$SLOP_TEST_TIMEOUT" pytest --tb=short > "$test_output" 2>&1; then
        tests_passed=1
        say "  ✓ pytest passed"
        
        # Extract coverage if available
        if grep -q "TOTAL" "$test_output"; then
          local coverage
          coverage=$(grep "TOTAL" "$test_output" | awk '{print $NF}' | tr -d '%')
          say "  Coverage: ${coverage}%"
          if [[ -n "$coverage" ]] && [[ "$coverage" -lt 50 ]]; then
            emit_issue "local/test-run" "test-coverage" "high" "." 1 \
              "Low test coverage: ${coverage}%" "pytest reports ${coverage}% coverage" \
              "Low coverage means untested code paths" 0.85 \
              "Add tests to increase coverage above 70%"
          fi
        fi
      else
        emit_issue "local/test-run" "test-coverage" "blocker" "." 1 \
          "Tests failed: pytest" "$(tail -30 "$test_output" | head -c 800)" \
          "Failing tests indicate broken functionality" 0.99 \
          "Fix failing tests before release"
      fi
    fi
    
  elif [[ -f "Cargo.toml" ]]; then
    say "  Running: cargo test..."
    tests_ran=1
    if timeout "$SLOP_TEST_TIMEOUT" cargo test > "$test_output" 2>&1; then
      tests_passed=1
      say "  ✓ cargo test passed"
    else
      emit_issue "local/test-run" "test-coverage" "blocker" "Cargo.toml" 1 \
        "Tests failed: cargo test" "$(tail -30 "$test_output" | head -c 800)" \
        "Failing tests indicate broken functionality" 0.99 \
        "Fix failing tests before release"
    fi
    
  elif [[ -f "go.mod" ]]; then
    say "  Running: go test..."
    tests_ran=1
    if timeout "$SLOP_TEST_TIMEOUT" go test ./... > "$test_output" 2>&1; then
      tests_passed=1
      say "  ✓ go test passed"
    else
      emit_issue "local/test-run" "test-coverage" "blocker" "go.mod" 1 \
        "Tests failed: go test" "$(tail -30 "$test_output" | head -c 800)" \
        "Failing tests indicate broken functionality" 0.99 \
        "Fix failing tests before release"
    fi
  fi
  
  # Certify mode requires tests to have run
  if [[ "$SLOP_CERTIFY_MODE" == "1" ]] && [[ "$tests_ran" -eq 0 ]]; then
    emit_issue "local/test-run" "test-coverage" "blocker" "." 1 \
      "No tests executed" "Could not find/run any test framework" \
      "Release certification requires passing tests" 0.95 \
      "Add a test framework and tests for core functionality"
  fi
  
  popd >/dev/null
}

########################################
# FULL COVERAGE PARALLEL SCANNING
########################################
run_full_coverage_scan() {
  [[ "$SLOP_FULL_COVERAGE" == "1" ]] || return 0
  
  say "Running full coverage parallel scan (ALL files)..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  # Create file list for parallel processing
  local file_list="$WORKDIR/all_source_files.txt"
  local total_files
  
  # Prefer git ls-files if in a git repo (respects .gitignore automatically)
  if is_git_repo; then
    say "  Using git ls-files (respects .gitignore)..."
    
    git ls-files --cached --others --exclude-standard 2>/dev/null | \
      grep -E '\.(ts|tsx|js|jsx|py|go|rs|java|rb|php|cs|cpp|c|h|hpp)$' | \
      grep -v -E '^(node_modules/|vendor/|dist/|build/|target/|\.venv/|__pycache__/)' \
      > "$file_list"
    
    total_files=$(wc -l < "$file_list")
  else
    # Fallback to find for non-git repos
    say "  Using find (not a git repo)..."
    
    total_files=$(find . -type f \
      \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" \
         -o -name "*.py" -o -name "*.go" -o -name "*.rs" -o -name "*.java" \
         -o -name "*.rb" -o -name "*.php" -o -name "*.cs" -o -name "*.cpp" \
         -o -name "*.c" -o -name "*.h" -o -name "*.hpp" \) \
      ! -path "*/.git/*" \
      ! -path "*/node_modules/*" \
      ! -path "*/vendor/*" \
      ! -path "*/dist/*" \
      ! -path "*/build/*" \
      ! -path "*/target/*" \
      ! -path "*/.venv/*" \
      ! -path "*/__pycache__/*" \
      2>/dev/null | wc -l)
    
    find . -type f \
      \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" \
         -o -name "*.py" -o -name "*.go" -o -name "*.rs" -o -name "*.java" \
         -o -name "*.rb" -o -name "*.php" -o -name "*.cs" -o -name "*.cpp" \
         -o -name "*.c" -o -name "*.h" -o -name "*.hpp" \) \
      ! -path "*/.git/*" \
      ! -path "*/node_modules/*" \
      ! -path "*/vendor/*" \
      ! -path "*/dist/*" \
      ! -path "*/build/*" \
      ! -path "*/target/*" \
      ! -path "*/.venv/*" \
      ! -path "*/__pycache__/*" \
      2>/dev/null > "$file_list"
  fi
  
  say "  Total source files to scan: $total_files"
  
  # Safety limit: warn if file count is huge
  if [[ $total_files -gt 10000 ]]; then
    warn "  ⚠️  Large repo detected ($total_files files). This may take a while and cost significant LLM tokens."
  fi
  
  # Split into chunks for parallel processing
  local chunks_dir="$WORKDIR/file_chunks"
  mkdir -p "$chunks_dir"
  
  # Split file list into N chunks (one per job)
  split -n "l/$SLOP_JOBS" "$file_list" "$chunks_dir/chunk_"
  
  say "  Split into $(ls "$chunks_dir" | wc -l) chunks for parallel scanning..."
  
  # Process each chunk in parallel
  local scanned=0
  for chunk in "$chunks_dir"/chunk_*; do
    [[ -f "$chunk" ]] || continue
    
    (
      while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        
        # Scan file for critical patterns
        # TODO/FIXME/HACK
        grep -nE '(TODO|FIXME|HACK|XXX|WIP)\b' "$file" 2>/dev/null | while IFS=: read -r ln content; do
          echo "local/full-scan|tech-debt|medium|$file|$ln|TODO/FIXME/HACK found|$content|Incomplete code markers|0.8|" >> "$WORKDIR/chunk_issues_$$.txt"
        done
        
        # Not implemented / placeholder
        grep -niE '(not implemented|throw.*not.*implement|pass\s*#|placeholder|stub)' "$file" 2>/dev/null | while IFS=: read -r ln content; do
          echo "local/full-scan|ai-slop|blocker|$file|$ln|Stub/placeholder code|$content|Code that does nothing is not done|0.9|" >> "$WORKDIR/chunk_issues_$$.txt"
        done
        
        # Console.log / print statements in non-test files
        if [[ "$file" != *"test"* ]] && [[ "$file" != *"spec"* ]]; then
          grep -nE '^\s*(console\.(log|debug|info)|print\(|println!|fmt\.Print)' "$file" 2>/dev/null | while IFS=: read -r ln content; do
            echo "local/full-scan|cleanup|medium|$file|$ln|Debug statement in production|$content|Remove debug statements before release|0.7|" >> "$WORKDIR/chunk_issues_$$.txt"
          done
        fi
        
      done < "$chunk"
    ) &
    
    # Limit parallel jobs
    while [[ $(jobs -r | wc -l) -ge $SLOP_JOBS ]]; do
      sleep 0.1
    done
  done
  
  # Wait for all jobs
  wait
  
  # Aggregate chunk results
  say "  Aggregating scan results..."
  for chunk_result in "$WORKDIR"/chunk_issues_*.txt; do
    [[ -f "$chunk_result" ]] || continue
    while IFS='|' read -r source category severity file line title evidence why confidence fix; do
      [[ -z "$file" ]] && continue
      emit_issue "$source" "$category" "$severity" "$file" "${line:-1}" \
        "$title" "${evidence:0:300}" "$why" "${confidence:-0.7}" "$fix"
    done < "$chunk_result"
  done
  
  say "  Full coverage scan complete: $total_files files processed"
  
  popd >/dev/null
}

########################################
# SURFACE AREA INVENTORY (discover what exists)
########################################
build_inventory() {
  say "Building surface area inventory..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  local inventory_file="$WORKDIR/inventory.json"
  
  python3 - "$root" "$inventory_file" <<'PYTHON'
import sys
import os
import re
import json
from pathlib import Path

root = sys.argv[1]
inventory_file = sys.argv[2]

inventory = {
    "ui_routes": [],
    "api_endpoints": [],
    "background_jobs": [],
    "cli_commands": [],
    "db_tables": [],
    "components": [],
    "services": []
}

def scan_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            return content
    except:
        return ""

# Walk through source files
for root_dir, dirs, files in os.walk(root):
    # Skip common non-source directories
    dirs[:] = [d for d in dirs if d not in [
        'node_modules', '.git', 'dist', 'build', 'target', 
        '.venv', '__pycache__', 'vendor', '.next'
    ]]
    
    for filename in files:
        filepath = os.path.join(root_dir, filename)
        relpath = os.path.relpath(filepath, root)
        
        # Skip non-source files
        if not any(filename.endswith(ext) for ext in [
            '.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.rs', '.java', '.rb'
        ]):
            continue
        
        content = scan_file(filepath)
        if not content:
            continue
        
        # === UI ROUTES ===
        # Next.js pages/app router
        if '/pages/' in relpath or '/app/' in relpath:
            if filename in ['page.tsx', 'page.ts', 'page.js'] or relpath.startswith('pages/'):
                route = '/' + relpath.replace('pages/', '').replace('app/', '')
                route = re.sub(r'\[([^\]]+)\]', r':\1', route)  # [id] -> :id
                route = re.sub(r'/(page|index)\.(tsx?|jsx?)$', '', route)
                route = route.rstrip('/') or '/'
                inventory["ui_routes"].append({
                    "path": route,
                    "file": relpath,
                    "framework": "nextjs"
                })
        
        # React Router routes
        router_matches = re.findall(r'<Route[^>]*path=["\']([^"\']+)["\']', content)
        for route in router_matches:
            inventory["ui_routes"].append({
                "path": route,
                "file": relpath,
                "framework": "react-router"
            })
        
        # === API ENDPOINTS ===
        # Express/Fastify/Hono routes
        api_patterns = [
            (r'(app|router|server)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', 'express'),
            (r'@(Get|Post|Put|Patch|Delete)\s*\(\s*["\']([^"\']+)["\']', 'nestjs'),
            (r'@app\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', 'fastapi'),
            (r'@(route|blueprint)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', 'flask'),
        ]
        
        for pattern, framework in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if framework in ['express', 'fastapi', 'flask']:
                    method = match[1].upper() if len(match) > 1 else 'GET'
                    path = match[2] if len(match) > 2 else match[-1]
                else:
                    method = match[0].upper()
                    path = match[1] if len(match) > 1 else '/'
                
                inventory["api_endpoints"].append({
                    "method": method,
                    "path": path,
                    "file": relpath,
                    "framework": framework
                })
        
        # tRPC routers
        if 'createTRPCRouter' in content or 'router({' in content:
            trpc_matches = re.findall(r'(\w+):\s*(query|mutation|subscription)\s*\(', content)
            for name, type_ in trpc_matches:
                inventory["api_endpoints"].append({
                    "method": type_.upper(),
                    "path": f"trpc.{name}",
                    "file": relpath,
                    "framework": "trpc"
                })
        
        # === BACKGROUND JOBS ===
        # Bull/BullMQ queues
        if 'Queue' in content or 'Worker' in content:
            queue_matches = re.findall(r'new\s+(?:Queue|Worker)\s*\(\s*["\']([^"\']+)["\']', content)
            for queue in queue_matches:
                inventory["background_jobs"].append({
                    "name": queue,
                    "file": relpath,
                    "type": "bullmq"
                })
        
        # Celery tasks
        if '@celery' in content or '@app.task' in content or '@shared_task' in content:
            task_matches = re.findall(r'def\s+(\w+)\s*\(', content)
            for task in task_matches:
                inventory["background_jobs"].append({
                    "name": task,
                    "file": relpath,
                    "type": "celery"
                })
        
        # === CLI COMMANDS ===
        # Click/Typer commands
        if '@click.command' in content or '@app.command' in content:
            cmd_matches = re.findall(r'@(?:click\.command|app\.command)\s*\([^)]*\)\s*\ndef\s+(\w+)', content)
            for cmd in cmd_matches:
                inventory["cli_commands"].append({
                    "name": cmd,
                    "file": relpath
                })
        
        # Commander.js
        if '.command(' in content:
            cmd_matches = re.findall(r'\.command\s*\(\s*["\']([^"\']+)["\']', content)
            for cmd in cmd_matches:
                inventory["cli_commands"].append({
                    "name": cmd,
                    "file": relpath
                })

# === DB TABLES (from migrations/schemas) ===
# Prisma schema
prisma_schema = os.path.join(root, 'prisma', 'schema.prisma')
if os.path.exists(prisma_schema):
    content = scan_file(prisma_schema)
    models = re.findall(r'model\s+(\w+)\s*\{', content)
    for model in models:
        inventory["db_tables"].append({
            "name": model,
            "source": "prisma"
        })

# Drizzle/SQL migrations
for pattern in ['**/migrations/*.sql', '**/drizzle/*.ts']:
    # Simple glob simulation
    pass  # Would need glob module

# Write inventory
with open(inventory_file, 'w') as f:
    json.dump(inventory, f, indent=2)

# Summary
print(f"Inventory: {len(inventory['ui_routes'])} routes, {len(inventory['api_endpoints'])} endpoints, {len(inventory['background_jobs'])} jobs")
PYTHON

  popd >/dev/null
  
  # Store for later use
  INVENTORY_FILE="$inventory_file"
}

########################################
# TRACEABILITY MATRIX (flow → test → evidence)
########################################
validate_traceability() {
  [[ "$SLOP_CERTIFY_MODE" == "1" ]] || return 0
  [[ -f "$WORKDIR/inventory.json" ]] || return 0
  
  say "Validating traceability matrix..."
  local root
  root="$(repo_root)"
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  
  [[ -f "$goldrecord_file" ]] || return 0
  
  python3 - "$goldrecord_file" "$WORKDIR/inventory.json" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json
import os

try:
    import yaml
except ImportError:
    yaml = None

goldrecord_file = sys.argv[1]
inventory_file = sys.argv[2]
issues_file = sys.argv[3]

def emit(sev, title, evidence, why, conf, fix):
    issue = {
        "source": "local/traceability",
        "category": "contract",
        "severity": sev,
        "file": goldrecord_file,
        "line": 1,
        "title": title,
        "evidence": evidence[:300],
        "why": why,
        "confidence": conf,
        "fix": fix
    }
    with open(issues_file, 'a') as f:
        f.write(json.dumps(issue) + '\n')

# Load goldrecord
if yaml:
    try:
        with open(goldrecord_file, 'r') as f:
            contract = yaml.safe_load(f) or {}
    except:
        contract = {}
else:
    contract = {}

# Load inventory
try:
    with open(inventory_file, 'r') as f:
        inventory = json.load(f)
except:
    inventory = {"ui_routes": [], "api_endpoints": [], "background_jobs": []}

user_flows = contract.get('user_flows', [])

# === CHECK 1: Every flow must have test_files ===
for flow in user_flows:
    if not isinstance(flow, dict):
        continue
    flow_id = flow.get('id', 'unknown')
    test_files = flow.get('test_files', [])
    
    if not test_files:
        emit("blocker", f"Flow '{flow_id}' has no test_files",
             f"user_flows[{flow_id}].test_files is empty",
             "Every flow must be linked to executable tests",
             0.95, f"Add test_files to flow '{flow_id}' in goldrecord.yaml")
    else:
        # Verify test files exist
        for tf in test_files:
            if not os.path.exists(tf):
                emit("high", f"Flow '{flow_id}' references missing test: {tf}",
                     f"test_files includes '{tf}' but file not found",
                     "Test files must exist to prove flow works",
                     0.9, f"Create test file '{tf}' or fix path in goldrecord.yaml")

# === CHECK 2: Every flow with API calls must have api_calls declared ===
for flow in user_flows:
    if not isinstance(flow, dict):
        continue
    flow_id = flow.get('id', 'unknown')
    api_calls = flow.get('api_calls', [])
    steps = flow.get('steps', [])
    
    # If steps mention API but no api_calls declared
    steps_text = ' '.join(str(s) for s in steps).lower()
    if ('api' in steps_text or 'endpoint' in steps_text or 'request' in steps_text) and not api_calls:
        emit("high", f"Flow '{flow_id}' mentions API but has no api_calls",
             f"Steps mention API but api_calls is empty",
             "API interactions must be explicitly declared for contract testing",
             0.8, f"Add api_calls to flow '{flow_id}'")

# === CHECK 3: Inventory endpoints not covered by any flow ===
inventory_endpoints = set()
for ep in inventory.get('api_endpoints', []):
    path = ep.get('path', '')
    if path and not path.startswith('trpc.'):  # tRPC handled differently
        inventory_endpoints.add(path)

declared_endpoints = set()
for flow in user_flows:
    if not isinstance(flow, dict):
        continue
    for call in flow.get('api_calls', []):
        # Extract path from "POST /api/foo" format
        parts = call.split()
        if len(parts) >= 2:
            declared_endpoints.add(parts[1])
        else:
            declared_endpoints.add(parts[0])

# Check for undeclared endpoints
out_of_scope = contract.get('out_of_scope', {}).get('endpoints', [])
uncovered = inventory_endpoints - declared_endpoints - set(out_of_scope)

if uncovered and len(uncovered) <= 10:
    for ep in list(uncovered)[:5]:
        emit("high", f"Discovered endpoint not in any flow: {ep}",
             f"Endpoint '{ep}' found in code but not declared in goldrecord",
             "All endpoints must be owned by a flow or marked out_of_scope",
             0.85, f"Add '{ep}' to a user_flow or out_of_scope.endpoints")
elif uncovered:
    emit("high", f"{len(uncovered)} endpoints not covered by any flow",
         f"Found {len(uncovered)} undeclared endpoints",
         "All endpoints must be owned by a flow or marked out_of_scope",
         0.85, "Review discovered endpoints and add to goldrecord.yaml")

# === CHECK 4: Declared endpoints not found in inventory ===
phantom = declared_endpoints - inventory_endpoints
if phantom:
    for ep in list(phantom)[:5]:
        emit("high", f"Declared endpoint not found in code: {ep}",
             f"goldrecord declares '{ep}' but not found in inventory",
             "Contract claims capability that doesn't exist (phantom feature)",
             0.9, f"Implement '{ep}' or remove from goldrecord.yaml")

print(f"Traceability: {len(user_flows)} flows, {len(inventory_endpoints)} discovered endpoints, {len(uncovered)} uncovered")
PYTHON
}

########################################
# FLOW-TAGGED TEST EXECUTION
########################################
run_flow_tagged_tests() {
  [[ "$SLOP_CERTIFY_MODE" == "1" ]] || return 0
  
  say "Running flow-tagged tests..."
  local root
  root="$(repo_root)"
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  
  [[ -f "$goldrecord_file" ]] || return 0
  
  pushd "$root" >/dev/null
  
  # Detect test framework
  local test_framework=""
  local test_cmd=""
  
  if [[ -f "playwright.config.ts" ]] || [[ -f "playwright.config.js" ]]; then
    test_framework="playwright"
    test_cmd="npx playwright test"
  elif [[ -f "cypress.config.ts" ]] || [[ -f "cypress.config.js" ]]; then
    test_framework="cypress"
    test_cmd="npx cypress run"
  elif jq -e '.devDependencies.vitest // .dependencies.vitest' package.json >/dev/null 2>&1; then
    test_framework="vitest"
    test_cmd="npx vitest run"
  elif jq -e '.devDependencies.jest // .dependencies.jest' package.json >/dev/null 2>&1; then
    test_framework="jest"
    test_cmd="npx jest"
  elif [[ -f "pytest.ini" ]] || [[ -f "pyproject.toml" ]]; then
    test_framework="pytest"
    test_cmd="pytest"
  fi
  
  if [[ -z "$test_framework" ]]; then
    say "  No recognized test framework for flow-tagged tests"
    popd >/dev/null
    return 0
  fi
  
  say "  Detected test framework: $test_framework"
  
  # Extract flow IDs from goldrecord
  local flow_ids
  flow_ids=$(python3 -c "
import sys
try:
    import yaml
    with open('$goldrecord_file', 'r') as f:
        c = yaml.safe_load(f) or {}
    for f in c.get('user_flows', []):
        if isinstance(f, dict) and 'id' in f:
            print(f['id'])
except:
    pass
")
  
  # Create evidence directory
  local evidence_dir="$WORKDIR/evidence"
  mkdir -p "$evidence_dir"
  
  # Run tests for each flow
  local flows_tested=0
  local flows_passed=0
  
  for flow_id in $flow_ids; do
    say "  Testing flow: $flow_id"
    
    local flow_output="$evidence_dir/${flow_id}_output.log"
    local grep_pattern="@goldrecord:${flow_id}|\\[GR:${flow_id}\\]|goldrecord.*${flow_id}"
    
    case "$test_framework" in
      playwright)
        if timeout 300 npx playwright test --grep "@goldrecord:${flow_id}" > "$flow_output" 2>&1; then
          say "    ✓ Flow $flow_id passed"
          ((flows_passed++))
        else
          emit_issue "local/flow-test" "test-coverage" "blocker" "$goldrecord_file" 1 \
            "Flow '$flow_id' tests failed" "$(tail -20 "$flow_output" | head -c 500)" \
            "Flow must pass all tests to certify" 0.95 \
            "Fix failing tests for flow $flow_id"
        fi
        ;;
      vitest|jest)
        if timeout 300 $test_cmd --testNamePattern="$grep_pattern" > "$flow_output" 2>&1; then
          say "    ✓ Flow $flow_id passed"
          ((flows_passed++))
        else
          # Check if no tests matched
          if grep -q "No tests found" "$flow_output" 2>/dev/null; then
            emit_issue "local/flow-test" "test-coverage" "high" "$goldrecord_file" 1 \
              "Flow '$flow_id' has no tagged tests" "No tests match @goldrecord:$flow_id" \
              "Flows should have tagged tests for traceability" 0.85 \
              "Add test.describe('@goldrecord:$flow_id', ...) to test files"
          else
            emit_issue "local/flow-test" "test-coverage" "blocker" "$goldrecord_file" 1 \
              "Flow '$flow_id' tests failed" "$(tail -20 "$flow_output" | head -c 500)" \
              "Flow must pass all tests to certify" 0.95 \
              "Fix failing tests for flow $flow_id"
          fi
        fi
        ;;
      pytest)
        if timeout 300 pytest -m "goldrecord_${flow_id}" > "$flow_output" 2>&1; then
          say "    ✓ Flow $flow_id passed"
          ((flows_passed++))
        else
          emit_issue "local/flow-test" "test-coverage" "blocker" "$goldrecord_file" 1 \
            "Flow '$flow_id' tests failed" "$(tail -20 "$flow_output" | head -c 500)" \
            "Flow must pass all tests to certify" 0.95 \
            "Fix failing tests for flow $flow_id"
        fi
        ;;
    esac
    
    ((flows_tested++))
  done
  
  say "  Flow tests: $flows_passed/$flows_tested passed"
  
  popd >/dev/null
}

########################################
# RUNTIME HARNESS (actually boot and healthcheck)
########################################
run_runtime_check() {
  # In certify mode, runtime check is REQUIRED (not optional)
  if [[ "$SLOP_CERTIFY_MODE" == "1" ]]; then
    SLOP_ENABLE_RUNTIME_CHECK=1
  fi
  
  [[ "$SLOP_ENABLE_RUNTIME_CHECK" == "1" ]] || return 0
  
  say "Running runtime verification (proof of life)..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  local health_endpoint="/api/health"
  local port=3000
  local startup_cmd=""
  
  # Extract settings from goldrecord if present
  if [[ -f "$goldrecord_file" ]]; then
    local gr_settings
    gr_settings=$(python3 -c "
import yaml
import re
try:
    with open('$goldrecord_file', 'r') as f:
        c = yaml.safe_load(f) or {}
    
    # v2 format: ops.health.url
    ops = c.get('ops', {})
    health = ops.get('health', {})
    health_url = health.get('url', '')
    
    # Extract port from URL
    port = 3000
    if health_url:
        m = re.search(r':(\d+)', health_url)
        if m:
            port = m.group(1)
    
    # v2 format: ops.startup.cmd
    startup = ops.get('startup', {})
    startup_cmd = startup.get('cmd', '')
    
    # v1 format fallback
    api_contract = c.get('api_contract', {})
    health_endpoint = api_contract.get('health_endpoint', '/api/health')
    
    # Extract health endpoint from URL
    if health_url:
        m = re.search(r'https?://[^/]+(/.*)$', health_url)
        if m:
            health_endpoint = m.group(1)
    
    print(f'{port}|{health_endpoint}|{startup_cmd}')
except Exception as e:
    print('3000|/api/health|')
" 2>/dev/null)
    
    IFS='|' read -r gr_port gr_health gr_startup <<< "$gr_settings"
    port="${gr_port:-3000}"
    health_endpoint="${gr_health:-/api/health}"
    startup_cmd="${gr_startup:-}"
  fi
  
  # Detect how to start the app (goldrecord.yaml > package.json > docker-compose)
  local start_cmd=""
  
  if [[ -n "$startup_cmd" ]]; then
    # Use goldrecord-specified startup command
    start_cmd="$startup_cmd &"
    say "  Using goldrecord startup command"
  elif [[ -f "docker-compose.yml" ]] || [[ -f "docker-compose.yaml" ]]; then
    say "  Detected docker-compose, starting services..."
    start_cmd="docker-compose up -d"
  elif [[ -f "package.json" ]]; then
    if jq -e '.scripts.start' package.json >/dev/null 2>&1; then
      start_cmd="npm start &"
    elif jq -e '.scripts.dev' package.json >/dev/null 2>&1; then
      start_cmd="npm run dev &"
    fi
  elif [[ -f "main.py" ]] || [[ -f "app.py" ]]; then
    local main_file="app.py"
    [[ -f "main.py" ]] && main_file="main.py"
    start_cmd="python3 $main_file &"
  fi
  
  if [[ -z "$start_cmd" ]]; then
    emit_issue "local/runtime" "runtime" "high" "." 1 \
      "Cannot determine how to start application" "No docker-compose, npm start, or main.py found" \
      "Runtime verification requires a way to boot the app. Add ops.startup.cmd to goldrecord.yaml" 0.8 \
      "Add docker-compose.yml, npm start script, or ops.startup.cmd to goldrecord.yaml"
    popd >/dev/null
    return 0
  fi
  
  # ═══════════════════════════════════════════════════════════════════════════
  # SECURITY: Safe execution patterns
  # We NEVER use eval on arbitrary commands. Instead:
  # 1. Known safe patterns: npm start, docker-compose, python/node with args
  # 2. Custom commands require SLOP_ALLOW_UNSAFE_RUNTIME=1
  # ═══════════════════════════════════════════════════════════════════════════
  
  local is_safe_command=0
  local exec_method=""
  
  # Check for safe patterns
  case "$start_cmd" in
    "npm start"*|"npm run start"*)
      is_safe_command=1
      exec_method="npm"
      ;;
    "npm run dev"*|"npm run serve"*)
      is_safe_command=1
      exec_method="npm"
      ;;
    "docker-compose up"*)
      is_safe_command=1
      exec_method="docker-compose"
      ;;
    "node "*|"python3 "*|"python "*)
      # Only safe if it's a simple file execution, no shell metacharacters
      if [[ ! "$start_cmd" =~ [\;\|\&\$\`] ]]; then
        is_safe_command=1
        exec_method="direct"
      fi
      ;;
    "uvicorn "*|"gunicorn "*|"flask run"*)
      if [[ ! "$start_cmd" =~ [\;\|\&\$\`] ]]; then
        is_safe_command=1
        exec_method="direct"
      fi
      ;;
  esac
  
  # If not a safe pattern, require explicit opt-in
  if [[ $is_safe_command -eq 0 ]]; then
    if [[ "$SLOP_ALLOW_UNSAFE_RUNTIME" != "1" ]]; then
      say ""
      say "  ${RED}⚠️  UNSAFE COMMAND DETECTED:${NC} $start_cmd"
      say "  ${YELLOW}This command contains shell metacharacters or is not a recognized safe pattern.${NC}"
      say "  ${YELLOW}For security, runtime check is SKIPPED by default.${NC}"
      say ""
      say "  To allow this command, set: ${CYAN}SLOP_ALLOW_UNSAFE_RUNTIME=1${NC}"
      say "  ${RED}WARNING: Only do this in ephemeral CI environments, NEVER on your local machine!${NC}"
      say ""
      
      emit_issue "local/runtime" "runtime" "medium" "." 1 \
        "Runtime check skipped - unsafe command" "Command '$start_cmd' requires SLOP_ALLOW_UNSAFE_RUNTIME=1" \
        "Custom start commands could be malicious. Only allow in trusted CI." 0.7 \
        "Set SLOP_ALLOW_UNSAFE_RUNTIME=1 in CI or use a standard start pattern"
      
      popd >/dev/null
      return 0
    else
      say "  ${RED}⚠️  UNSAFE MODE ENABLED - executing custom command${NC}"
      exec_method="unsafe"
    fi
  fi
  
  say ""
  say "  ${YELLOW}Starting application (${exec_method}):${NC} $start_cmd"
  say "  ${YELLOW}Port:${NC} $port"
  say ""
  
  # Start the application SAFELY (no eval!)
  local start_log="$WORKDIR/runtime_start.log"
  local start_pid
  local use_setsid=0
  
  # Check if setsid is available for process group isolation
  command -v setsid >/dev/null 2>&1 && use_setsid=1
  
  case "$exec_method" in
    npm)
      # Use npm directly - this is the safest option
      if [[ "$start_cmd" == "npm start"* ]]; then
        if [[ $use_setsid -eq 1 ]]; then
          setsid npm start > "$start_log" 2>&1 &
        else
          npm start > "$start_log" 2>&1 &
        fi
      elif [[ "$start_cmd" == "npm run dev"* ]]; then
        if [[ $use_setsid -eq 1 ]]; then
          setsid npm run dev > "$start_log" 2>&1 &
        else
          npm run dev > "$start_log" 2>&1 &
        fi
      elif [[ "$start_cmd" == "npm run serve"* ]]; then
        if [[ $use_setsid -eq 1 ]]; then
          setsid npm run serve > "$start_log" 2>&1 &
        else
          npm run serve > "$start_log" 2>&1 &
        fi
      else
        # Extract the npm run target
        local npm_target
        npm_target=$(echo "$start_cmd" | sed 's/npm run //')
        if [[ $use_setsid -eq 1 ]]; then
          setsid npm run "$npm_target" > "$start_log" 2>&1 &
        else
          npm run "$npm_target" > "$start_log" 2>&1 &
        fi
      fi
      start_pid=$!
      ;;
    docker-compose)
      docker-compose up -d > "$start_log" 2>&1
      start_pid=$$  # docker-compose detaches
      ;;
    direct)
      # Direct execution without shell interpretation
      # Use Python's shlex to properly handle quoted arguments (e.g., python "my script.py")
      local cmd_array
      IFS=$'\n' read -d '' -r -a cmd_array < <(python3 -c "import sys, shlex; print('\n'.join(shlex.split(sys.argv[1])))" "$start_cmd" 2>/dev/null) || {
        # Fallback to simple space-split if shlex fails
        read -ra cmd_array <<< "$start_cmd"
      }
      if [[ $use_setsid -eq 1 ]]; then
        setsid "${cmd_array[@]}" > "$start_log" 2>&1 &
      else
        "${cmd_array[@]}" > "$start_log" 2>&1 &
      fi
      start_pid=$!
      ;;
    unsafe)
      # User explicitly opted in - use bash -c (still safer than eval)
      say "  ${RED}Executing via bash -c (unsafe mode)${NC}"
      if [[ $use_setsid -eq 1 ]]; then
        setsid bash -c "$start_cmd" > "$start_log" 2>&1 &
      else
        bash -c "$start_cmd" > "$start_log" 2>&1 &
      fi
      start_pid=$!
      ;;
  esac
  
  # Wait for health endpoint
  say "  Waiting for health endpoint: http://localhost:${port}${health_endpoint}"
  local max_wait=60
  local waited=0
  local healthy=0
  
  while [[ $waited -lt $max_wait ]]; do
    if curl -sf "http://localhost:${port}${health_endpoint}" >/dev/null 2>&1; then
      healthy=1
      break
    fi
    
    # Also try common alternative ports
    for alt_port in 8080 8000 5000 4000; do
      if [[ "$alt_port" != "$port" ]] && curl -sf "http://localhost:${alt_port}${health_endpoint}" >/dev/null 2>&1; then
        say "  Found app on alternative port: $alt_port"
        port=$alt_port
        healthy=1
        break 2
      fi
    done
    
    sleep 2
    ((waited+=2))
    echo -n "."
  done
  echo ""
  
  if [[ $healthy -eq 1 ]]; then
    say "  ✓ Application healthy after ${waited}s (port $port)"
    
    # Run smoke tests against running app
    say "  Running smoke tests..."
    
    # Test health endpoint returns 200
    local health_response
    health_response=$(curl -sf "http://localhost:${port}${health_endpoint}" 2>/dev/null)
    if [[ -z "$health_response" ]]; then
      emit_issue "local/runtime" "runtime" "high" "." 1 \
        "Health endpoint returns empty response" "GET $health_endpoint returned empty body" \
        "Health endpoint should return meaningful status" 0.75 \
        "Return JSON status from health endpoint"
    fi
    
    # Check for obvious error pages
    local root_response
    root_response=$(curl -sf "http://localhost:${port}/" 2>/dev/null || true)
    if echo "$root_response" | grep -qiE "error|exception|500|internal server error"; then
      emit_issue "local/runtime" "runtime" "blocker" "." 1 \
        "Application root returns error" "GET / contains error message" \
        "Application crashes or errors on startup" 0.9 \
        "Fix application startup errors"
    fi
    
  else
    emit_issue "local/runtime" "runtime" "blocker" "." 1 \
      "Application failed to start" "Health endpoint not responding after ${max_wait}s" \
      "Application must be bootable to certify" 0.95 \
      "Fix startup issues; check $start_log for errors"
  fi
  
  # Cleanup - ONLY kill the process we started (not generic pkill patterns!)
  # This prevents the "bad neighbor" problem where we kill other developers' processes
  say "  Stopping application..."
  
  if [[ "$exec_method" == "docker-compose" ]]; then
    # Docker-compose has its own cleanup mechanism
    docker-compose down >/dev/null 2>&1 || true
  elif [[ -n "${start_pid:-}" ]] && [[ "$start_pid" != "$$" ]]; then
    # If we used setsid, the process is a session leader and we can kill the whole group
    # Using negative PID kills the entire process group
    if [[ $use_setsid -eq 1 ]]; then
      # Kill the whole process group (negative PID)
      kill -TERM -- -"$start_pid" 2>/dev/null || kill -TERM "$start_pid" 2>/dev/null || true
      sleep 1
      kill -9 -- -"$start_pid" 2>/dev/null || kill -9 "$start_pid" 2>/dev/null || true
    else
      # Fallback: kill children first, then parent
      pkill -P "$start_pid" 2>/dev/null || true
      kill "$start_pid" 2>/dev/null || true
      sleep 1
      kill -9 "$start_pid" 2>/dev/null || true
    fi
  fi
  
  popd >/dev/null
}

########################################
# REAL COVERAGE PARSING (not just "exists")
########################################
parse_coverage_report() {
  [[ "$SLOP_CERTIFY_MODE" == "1" ]] || return 0
  
  say "Parsing coverage reports..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  local coverage_found=0
  local coverage_percent=0
  
  # Check for various coverage report formats
  # NYC/Istanbul (JS/TS)
  if [[ -f "coverage/coverage-summary.json" ]]; then
    coverage_found=1
    coverage_percent=$(jq -r '.total.lines.pct // 0' coverage/coverage-summary.json 2>/dev/null)
    say "  Found NYC/Istanbul coverage: ${coverage_percent}%"
  fi
  
  # Vitest coverage
  if [[ -f "coverage/coverage-final.json" ]]; then
    coverage_found=1
    # Calculate from coverage-final.json
    coverage_percent=$(python3 -c "
import json
try:
    with open('coverage/coverage-final.json', 'r') as f:
        data = json.load(f)
    total_lines = 0
    covered_lines = 0
    for file_data in data.values():
        s = file_data.get('s', {})
        total_lines += len(s)
        covered_lines += sum(1 for v in s.values() if v > 0)
    print(round(covered_lines / total_lines * 100, 1) if total_lines > 0 else 0)
except:
    print(0)
" 2>/dev/null)
    say "  Found Vitest coverage: ${coverage_percent}%"
  fi
  
  # Python coverage.py
  if [[ -f ".coverage" ]] || [[ -f "htmlcov/index.html" ]]; then
    coverage_found=1
    if need_cmd coverage; then
      coverage_percent=$(coverage report 2>/dev/null | grep "TOTAL" | awk '{print $NF}' | tr -d '%')
      say "  Found Python coverage: ${coverage_percent}%"
    fi
  fi
  
  # Go coverage
  if [[ -f "coverage.out" ]]; then
    coverage_found=1
    coverage_percent=$(go tool cover -func=coverage.out 2>/dev/null | grep total | awk '{print $NF}' | tr -d '%')
    say "  Found Go coverage: ${coverage_percent}%"
  fi
  
  if [[ $coverage_found -eq 0 ]]; then
    emit_issue "local/coverage" "test-coverage" "high" "." 1 \
      "No coverage report found" "Could not find coverage/coverage-summary.json or similar" \
      "Certify mode requires coverage reports to verify test quality" 0.85 \
      "Run tests with coverage enabled (--coverage flag)"
    popd >/dev/null
    return 0
  fi
  
  # Check against goldrecord threshold
  local goldrecord_file="$root/$SLOP_GOLDRECORD_FILE"
  local min_coverage=70
  
  if [[ -f "$goldrecord_file" ]]; then
    min_coverage=$(python3 -c "
import yaml
try:
    with open('$goldrecord_file', 'r') as f:
        c = yaml.safe_load(f) or {}
    print(c.get('test_coverage', {}).get('minimum', 70))
except:
    print(70)
" 2>/dev/null)
  fi
  
  say "  Required coverage: ${min_coverage}%, Actual: ${coverage_percent}%"
  
  if (( $(echo "$coverage_percent < $min_coverage" | bc -l 2>/dev/null || echo 0) )); then
    emit_issue "local/coverage" "test-coverage" "blocker" "." 1 \
      "Coverage below threshold: ${coverage_percent}% < ${min_coverage}%" \
      "Test coverage is ${coverage_percent}%, required ${min_coverage}%" \
      "Insufficient test coverage means untested code paths" 0.95 \
      "Add tests to increase coverage to at least ${min_coverage}%"
  else
    say "  ✓ Coverage meets threshold"
  fi
  
  popd >/dev/null
}

########################################
# HARD NO-STUBS ENFORCEMENT
########################################
run_hard_stub_check() {
  [[ "$SLOP_CERTIFY_MODE" == "1" ]] || return 0
  
  say "Running hard stub enforcement..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null
  
  # Check for 501 Not Implemented returns
  rg -n --no-heading "501|Not Implemented|NotImplementedError" \
    --glob '!node_modules/*' --glob '!.git/*' --glob '!*test*' --glob '!*spec*' \
    . 2>/dev/null | head -20 | while IFS=: read -r file line content; do
    emit_issue "local/stub-check" "ai-slop" "blocker" "$file" "$line" \
      "501/NotImplemented in production code" "$content" \
      "Production code cannot return 'not implemented'" 0.95 \
      "Implement the functionality or remove the endpoint"
  done
  
  # Check for return {} / return [] stubs in route handlers
  rg -n --no-heading -e 'return\s*\{\s*\}' -e 'return\s*\[\s*\]' \
    --glob '!node_modules/*' --glob '!.git/*' --glob '!*test*' \
    --glob '*.ts' --glob '*.js' --glob '*.py' \
    . 2>/dev/null | while IFS=: read -r file line content; do
    # Skip if in a test file or if it's a valid empty return
    [[ "$file" == *"test"* ]] && continue
    [[ "$file" == *"spec"* ]] && continue
    
    emit_issue "local/stub-check" "ai-slop" "high" "$file" "$line" \
      "Empty return in production code" "$content" \
      "Returning empty objects may indicate stub code" 0.75 \
      "Verify this is intentional, not a placeholder"
  done
  
  # Check for mock servers in production imports
  rg -n --no-heading -e "from 'msw'" -e 'require.*msw' -e 'json-server' -e 'mock-server' \
    --glob '!node_modules/*' --glob '!.git/*' --glob '!*test*' --glob '!*mock*' \
    --glob '*.ts' --glob '*.js' \
    . 2>/dev/null | while IFS=: read -r file line content; do
    emit_issue "local/stub-check" "security" "blocker" "$file" "$line" \
      "Mock server imported in production code" "$content" \
      "Mock servers must not be in production bundles" 0.95 \
      "Move mock setup to test files only"
  done
  
  # Check for demo mode / fake data flags
  rg -n --no-heading -iE "(DEMO_MODE|FAKE_DATA|USE_MOCK|MOCK_API)\s*[=:]\s*(true|1|'true'|\"true\")" \
    --glob '!node_modules/*' --glob '!.git/*' \
    . 2>/dev/null | while IFS=: read -r file line content; do
    emit_issue "local/stub-check" "security" "high" "$file" "$line" \
      "Demo/mock mode enabled by default" "$content" \
      "Demo modes should be disabled by default" 0.85 \
      "Set demo mode to false/0 by default"
  done
  
  popd >/dev/null
}

########################################
# GENERATE RELEASE DOSSIER
########################################
generate_dossier() {
  [[ "$SLOP_CERTIFY_MODE" == "1" ]] || return 0
  
  say "Generating release dossier..."
  local root
  root="$(repo_root)"
  local ts
  ts="$(ts_utc)"
  local dossier_dir="$root/.gatekeeper/dossier-${ts}"
  mkdir -p "$dossier_dir"
  mkdir -p "$dossier_dir/evidence"
  
  # Copy evidence files
  if [[ -d "$WORKDIR/evidence" ]]; then
    cp -r "$WORKDIR/evidence"/* "$dossier_dir/evidence/" 2>/dev/null || true
  fi
  
  # Copy inventory
  if [[ -f "$WORKDIR/inventory.json" ]]; then
    cp "$WORKDIR/inventory.json" "$dossier_dir/"
  fi
  
  # Generate summary
  local issue_count
  issue_count=$(wc -l < "$ISSUES_JSONL" 2>/dev/null || echo 0)
  local blocker_count
  blocker_count=$(grep -c '"severity":"blocker"' "$ISSUES_JSONL" 2>/dev/null || echo 0)
  
  local git_sha
  git_sha=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
  local git_branch
  git_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
  
  cat > "$dossier_dir/summary.json" <<EOF
{
  "scanner_version": "$VERSION",
  "mode": "$MODE",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git": {
    "sha": "$git_sha",
    "branch": "$git_branch"
  },
  "result": {
    "total_issues": $issue_count,
    "blockers": $blocker_count,
    "certified": $([ "$blocker_count" -eq 0 ] && echo "true" || echo "false")
  }
}
EOF

  # Generate traceability report
  if [[ -f "$root/$SLOP_GOLDRECORD_FILE" ]]; then
    python3 - "$root/$SLOP_GOLDRECORD_FILE" "$WORKDIR/inventory.json" "$dossier_dir/traceability.json" <<'PYTHON'
import sys
import json

try:
    import yaml
    with open(sys.argv[1], 'r') as f:
        contract = yaml.safe_load(f) or {}
except:
    contract = {}

try:
    with open(sys.argv[2], 'r') as f:
        inventory = json.load(f)
except:
    inventory = {}

traceability = {
    "flows": [],
    "coverage": {
        "declared_flows": len(contract.get('user_flows', [])),
        "discovered_endpoints": len(inventory.get('api_endpoints', [])),
        "discovered_routes": len(inventory.get('ui_routes', []))
    }
}

for flow in contract.get('user_flows', []):
    if not isinstance(flow, dict):
        continue
    traceability["flows"].append({
        "id": flow.get('id'),
        "name": flow.get('name'),
        "test_files": flow.get('test_files', []),
        "api_calls": flow.get('api_calls', []),
        "ui_routes": flow.get('ui_routes', [])
    })

with open(sys.argv[3], 'w') as f:
    json.dump(traceability, f, indent=2)
PYTHON
  fi
  
  say "  Dossier generated: $dossier_dir"
  say "  Summary: $issue_count issues, $blocker_count blockers"
  
  if [[ "$blocker_count" -eq 0 ]]; then
    say "  ✓ CERTIFIED: Ready for release"
  else
    say "  ✗ NOT CERTIFIED: $blocker_count blockers must be resolved"
  fi
}

########################################
# Pattern-based scanning (ripgrep)
########################################
rg_scan() {
  local category="$1" severity="$2" title="$3" pattern="$4" why="$5" confidence="$6"
  
  rg -n --no-heading --color never \
     --glob '!.git/*' \
     --glob '!node_modules/*' \
     --glob '!vendor/*' \
     --glob '!dist/*' \
     --glob '!build/*' \
     --glob '!target/*' \
     --glob '!*.min.js' \
     --glob '!*.min.css' \
     --glob '!package-lock.json' \
     --glob '!yarn.lock' \
     --glob '!pnpm-lock.yaml' \
     --glob '!.gatekeeper/*' \
     --max-columns 300 \
     -e "$pattern" \
     . 2>/dev/null \
    | head -n "$SLOP_MAX_MATCHES_PER_RULE" \
    | while IFS=: read -r file line_num context; do
        [[ -z "$file" ]] && continue
        [[ "$line_num" =~ ^[0-9]+$ ]] || line_num=1
        emit_issue "local/rg" "$category" "$severity" "$file" "$line_num" \
          "$title" "$context" "$why" "$confidence" ""
      done || true
}

run_pattern_scans() {
  say "Running pattern scans..."

  # ═══════════════════════════════════════════════════════════════════════════
  # AI SLOP PHRASES - Critical (The dead giveaways)
  # Inspired by KarpeSlop and SloppyLint
  # ═══════════════════════════════════════════════════════════════════════════
  
  # KarpeSlop-style: Information Quality (Lies) - AI placeholder phrases
  rg_scan "ai-slop" "blocker" "AI placeholder phrase" \
    '(?i)\b(here is a (simple|basic)|you (would|will|should) need to|implement your own|for (simplicity|brevity|demonstration)|in (this example|a real (scenario|application))|beyond the scope|exercise for the reader|left as an exercise|simplified (version|for)|would look like|actual implementation|production implementation)\b' \
    "AI-generated placeholder text indicates incomplete implementation" 0.9

  # KarpeSlop-style: Information Utility (Noise) - Hedging language
  rg_scan "ai-slop" "high" "AI hedging language" \
    '(?i)\b(the important thing is|for the purposes of this|omitted for brevity|not fully implemented|this (should|might|may) work|in theory|ideally|in an ideal world|generally speaking|as a general rule)\b' \
    "Hedging language often indicates AI uncertainty or incomplete implementation" 0.75

  # KarpeSlop-style: Style/Taste (Soul) - Overconfident comments
  rg_scan "ai-slop" "medium" "AI overconfident comment" \
    '(?i)(\/\/|#)\s*(obviously|clearly|of course|as you can see|it.?s (clear|obvious|simple)|trivially|straightforward(ly)?)\b' \
    "Overconfident comments often mask complexity or incomplete understanding" 0.6

  # SloppyLint-style: Vibe coding patterns
  rg_scan "ai-slop" "high" "Vibe coding pattern" \
    '(?i)\b(this (works|should work)|magic (number|string|value)|hack(y|ed)?|workaround|quick (fix|hack)|temporary (fix|solution)|bandaid|band-aid)\b' \
    "Vibe coding patterns indicate shortcuts that may need proper implementation" 0.7

  # AI boilerplate detection
  rg_scan "ai-slop" "medium" "AI boilerplate pattern" \
    '(?i)(\/\*\*?\s*\n\s*\*\s*@(description|param|returns?|example)\s*[A-Z][a-z]+\s+(the|a|an)\s+)' \
    "Generic JSDoc/docstring patterns often indicate AI-generated documentation" 0.55

  # ═══════════════════════════════════════════════════════════════════════════
  # PLACEHOLDERS (High)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "placeholder" "high" "TODO/FIXME/HACK marker" \
    '(?i)\b(TODO|FIXME|XXX|HACK|TEMP|WIP|TBD|PLACEHOLDER|CHANGEME|REMOVEME)\b' \
    "Unfinished work markers - prioritize if in production paths" 0.7

  rg_scan "placeholder" "high" "NotImplemented exceptions" \
    '(?i)(NotImplementedError|NotImplementedException|raise.*not.?implemented|throw.*not.?implemented|unimplemented!|todo!)' \
    "Explicit not-implemented markers indicate incomplete code" 0.85

  # ═══════════════════════════════════════════════════════════════════════════
  # STUBS (High)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "stub" "high" "Stub/scaffold/placeholder code" \
    '(?i)\b(stub(bed)?|scaffold(ed)?|placeholder|fake.?data|dummy.?data|sample.?data|lorem.?ipsum|implementation.?omitted|omitted.?for.?brevity)\b' \
    "Stub/placeholder implementation - verify real functionality exists" 0.75

  # SloppyLint-style: Pass placeholder
  rg_scan "stub" "high" "Pass placeholder in function" \
    '^\s*def\s+\w+\s*\([^)]*\)\s*:\s*\n\s*pass\s*$' \
    "Empty function body with pass indicates unimplemented function" 0.8

  # ═══════════════════════════════════════════════════════════════════════════
  # TEST QUALITY (Critical)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "test-quality" "blocker" "Tautology test" \
    '(expect\(true\)\.toBe\(true\)|expect\(1\)\.toBe\(1\)|assert True$|assertTrue\(true\)|assertEquals\(1,\s*1\)|assert_eq!\(1,\s*1\))' \
    "Test asserts nothing meaningful - always passes" 0.95

  rg_scan "test-quality" "high" "Skipped/disabled test" \
    '(?i)(describe\.skip|it\.skip|test\.skip|@skip|@pytest\.mark\.skip|@unittest\.skip|@Ignore|@Disabled|xit\(|xdescribe\(|xtest\(|pending\()' \
    "Skipped tests reduce coverage and can hide failures" 0.8

  rg_scan "test-quality" "high" "Empty test body" \
    '(?i)(it\s*\(\s*["\x27][^"]+["\x27]\s*,\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)|def\s+test_\w+\s*\([^)]*\)\s*:\s*\n\s*(pass|\.\.\.)\s*$)' \
    "Empty test body means no actual testing occurs" 0.9

  # ═══════════════════════════════════════════════════════════════════════════
  # SECURITY (Blocker)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "security" "blocker" "Hardcoded secret/credential" \
    '(?i)(password|secret|api.?key|apikey|access.?token|private.?key|mnemonic)\s*[=:]\s*["\x27][^"\x27]{8,}' \
    "Hardcoded credentials are a security vulnerability" 0.9

  rg_scan "security" "blocker" "Private key in code" \
    '(BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE|PRIVATE KEY)' \
    "Private key material should never be in code" 0.95

  rg_scan "security" "blocker" "TLS/SSL verification disabled" \
    '(?i)(rejectUnauthorized\s*:\s*false|tlsInsecureSkipVerify|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER.*false)' \
    "Disabling TLS verification is a security vulnerability" 0.9

  rg_scan "security" "high" "CORS wildcard" \
    '(?i)(Access-Control-Allow-Origin.*\*|cors.*\*|allowedOrigins.*\*)' \
    "CORS wildcard can allow unauthorized cross-origin requests" 0.75

  rg_scan "security" "high" "Eval/exec usage" \
    '(?i)(eval\s*\(|exec\s*\(|dangerouslySetInnerHTML|innerHTML\s*=|v-html|__import__)' \
    "Dynamic code execution can lead to injection vulnerabilities" 0.7

  rg_scan "security" "high" "SQL string concatenation" \
    '(?i)(execute\s*\(\s*["\x27].*\+|query\s*\(\s*["\x27].*\+|cursor\.execute\s*\(\s*f["\x27])' \
    "SQL string concatenation can lead to SQL injection" 0.75

  # ═══════════════════════════════════════════════════════════════════════════
  # CI/BUILD (High)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "ci" "high" "CI step forced green" \
    '(?i)(continue-on-error:\s*true|\|\|\s*true\b|;\s*true$|exit\s+0.*#.*(test|lint|build)|set\s+\+e)' \
    "Pattern forces CI success - can mask broken builds/tests" 0.85

  # ═══════════════════════════════════════════════════════════════════════════
  # ERROR HANDLING (Medium)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "error-handling" "medium" "Swallowed exception" \
    '(?i)(catch\s*\([^)]*\)\s*\{\s*\}|except\s*:\s*pass|rescue\s*=>\s*nil|catch\s*\{\s*\})' \
    "Empty catch/except blocks hide errors" 0.65

  # SloppyLint-style: Bare except
  rg_scan "error-handling" "high" "Bare except clause" \
    '^\s*except\s*:\s*$' \
    "Bare except catches SystemExit and KeyboardInterrupt - use specific exceptions" 0.85

  # ═══════════════════════════════════════════════════════════════════════════
  # DEBUG LEFTOVERS (Medium)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "debug" "medium" "Debug statement left in" \
    '(?i)(console\.(log|debug|info)\s*\(|debugger;?$|pdb\.set_trace|breakpoint\(\)|binding\.pry|byebug|import\s+pdb)' \
    "Debug statements should be removed before production" 0.6

  # ═══════════════════════════════════════════════════════════════════════════
  # DEAD CODE (Medium)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "dead-code" "medium" "Linter/type suppression" \
    '(?i)(eslint-disable|noqa|type:\s*ignore|@ts-ignore|@ts-nocheck|@SuppressWarnings|noinspection|NOSONAR|nosec|pragma:\s*no\s*cover|@ts-expect-error)' \
    "Suppressed warnings often indicate underlying issues" 0.55

  # ═══════════════════════════════════════════════════════════════════════════
  # MOCKS IN PROD (Medium)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "mock" "medium" "Mock/localhost endpoint" \
    '(?i)(localhost|127\.0\.0\.1|example\.com|jsonplaceholder|mockserver|mock-api|httpbin\.org)' \
    "Mock endpoints in code paths may indicate incomplete integration" 0.5

  # ═══════════════════════════════════════════════════════════════════════════
  # KARPESLOP-STYLE: TYPE SAFETY (JS/TS specific)
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "type-safety" "high" "TypeScript any abuse" \
    ':\s*any\b|as\s+any\b|<any>' \
    "Using 'any' type defeats TypeScript's type safety" 0.7

  rg_scan "type-safety" "medium" "Non-null assertion abuse" \
    '!\.' \
    "Non-null assertions (!) can hide null pointer issues" 0.5

  # ═══════════════════════════════════════════════════════════════════════════
  # SLOPPYLINT-STYLE: PYTHON ANTI-PATTERNS
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "python-antipattern" "high" "Mutable default argument" \
    'def\s+\w+\s*\([^)]*=\s*\[\s*\]|def\s+\w+\s*\([^)]*=\s*\{\s*\}' \
    "Mutable default arguments are shared between calls - use None instead" 0.9

  rg_scan "python-antipattern" "medium" "Global variable modification" \
    '^\s*global\s+\w+' \
    "Global variable modification makes code harder to reason about" 0.6

  # ═══════════════════════════════════════════════════════════════════════════
  # HALLUCINATED IMPORTS (KarpeSlop-inspired)
  # Common fake packages that AI often suggests
  # ═══════════════════════════════════════════════════════════════════════════
  
  rg_scan "hallucinated-import" "blocker" "Potentially hallucinated import" \
    '(?i)(from\s+(flask_gpt|django_ai|react_helper|vue_utils|angular_helper|express_ai|fastapi_helper|nextjs_utils)\s+import|import\s+(flask_gpt|django_ai|react_helper|vue_utils|angular_helper|express_ai|fastapi_helper|nextjs_utils))' \
    "This import pattern matches commonly hallucinated AI package names" 0.85

  say "Pattern scans complete"
}

########################################
# Structural checks
########################################
run_structural_checks() {
  say "Running structural checks..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # Missing README
  if [[ ! -f README.md && ! -f readme.md && ! -f README.MD && ! -f README.rst ]]; then
    emit_issue "local/structure" "docs" "high" "README.md" 1 \
      "Missing README" "No README found in repo root" \
      "Projects without README are difficult to onboard and often indicate incomplete setup" 0.85 \
      "Create a README.md with project description, setup instructions, and usage examples"
  fi

  # node_modules tracked in git
  if is_git_repo && [[ -d node_modules ]]; then
    if git ls-files node_modules 2>/dev/null | head -1 | grep -q .; then
      emit_issue "local/structure" "repo-hygiene" "blocker" "node_modules" 1 \
        "node_modules tracked by git" "git ls-files includes node_modules" \
        "Tracking node_modules causes massive bloat and inconsistent builds" 0.95 \
        "Add node_modules to .gitignore and remove from git history"
    fi
  fi

  # .env committed
  if is_git_repo && git ls-files 2>/dev/null | grep -qE '(^|/)\.env$'; then
    emit_issue "local/structure" "security" "blocker" ".env" 1 \
      ".env file committed to git" ".env is tracked by git" \
      "High risk of leaked credentials and environment drift" 0.95 \
      "Add .env to .gitignore, remove from git history, use .env.example template"
  fi

  # Large files tracked (>10MB)
  if is_git_repo; then
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      local sz
      sz="$(stat -c%s "$f" 2>/dev/null || echo 0)"
      if [[ "$sz" -ge 10485760 ]]; then
        emit_issue "local/structure" "repo-hygiene" "medium" "$f" 1 \
          "Large file tracked (>10MB)" "size=$sz bytes" \
          "Large files in git cause slow clones; consider Git LFS or external storage" 0.7 \
          "Move to Git LFS or external storage"
      fi
    done < <(git ls-files 2>/dev/null | head -100)
  fi

  # package.json fake test script
  if [[ -f package.json ]]; then
    local test_script
    test_script=$(jq -r '.scripts.test // ""' package.json 2>/dev/null)
    if [[ "$test_script" == *"no test specified"* ]] || [[ "$test_script" == *"exit 1"* ]] || [[ "$test_script" == "echo"* ]]; then
      emit_issue "local/structure" "test-quality" "high" "package.json" 1 \
        "Placeholder test script" "scripts.test: $test_script" \
        "Fake test script means no tests run in CI" 0.9 \
        "Configure actual test runner (jest, vitest, mocha, etc.)"
    fi
  fi

  # Missing test files
  local src_count test_count
  src_count=$(find . -type f \( -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.rs" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" ! -path "*/build/*" \
    ! -name "*.test.*" ! -name "*.spec.*" ! -name "test_*" ! -name "*_test.*" 2>/dev/null | wc -l)
  test_count=$(find . -type f \( -name "*.test.*" -o -name "*.spec.*" -o -name "test_*" -o -name "*_test.*" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" 2>/dev/null | wc -l)
  
  if [[ "$src_count" -gt 10 ]] && [[ "$test_count" -eq 0 ]]; then
    emit_issue "local/structure" "test-coverage" "blocker" "." 1 \
      "No test files found" "$src_count source files, 0 test files" \
      "Zero test coverage is a major quality risk" 0.9 \
      "Add unit tests for core functionality"
  fi

  popd >/dev/null
}

########################################
# Doc drift detection
########################################
run_doc_drift_checks() {
  say "Checking for doc drift..."
  local root
  root="$(repo_root)"
  
  [[ -f "$root/package.json" ]] || return 0

  python3 - "$root" "$ISSUES_JSONL" <<'PYTHON'
import sys, json, re, pathlib

root = pathlib.Path(sys.argv[1])
issues_jsonl = sys.argv[2]

try:
    pkg = json.loads((root / "package.json").read_text())
except:
    sys.exit(0)

scripts = set((pkg.get("scripts") or {}).keys())
if not scripts:
    sys.exit(0)

pat = re.compile(r'\b(?:npm|pnpm|yarn)\s+run\s+([A-Za-z0-9:_-]+)\b')
missing = {}

for md in root.rglob("*.md"):
    if ".git" in str(md) or "node_modules" in str(md):
        continue
    try:
        text = md.read_text(errors="ignore")
    except:
        continue
    for m in pat.finditer(text):
        script = m.group(1)
        if script not in scripts:
            missing.setdefault(script, []).append(str(md.relative_to(root)))

for script, files in missing.items():
    issue = {
        "source": "local/doc-drift",
        "category": "doc-drift",
        "severity": "high",
        "file": "package.json",
        "line": 1,
        "title": f"Docs reference missing npm script: {script}",
        "evidence": f"Referenced in: {', '.join(files[:5])}" + ("..." if len(files) > 5 else ""),
        "why": "README/docs reference npm scripts that don't exist - commands won't work",
        "confidence": 0.85,
        "fix": f"Either add '{script}' to package.json scripts or update documentation"
    }
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")
PYTHON
}

########################################
# Empty/Stub file detection (AI scaffold smell)
########################################
run_empty_file_detection() {
  say "Detecting empty/stub files..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # Find source files with ≤2 non-blank lines (common AI scaffold pattern)
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    local nonblank
    nonblank=$(awk 'NF{c++} END{print c+0}' "$f" 2>/dev/null || echo 0)
    if [[ "$nonblank" -le 2 ]]; then
      emit_issue "local/scaffold" "ai-slop" "high" "$f" 1 \
        "Empty/stub file ($nonblank non-blank lines)" "File has only $nonblank lines of actual code" \
        "Near-empty source files are a classic sign of AI-generated scaffolds with no implementation" 0.85 \
        "Either implement the functionality or remove the file"
    fi
  done < <(find . -type f \( -name "*.py" -o -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" \
    -o -name "*.go" -o -name "*.rs" -o -name "*.java" -o -name "*.rb" -o -name "*.php" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" ! -path "*/build/*" \
    ! -path "*/__pycache__/*" ! -path "*/.venv/*" ! -path "*/vendor/*" 2>/dev/null | head -200)

  popd >/dev/null
}

########################################
# Broken path detection in docs
########################################
run_broken_path_checks() {
  say "Checking for broken paths in documentation..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # Find README/doc files and check if referenced paths exist
  while IFS= read -r doc; do
    [[ -f "$doc" ]] || continue
    
    # Extract local path references (./something, docs/something, src/something)
    while IFS= read -r ref; do
      # Clean up the reference
      ref=$(echo "$ref" | sed 's/[),.;:\"'"'"']$//' | sed 's/^[\"'"'"']//')
      [[ -z "$ref" ]] && continue
      
      # Skip URLs, anchors, common false positives
      [[ "$ref" == http* ]] && continue
      [[ "$ref" == mailto:* ]] && continue
      [[ "$ref" == "#"* ]] && continue
      [[ "$ref" == *"\$"* ]] && continue
      
      # Check if path exists
      if [[ ! -e "$ref" ]]; then
        emit_issue "local/doc-drift" "docs" "medium" "$doc" 1 \
          "Broken path reference: $ref" "Path '$ref' referenced in documentation does not exist" \
          "Broken documentation references confuse users and indicate docs are out of sync with code" 0.75 \
          "Either create the missing path or update the documentation"
      fi
    done < <(rg -o --no-filename '(?:\./|docs/|src/|packages/|lib/|examples/)[A-Za-z0-9_./-]+' "$doc" 2>/dev/null | sort -u | head -50)
  done < <(find . -maxdepth 3 -type f \( -name "README*" -o -name "CONTRIBUTING*" -o -name "*.md" \) \
    ! -path "*/.git/*" ! -path "*/node_modules/*" 2>/dev/null | head -50)

  popd >/dev/null
}

########################################
# Multiple lockfile detection (package manager confusion)
########################################
run_lockfile_checks() {
  say "Checking for multiple lockfiles..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  local locks=()
  local lock_names=()
  
  # Node lockfiles
  [[ -f "package-lock.json" ]] && locks+=("package-lock.json") && lock_names+=("npm")
  [[ -f "yarn.lock" ]] && locks+=("yarn.lock") && lock_names+=("yarn")
  [[ -f "pnpm-lock.yaml" ]] && locks+=("pnpm-lock.yaml") && lock_names+=("pnpm")
  [[ -f "bun.lockb" ]] && locks+=("bun.lockb") && lock_names+=("bun")
  
  # Python lockfiles
  local py_locks=()
  [[ -f "poetry.lock" ]] && py_locks+=("poetry")
  [[ -f "Pipfile.lock" ]] && py_locks+=("pipenv")
  [[ -f "pdm.lock" ]] && py_locks+=("pdm")
  [[ -f "uv.lock" ]] && py_locks+=("uv")
  
  # Flag multiple Node lockfiles
  if [[ "${#locks[@]}" -gt 1 ]]; then
    emit_issue "local/structure" "repo-hygiene" "high" "." 1 \
      "Multiple Node.js lockfiles detected" "Found: ${locks[*]}" \
      "Multiple lockfiles indicate package manager confusion, can cause dependency mismatches and CI issues" 0.9 \
      "Pick one package manager (${lock_names[*]}) and remove the other lockfiles"
  fi
  
  # Flag multiple Python lockfiles
  if [[ "${#py_locks[@]}" -gt 1 ]]; then
    emit_issue "local/structure" "repo-hygiene" "high" "." 1 \
      "Multiple Python lockfiles detected" "Found lockfiles for: ${py_locks[*]}" \
      "Multiple Python lockfiles indicate confusion about dependency management" 0.9 \
      "Pick one tool (${py_locks[*]}) and remove the others"
  fi

  popd >/dev/null
}

########################################
# Test signal heuristics
########################################
run_test_signals() {
  say "Analyzing test signals..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  local signals=()
  local issues=()

  # Check for test directories
  [[ -d tests ]] && signals+=("tests_dir")
  [[ -d test ]] && signals+=("test_dir")
  [[ -d __tests__ ]] && signals+=("jest_tests")
  [[ -d spec ]] && signals+=("rspec")
  [[ -d cypress ]] && signals+=("cypress")
  [[ -d e2e ]] && signals+=("e2e")

  # Check for test config files
  [[ -f jest.config.js || -f jest.config.ts || -f jest.config.mjs ]] && signals+=("jest_config")
  [[ -f vitest.config.js || -f vitest.config.ts || -f vitest.config.mjs ]] && signals+=("vitest_config")
  [[ -f pytest.ini ]] && signals+=("pytest")
  [[ -f pyproject.toml ]] && grep -q pytest pyproject.toml 2>/dev/null && signals+=("pytest_toml")
  [[ -f .mocharc.js || -f .mocharc.json || -f .mocharc.yaml ]] && signals+=("mocha_config")
  [[ -f cypress.config.js || -f cypress.config.ts ]] && signals+=("cypress_config")
  [[ -f playwright.config.js || -f playwright.config.ts ]] && signals+=("playwright")
  [[ -f karma.conf.js ]] && signals+=("karma")

  # Check package.json for test script
  if [[ -f package.json ]]; then
    if jq -e '.scripts.test' package.json >/dev/null 2>&1; then
      local test_cmd
      test_cmd=$(jq -r '.scripts.test // ""' package.json 2>/dev/null)
      
      # Check if it's a real test command
      if [[ "$test_cmd" == *"jest"* ]] || [[ "$test_cmd" == *"vitest"* ]] || \
         [[ "$test_cmd" == *"mocha"* ]] || [[ "$test_cmd" == *"ava"* ]] || \
         [[ "$test_cmd" == *"tap"* ]] || [[ "$test_cmd" == *"playwright"* ]] || \
         [[ "$test_cmd" == *"cypress"* ]]; then
        signals+=("npm_test_real")
      fi
    fi
  fi

  # Count actual test files
  local test_file_count
  test_file_count=$(find . -type f \( -name "*.test.*" -o -name "*.spec.*" -o -name "test_*.py" -o -name "*_test.py" \
    -o -name "*_test.go" -o -name "*_test.rs" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" 2>/dev/null | wc -l)

  # Check for CI test jobs
  local ci_tests=0
  if [[ -d .github/workflows ]]; then
    if grep -rqE '\b(test|pytest|jest|vitest|mocha|cypress|playwright)\b' .github/workflows/ 2>/dev/null; then
      signals+=("github_ci_tests")
      ci_tests=1
    fi
  fi

  # Evaluate test health
  if [[ "${#signals[@]}" -eq 0 ]] && [[ "$test_file_count" -eq 0 ]]; then
    emit_issue "local/test-analysis" "test-coverage" "blocker" "." 1 \
      "No testing infrastructure detected" "No test dirs, configs, or test files found" \
      "Complete absence of testing setup indicates high technical debt risk" 0.95 \
      "Set up a testing framework (jest for JS/TS, pytest for Python) and add initial tests"
  elif [[ "$test_file_count" -gt 0 ]] && [[ "${#signals[@]}" -lt 2 ]]; then
    emit_issue "local/test-analysis" "test-coverage" "medium" "." 1 \
      "Minimal testing infrastructure" "Found $test_file_count test files but limited config/CI integration" \
      "Tests exist but may not be running in CI or have proper configuration" 0.7 \
      "Add test configuration and CI integration"
  fi

  # Check for coverage configuration
  local has_coverage=0
  if [[ -f .nycrc ]] || [[ -f .nycrc.json ]] || [[ -f .c8rc ]] || [[ -f coverage.xml ]] || \
     [[ -f .coveragerc ]] || [[ -f htmlcov ]]; then
    has_coverage=1
  fi
  if grep -q "coverage" package.json 2>/dev/null || grep -q "pytest-cov" pyproject.toml 2>/dev/null; then
    has_coverage=1
  fi

  if [[ "$test_file_count" -gt 5 ]] && [[ "$has_coverage" -eq 0 ]]; then
    emit_issue "local/test-analysis" "test-coverage" "low" "." 1 \
      "No coverage configuration detected" "Tests exist but no coverage tooling found" \
      "Without coverage tracking, you can't measure test effectiveness" 0.6 \
      "Add coverage configuration (c8/nyc for JS, pytest-cov for Python)"
  fi

  popd >/dev/null
}

########################################
# Agentic Mess Detection (AI work artifacts)
########################################
run_agentic_mess_detection() {
  say "Detecting agentic mess (AI work artifacts)..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # Patterns for AI-generated junk files
  local -a junk_patterns=(
    # Claude/GPT conversation artifacts
    'cleanup-*.md'
    'response*.md'
    'prompt*.txt'
    'prompt*.md'
    'conversation*.md'
    'chat*.md'
    'output*.md'
    'result*.md'
    'analysis*.md'
    'review*.md'
    # Agentic work logs
    '.gatekeeper/*.md'
    '.slopscan/*.md'
    '*-report.md'
    '*_report.md'
    'scan-*.md'
    'audit-*.md'
    # Temporary AI outputs
    'temp*.md'
    'tmp*.md'
    'draft*.md'
    'wip*.md'
    'todo*.md'
    'notes*.md'
    # Plan files from agents
    'plan*.md'
    'stage-*.md'
    'progress*.md'
    'overview*.md'
    # Debug/log artifacts
    '*.log'
    'debug*.txt'
    'trace*.txt'
  )

  local found_junk=0
  for pattern in "${junk_patterns[@]}"; do
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      # Skip legitimate files
      [[ "$f" == "README.md" ]] && continue
      [[ "$f" == "CHANGELOG.md" ]] && continue
      [[ "$f" == "CONTRIBUTING.md" ]] && continue
      [[ "$f" == "SECURITY.md" ]] && continue
      [[ "$f" == "LICENSE.md" ]] && continue
      [[ "$f" == *"/docs/"* ]] && continue
      [[ "$f" == ".github/"* ]] && continue
      
      emit_issue "local/agentic-mess" "cleanup" "medium" "$f" 1 \
        "Potential agentic work artifact" "File matches AI output pattern: $pattern" \
        "Stray AI-generated files clutter the repo and may contain sensitive prompts or incomplete work" 0.7 \
        "Review and delete if not needed, or move to appropriate location"
      found_junk=1
    done < <(find . -name "$pattern" ! -path "*/.git/*" ! -path "*/node_modules/*" 2>/dev/null | head -50)
  done

  # Check for AI conversation markers in files
  local ai_markers=(
    "as an AI"
    "As an AI"
    "I'm Claude"
    "I am Claude"
    "I'm an AI"
    "language model"
    "ChatGPT"
    "OpenAI"
    "Anthropic"
    "Claude Code"
    "generated by Claude"
    "generated by GPT"
    "## Assistant"
    "## Human"
    "<assistant>"
    "</assistant>"
    "<human>"
    "</human>"
  )

  for marker in "${ai_markers[@]}"; do
    while IFS=: read -r file line_num content; do
      [[ -z "$file" ]] && continue
      # Skip this script itself
      [[ "$file" == *"slop-scanner"* ]] && continue
      [[ "$file" == *".sh" ]] && continue
      
      emit_issue "local/agentic-mess" "cleanup" "high" "$file" "$line_num" \
        "AI conversation marker in source" "Found: '$marker'" \
        "AI conversation artifacts should not be in production code" 0.85 \
        "Remove AI conversation markers and review file contents"
    done < <(rg -n --no-heading -F "$marker" \
      --glob '!*.sh' \
      --glob '!node_modules/*' \
      --glob '!.git/*' \
      . 2>/dev/null | head -20)
  done

  # Check for orphaned plan/stage directories
  for dir in .gatekeeper/plans .slopscan/runs .claude; do
    if [[ -d "$dir" ]]; then
      local file_count
      file_count=$(find "$dir" -type f 2>/dev/null | wc -l)
      if [[ "$file_count" -gt 10 ]]; then
        emit_issue "local/agentic-mess" "cleanup" "low" "$dir" 1 \
          "Large agentic work directory" "$file_count files in $dir" \
          "Old agentic work artifacts accumulate; periodically clean up" 0.6 \
          "Review and clean up old runs/plans"
      fi
    fi
  done

  popd >/dev/null
}

########################################
# Documentation Quality Enforcement
########################################
run_docs_quality_check() {
  say "Checking documentation quality..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # README completeness check
  if [[ -f README.md ]]; then
    local readme_lines readme_sections
    readme_lines=$(wc -l < README.md)
    readme_sections=$(grep -cE '^#{1,3} ' README.md 2>/dev/null || echo 0)
    
    if [[ "$readme_lines" -lt 50 ]]; then
      emit_issue "local/docs-quality" "docs" "high" "README.md" 1 \
        "README is too short ($readme_lines lines)" "Comprehensive README should have 100+ lines" \
        "Short README indicates incomplete documentation" 0.8 \
        "Add: description, installation, usage, API docs, contributing guide"
    fi

    # Check for essential sections
    local missing_sections=()
    grep -qiE '^#{1,3}.*install' README.md 2>/dev/null || missing_sections+=("Installation")
    grep -qiE '^#{1,3}.*usage|getting started' README.md 2>/dev/null || missing_sections+=("Usage/Getting Started")
    grep -qiE '^#{1,3}.*api|endpoint' README.md 2>/dev/null || missing_sections+=("API Documentation")
    grep -qiE '^#{1,3}.*contribut' README.md 2>/dev/null || missing_sections+=("Contributing")
    grep -qiE '^#{1,3}.*license' README.md 2>/dev/null || missing_sections+=("License")

    if [[ "${#missing_sections[@]}" -gt 2 ]]; then
      emit_issue "local/docs-quality" "docs" "high" "README.md" 1 \
        "README missing essential sections" "Missing: ${missing_sections[*]}" \
        "Production READMEs should include standard sections" 0.85 \
        "Add missing sections: ${missing_sections[*]}"
    fi

    # Check for placeholder content
    if grep -qiE '(lorem ipsum|placeholder|TODO|coming soon|TBD|to be|will be added)' README.md 2>/dev/null; then
      emit_issue "local/docs-quality" "docs" "blocker" "README.md" 1 \
        "README contains placeholder content" "Found 'TODO', 'TBD', 'coming soon', or similar" \
        "Placeholder text in README is a DD red flag" 0.9 \
        "Replace all placeholder content with actual documentation"
    fi
  fi

  # Architecture documentation check
  local has_arch_docs=0
  for arch_file in ARCHITECTURE.md architecture.md docs/ARCHITECTURE.md docs/architecture.md \
                   DESIGN.md design.md docs/DESIGN.md docs/design.md \
                   docs/README.md docs/overview.md; do
    if [[ -f "$arch_file" ]]; then
      has_arch_docs=1
      
      # Check if it's substantive
      local arch_lines
      arch_lines=$(wc -l < "$arch_file")
      if [[ "$arch_lines" -lt 30 ]]; then
        emit_issue "local/docs-quality" "docs" "medium" "$arch_file" 1 \
          "Architecture doc is too short ($arch_lines lines)" "Substantive arch docs should be 50+ lines" \
          "Architecture documentation should explain system design decisions" 0.7 \
          "Expand with: system overview, components, data flow, deployment"
      fi
      break
    fi
  done

  # Flag missing arch docs for larger projects
  local src_file_count
  src_file_count=$(find . -type f \( -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.go" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null | wc -l)
  
  if [[ "$src_file_count" -gt 20 ]] && [[ "$has_arch_docs" -eq 0 ]]; then
    emit_issue "local/docs-quality" "docs" "high" "." 1 \
      "No architecture documentation found" "$src_file_count source files but no ARCHITECTURE.md or docs/" \
      "Larger projects need architecture documentation for maintainability" 0.8 \
      "Create ARCHITECTURE.md explaining system design and component relationships"
  fi

  # Check docs directory structure
  if [[ -d docs ]]; then
    local doc_count
    doc_count=$(find docs -name "*.md" 2>/dev/null | wc -l)
    if [[ "$doc_count" -lt 3 ]] && [[ "$src_file_count" -gt 30 ]]; then
      emit_issue "local/docs-quality" "docs" "medium" "docs/" 1 \
        "Sparse documentation directory" "Only $doc_count docs for $src_file_count source files" \
        "Documentation should grow with codebase complexity" 0.7 \
        "Add API docs, guides, and architectural decision records (ADRs)"
    fi
  fi

  popd >/dev/null
}

########################################
# API Documentation Coverage (Swagger/OpenAPI)
########################################
run_api_docs_check() {
  say "Checking API documentation coverage..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  local has_api_endpoints=0
  local has_api_docs=0
  local api_doc_file=""

  # Detect API endpoints
  local endpoint_count
  endpoint_count=$(rg -c '(app\.(get|post|put|delete|patch)|router\.(get|post|put|delete|patch)|@(Get|Post|Put|Delete|Patch|Route)|FastAPI|@app\.route|@blueprint\.route)' \
    --glob '!node_modules/*' --glob '!dist/*' --glob '!.git/*' \
    . 2>/dev/null | awk -F: '{sum+=$2} END{print sum+0}')

  if [[ "$endpoint_count" -gt 5 ]]; then
    has_api_endpoints=1
  fi

  # Check for API documentation files
  for api_doc in openapi.yaml openapi.json swagger.yaml swagger.json \
                 api.yaml api.json docs/api.yaml docs/api.json \
                 docs/openapi.yaml docs/openapi.json docs/swagger.yaml docs/swagger.json; do
    if [[ -f "$api_doc" ]]; then
      has_api_docs=1
      api_doc_file="$api_doc"
      break
    fi
  done

  # Check for inline OpenAPI decorators
  if rg -q '@(OpenAPI|ApiOperation|ApiResponse|ApiTags|swagger)' --glob '!node_modules/*' . 2>/dev/null; then
    has_api_docs=1
    api_doc_file="inline"
  fi

  # Check for GraphQL schema
  local has_graphql=0
  if [[ -f "schema.graphql" ]] || [[ -f "schema.gql" ]] || \
     rg -q 'type Query|type Mutation|@GraphQL' --glob '!node_modules/*' . 2>/dev/null; then
    has_graphql=1
  fi

  # Flag missing API docs
  if [[ "$has_api_endpoints" -eq 1 ]] && [[ "$has_api_docs" -eq 0 ]]; then
    emit_issue "local/api-docs" "docs" "blocker" "." 1 \
      "No API documentation found" "$endpoint_count API endpoints detected but no OpenAPI/Swagger spec" \
      "REST APIs must have OpenAPI documentation for DD approval" 0.9 \
      "Add openapi.yaml with full endpoint documentation, or use swagger-jsdoc/tsoa"
  fi

  # Validate OpenAPI file if exists
  if [[ -n "$api_doc_file" ]] && [[ "$api_doc_file" != "inline" ]] && [[ -f "$api_doc_file" ]]; then
    # Check for paths section
    if ! grep -q 'paths:' "$api_doc_file" 2>/dev/null && ! grep -q '"paths"' "$api_doc_file" 2>/dev/null; then
      emit_issue "local/api-docs" "docs" "high" "$api_doc_file" 1 \
        "OpenAPI file has no paths defined" "API spec exists but no endpoints documented" \
        "Empty or incomplete OpenAPI spec is worse than none" 0.85 \
        "Add all API endpoints with request/response schemas"
    fi

    # Compare endpoint count to documented paths
    local doc_path_count
    doc_path_count=$(grep -cE '^\s+/(|"/)' "$api_doc_file" 2>/dev/null || echo 0)
    
    if [[ "$has_api_endpoints" -eq 1 ]] && [[ "$doc_path_count" -lt $((endpoint_count / 2)) ]]; then
      emit_issue "local/api-docs" "docs" "high" "$api_doc_file" 1 \
        "API docs incomplete" "~$endpoint_count endpoints in code but only ~$doc_path_count documented" \
        "API documentation must cover all endpoints" 0.8 \
        "Document all missing endpoints in OpenAPI spec"
    fi
  fi

  # GraphQL schema documentation
  if [[ "$has_graphql" -eq 1 ]]; then
    # Check for GraphQL documentation
    if ! rg -q '"""' --glob '*.graphql' --glob '*.gql' . 2>/dev/null; then
      emit_issue "local/api-docs" "docs" "high" "." 1 \
        "GraphQL schema lacks documentation" "GraphQL types/fields should have descriptions" \
        "GraphQL schemas should be self-documenting with descriptions" 0.75 \
        "Add description strings to all types and fields"
    fi
  fi

  popd >/dev/null
}

########################################
# Code Documentation (JSDoc/Docstrings)
########################################
run_code_docs_check() {
  say "Checking code documentation coverage..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # TypeScript/JavaScript JSDoc coverage
  local ts_files
  ts_files=$(find . -type f \( -name "*.ts" -o -name "*.tsx" \) \
    ! -path "*/node_modules/*" ! -path "*/dist/*" ! -path "*/.git/*" \
    ! -name "*.d.ts" ! -name "*.test.*" ! -name "*.spec.*" 2>/dev/null | head -100)

  if [[ -n "$ts_files" ]]; then
    local total_exports=0
    local documented_exports=0

    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      # Count exported functions/classes
      local exports
      exports=$(grep -cE '^export (function|class|const|interface|type|async function)' "$f" 2>/dev/null || echo 0)
      total_exports=$((total_exports + exports))
      
      # Count JSDoc comments before exports
      local docs
      docs=$(grep -cE '^\s*\*\s*@(param|returns|description|example)' "$f" 2>/dev/null || echo 0)
      documented_exports=$((documented_exports + docs))
    done <<< "$ts_files"

    if [[ "$total_exports" -gt 20 ]]; then
      local coverage_pct=$((documented_exports * 100 / total_exports))
      if [[ "$coverage_pct" -lt 30 ]]; then
        emit_issue "local/code-docs" "docs" "high" "." 1 \
          "Low JSDoc coverage (~${coverage_pct}%)" "$documented_exports documented of $total_exports exports" \
          "Public APIs should have JSDoc with @param, @returns, @example" 0.8 \
          "Add JSDoc to all exported functions, classes, and types"
      elif [[ "$coverage_pct" -lt 60 ]]; then
        emit_issue "local/code-docs" "docs" "medium" "." 1 \
          "Moderate JSDoc coverage (~${coverage_pct}%)" "$documented_exports documented of $total_exports exports" \
          "Aim for 80%+ JSDoc coverage on public APIs" 0.7 \
          "Add JSDoc to remaining undocumented exports"
      fi
    fi
  fi

  # Python docstring coverage
  local py_files
  py_files=$(find . -type f -name "*.py" \
    ! -path "*/node_modules/*" ! -path "*/.venv/*" ! -path "*/.git/*" \
    ! -name "test_*" ! -name "*_test.py" ! -name "conftest.py" 2>/dev/null | head -100)

  if [[ -n "$py_files" ]]; then
    local total_funcs=0
    local documented_funcs=0

    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      # Count function definitions
      local funcs
      funcs=$(grep -cE '^\s*def [a-zA-Z_][a-zA-Z0-9_]*\s*\(' "$f" 2>/dev/null || echo 0)
      total_funcs=$((total_funcs + funcs))
      
      # Count docstrings (triple quotes after def)
      local docs
      docs=$(grep -cE '^\s+"""' "$f" 2>/dev/null || echo 0)
      documented_funcs=$((documented_funcs + docs))
    done <<< "$py_files"

    if [[ "$total_funcs" -gt 15 ]]; then
      local coverage_pct=$((documented_funcs * 100 / total_funcs))
      if [[ "$coverage_pct" -lt 40 ]]; then
        emit_issue "local/code-docs" "docs" "high" "." 1 \
          "Low Python docstring coverage (~${coverage_pct}%)" "$documented_funcs documented of $total_funcs functions" \
          "Python functions should have docstrings explaining purpose, args, returns" 0.8 \
          "Add docstrings to all public functions and classes"
      fi
    fi
  fi

  # Check for missing type hints in Python
  if [[ -n "$py_files" ]]; then
    local untyped_funcs
    untyped_funcs=$(rg -c 'def [a-zA-Z_]+\([^)]*\):\s*$' --glob '*.py' \
      --glob '!**/test_*' --glob '!**/*_test.py' --glob '!**/conftest.py' \
      --glob '!**/.venv/*' --glob '!**/node_modules/*' . 2>/dev/null | \
      awk -F: '{sum+=$2} END{print sum+0}')

    if [[ "$untyped_funcs" -gt 10 ]]; then
      emit_issue "local/code-docs" "type-safety" "medium" "." 1 \
        "Many Python functions lack type hints" "$untyped_funcs functions without return type annotations" \
        "Type hints improve code quality and enable static analysis" 0.75 \
        "Add type hints to function signatures (def func(x: int) -> str:)"
    fi
  fi

  popd >/dev/null
}

########################################
# CI/CD Quality Check
########################################
run_ci_quality_check() {
  say "Checking CI/CD quality..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  local has_ci=0

  # GitHub Actions
  if [[ -d .github/workflows ]]; then
    has_ci=1
    
    while IFS= read -r wf; do
      [[ -f "$wf" ]] || continue
      
      # Check for deprecated actions
      if grep -qE 'uses:\s*(actions/checkout@v[12]|actions/setup-node@v[12]|actions/cache@v[12])' "$wf" 2>/dev/null; then
        emit_issue "local/ci-quality" "ci" "medium" "$wf" 1 \
          "Deprecated GitHub Action versions" "Using v1/v2 of actions; v3/v4 available" \
          "Old action versions may have security issues and missing features" 0.75 \
          "Update to latest action versions (v3/v4)"
      fi

      # Check for hardcoded secrets
      if grep -qE '(password|secret|token|key)\s*[:=]\s*["\047][^$\{]' "$wf" 2>/dev/null; then
        emit_issue "local/ci-quality" "security" "blocker" "$wf" 1 \
          "Possible hardcoded secret in CI workflow" "Credential-like string found" \
          "Never hardcode secrets in CI files; use GitHub Secrets" 0.9 \
          "Move to GitHub Secrets and reference via \${{ secrets.NAME }}"
      fi

      # Check if workflow has tests
      if ! grep -qE '(npm test|yarn test|pnpm test|pytest|go test|cargo test|jest|vitest|mocha)' "$wf" 2>/dev/null; then
        local wf_name
        wf_name=$(basename "$wf")
        if [[ "$wf_name" != *"deploy"* ]] && [[ "$wf_name" != *"release"* ]]; then
          emit_issue "local/ci-quality" "ci" "high" "$wf" 1 \
            "CI workflow has no test step" "No test command found in workflow" \
            "CI pipelines should run tests automatically" 0.8 \
            "Add test step to workflow"
        fi
      fi

      # Check for continue-on-error abuse
      local coe_count
      coe_count=$(grep -c 'continue-on-error:\s*true' "$wf" 2>/dev/null || echo 0)
      if [[ "$coe_count" -gt 2 ]]; then
        emit_issue "local/ci-quality" "ci" "high" "$wf" 1 \
          "Excessive continue-on-error usage ($coe_count times)" "Workflow ignores too many failures" \
          "continue-on-error masks real problems" 0.85 \
          "Remove continue-on-error or add proper error handling"
      fi

    done < <(find .github/workflows -name "*.yml" -o -name "*.yaml" 2>/dev/null)
  fi

  # GitLab CI
  if [[ -f .gitlab-ci.yml ]]; then
    has_ci=1
    
    if grep -qE '(password|secret|token|key)\s*[:=]\s*["\047][^$]' .gitlab-ci.yml 2>/dev/null; then
      emit_issue "local/ci-quality" "security" "blocker" ".gitlab-ci.yml" 1 \
        "Possible hardcoded secret in GitLab CI" "Credential-like string found" \
        "Never hardcode secrets; use GitLab CI variables" 0.9 \
        "Move to GitLab CI/CD Variables"
    fi
  fi

  # No CI at all
  if [[ "$has_ci" -eq 0 ]]; then
    emit_issue "local/ci-quality" "ci" "blocker" "." 1 \
      "No CI/CD configuration found" "No .github/workflows/ or .gitlab-ci.yml" \
      "Production projects must have CI/CD for automated testing and deployment" 0.95 \
      "Add GitHub Actions or GitLab CI configuration"
  fi

  # Check for required CI features
  if [[ -d .github/workflows ]]; then
    local has_lint=0 has_test=0 has_build=0 has_security=0

    if grep -rq 'lint\|eslint\|ruff\|biome' .github/workflows/ 2>/dev/null; then has_lint=1; fi
    if grep -rq 'test\|pytest\|jest\|vitest' .github/workflows/ 2>/dev/null; then has_test=1; fi
    if grep -rq 'build\|compile\|tsc' .github/workflows/ 2>/dev/null; then has_build=1; fi
    if grep -rq 'security\|snyk\|dependabot\|codeql\|semgrep\|trivy' .github/workflows/ 2>/dev/null; then has_security=1; fi

    if [[ "$has_test" -eq 0 ]]; then
      emit_issue "local/ci-quality" "ci" "blocker" ".github/workflows" 1 \
        "CI has no test job" "No test step found in any workflow" \
        "CI must run tests on every push/PR" 0.95 \
        "Add test job to CI workflow"
    fi

    if [[ "$has_lint" -eq 0 ]]; then
      emit_issue "local/ci-quality" "ci" "high" ".github/workflows" 1 \
        "CI has no lint job" "No linting step found" \
        "CI should enforce code quality via linting" 0.8 \
        "Add lint job (eslint, ruff, biome)"
    fi

    if [[ "$has_security" -eq 0 ]]; then
      emit_issue "local/ci-quality" "ci" "high" ".github/workflows" 1 \
        "CI has no security scanning" "No security tools (snyk, dependabot, codeql, semgrep)" \
        "CI should include automated security scanning" 0.75 \
        "Add security scanning (CodeQL, Snyk, Semgrep, or Dependabot)"
    fi
  fi

  popd >/dev/null
}

########################################
# Test Quality Deep Analysis
########################################
run_test_quality_deep() {
  say "Running deep test quality analysis..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # Find test files
  local test_files
  test_files=$(find . -type f \( -name "*.test.*" -o -name "*.spec.*" -o -name "test_*.py" -o -name "*_test.py" \
    -o -name "*_test.go" -o -name "*_test.rs" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null)

  if [[ -z "$test_files" ]]; then
    return 0
  fi

  # Check for skipped tests
  local skipped_count
  skipped_count=$(rg -c '(\.skip\(|@pytest\.mark\.skip|it\.skip|describe\.skip|test\.skip|@Skip|@Ignore|xtest|xit|xdescribe)' \
    --glob '*.test.*' --glob '*.spec.*' --glob 'test_*' --glob '*_test.*' \
    --glob '!node_modules/*' --glob '!.git/*' . 2>/dev/null | \
    awk -F: '{sum+=$2} END{print sum+0}')

  if [[ "$skipped_count" -gt 5 ]]; then
    emit_issue "local/test-quality" "test-coverage" "high" "." 1 \
      "Many skipped tests ($skipped_count)" "Tests marked skip/xtest/ignore" \
      "Skipped tests are tech debt; they should pass or be removed" 0.85 \
      "Fix or remove skipped tests"
  fi

  # Check for empty/minimal test functions
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    
    # Look for tests with no assertions
    if rg -q '(it|test|def test_)\s*\([^)]*\)\s*\{?\s*(//.*)?[\s\n]*\}' "$f" 2>/dev/null; then
      emit_issue "local/test-quality" "test-coverage" "high" "$f" 1 \
        "Test with no body/assertions" "Empty test function detected" \
        "Tests without assertions don't verify anything" 0.85 \
        "Add meaningful assertions to test"
    fi

    # Check for tests that just console.log
    if rg -q 'test\(.*\{[^}]*console\.log[^}]*\}' "$f" 2>/dev/null; then
      emit_issue "local/test-quality" "test-coverage" "high" "$f" 1 \
        "Test only logs, no assertions" "Test body is just console.log" \
        "Logging is not testing; add expect/assert statements" 0.8 \
        "Replace logging with actual assertions"
    fi

  done <<< "$test_files"

  # Check for hardcoded test data that matches prod patterns
  local hardcoded_patterns=(
    'password.*["\047](test|admin|password|123|abc)'
    'email.*["\047](test@|fake@|example@)'
    'token.*["\047][a-zA-Z0-9]{20,}'
    'apiKey.*["\047][a-zA-Z0-9]{20,}'
  )

  for pattern in "${hardcoded_patterns[@]}"; do
    while IFS=: read -r file line_num content; do
      [[ -z "$file" ]] && continue
      emit_issue "local/test-quality" "test-coverage" "medium" "$file" "$line_num" \
        "Hardcoded test credential" "Pattern: $pattern" \
        "Hardcoded credentials in tests may leak or cause confusion" 0.7 \
        "Use test fixtures or factories instead of hardcoded values"
    done < <(rg -n "$pattern" --glob '*.test.*' --glob '*.spec.*' --glob 'test_*' \
      --glob '!node_modules/*' . 2>/dev/null | head -10)
  done

  # Check test-to-source ratio
  local test_count src_count
  test_count=$(echo "$test_files" | wc -l)
  src_count=$(find . -type f \( -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.go" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" \
    ! -name "*.test.*" ! -name "*.spec.*" ! -name "test_*" ! -name "*_test.*" 2>/dev/null | wc -l)

  if [[ "$src_count" -gt 20 ]] && [[ "$test_count" -gt 0 ]]; then
    local ratio=$((src_count / test_count))
    if [[ "$ratio" -gt 5 ]]; then
      emit_issue "local/test-quality" "test-coverage" "high" "." 1 \
        "Low test-to-source ratio (1:$ratio)" "$test_count test files for $src_count source files" \
        "Good coverage typically has 1 test file per 1-3 source files" 0.75 \
        "Add more test files to improve coverage"
    fi
  fi

  # Check for assertion count in test files
  local total_tests total_assertions
  total_tests=$(rg -c '(it\(|test\(|def test_|func Test)' \
    --glob '*.test.*' --glob '*.spec.*' --glob 'test_*.py' --glob '*_test.*' \
    --glob '!node_modules/*' . 2>/dev/null | awk -F: '{sum+=$2} END{print sum+0}')
  total_assertions=$(rg -c '(expect\(|assert|should\.|toBe|toEqual|assertEqual|assertIn)' \
    --glob '*.test.*' --glob '*.spec.*' --glob 'test_*.py' --glob '*_test.*' \
    --glob '!node_modules/*' . 2>/dev/null | awk -F: '{sum+=$2} END{print sum+0}')

  if [[ "$total_tests" -gt 10 ]]; then
    local avg_assertions=$((total_assertions / total_tests))
    if [[ "$avg_assertions" -lt 1 ]]; then
      emit_issue "local/test-quality" "test-coverage" "blocker" "." 1 \
        "Tests have very few assertions" "Avg $avg_assertions assertions per test" \
        "Tests without assertions are not actually testing anything" 0.9 \
        "Add meaningful assertions to all tests"
    fi
  fi

  # Check for integration/e2e tests
  local has_e2e=0
  [[ -d cypress ]] && has_e2e=1
  [[ -d e2e ]] && has_e2e=1
  [[ -d tests/e2e ]] && has_e2e=1
  [[ -f playwright.config.js ]] && has_e2e=1
  [[ -f playwright.config.ts ]] && has_e2e=1
  rg -q 'supertest|request\(app\)|TestClient' --glob '*.test.*' --glob '*.spec.*' . 2>/dev/null && has_e2e=1

  if [[ "$has_e2e" -eq 0 ]] && [[ "$src_count" -gt 30 ]]; then
    emit_issue "local/test-quality" "test-coverage" "high" "." 1 \
      "No integration/e2e tests detected" "Only unit tests found; no cypress/playwright/supertest" \
      "Production apps need integration tests for critical user flows" 0.8 \
      "Add integration or e2e tests for key user journeys"
  fi

  popd >/dev/null
}

########################################
# Credential Leak Deep Scan
########################################
run_credential_deep_scan() {
  say "Running deep credential leak scan..."
  local root
  root="$(repo_root)"
  pushd "$root" >/dev/null

  # Check .env files for real values (not examples)
  for env_file in .env .env.local .env.development .env.production; do
    if [[ -f "$env_file" ]]; then
      # Check if it has real-looking values (not placeholders)
      if grep -qE '^[A-Z_]+=.{10,}' "$env_file" 2>/dev/null && \
         ! grep -qE '^[A-Z_]+=(your_|changeme|placeholder|xxx|TODO)' "$env_file" 2>/dev/null; then
        emit_issue "local/cred-scan" "security" "blocker" "$env_file" 1 \
          ".env file may contain real credentials" "File has long values that don't look like placeholders" \
          ".env files with real credentials should never be committed" 0.9 \
          "Remove from git, add to .gitignore, use .env.example template"
      fi
    fi
  done

  # Check for API keys in config files
  local config_patterns=(
    'api[_-]?key\s*[:=]\s*["\047][a-zA-Z0-9_-]{20,}'
    'secret[_-]?key\s*[:=]\s*["\047][a-zA-Z0-9_-]{20,}'
    'auth[_-]?token\s*[:=]\s*["\047][a-zA-Z0-9_-]{20,}'
    'password\s*[:=]\s*["\047][^\s$]{8,}'
    'private[_-]?key\s*[:=]'
    'AWS_SECRET_ACCESS_KEY\s*[:=]'
    'GITHUB_TOKEN\s*[:=]\s*["\047]ghp_'
    'sk-[a-zA-Z0-9]{20,}'  # OpenAI keys
    'sk_live_[a-zA-Z0-9]{20,}'  # Stripe keys
  )

  for pattern in "${config_patterns[@]}"; do
    while IFS=: read -r file line_num content; do
      [[ -z "$file" ]] && continue
      # Skip test files and examples
      [[ "$file" == *"test"* ]] && continue
      [[ "$file" == *"example"* ]] && continue
      [[ "$file" == *".example"* ]] && continue
      
      emit_issue "local/cred-scan" "security" "blocker" "$file" "$line_num" \
        "Potential credential in config" "Pattern match: $pattern" \
        "Hardcoded credentials are a critical security risk" 0.9 \
        "Remove credential, rotate it, use environment variables"
    done < <(rg -n -i "$pattern" \
      --glob '*.json' --glob '*.yaml' --glob '*.yml' --glob '*.toml' \
      --glob '*.config.*' --glob '*.conf' --glob 'config.*' \
      --glob '!node_modules/*' --glob '!.git/*' --glob '!package-lock.json' \
      . 2>/dev/null | head -20)
  done

  # Check for private keys
  if rg -q 'BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY' \
    --glob '!node_modules/*' --glob '!.git/*' . 2>/dev/null; then
    while IFS=: read -r file line_num content; do
      emit_issue "local/cred-scan" "security" "blocker" "$file" "$line_num" \
        "Private key found in repository" "BEGIN PRIVATE KEY detected" \
        "Private keys must never be committed to version control" 0.95 \
        "Remove immediately, rotate the key, add to .gitignore"
    done < <(rg -n 'BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY' \
      --glob '!node_modules/*' --glob '!.git/*' . 2>/dev/null | head -10)
  fi

  # Check for JWT secrets
  if rg -q 'JWT_SECRET\s*[:=]\s*["\047][a-zA-Z0-9]{10,}' \
    --glob '!node_modules/*' --glob '!.git/*' --glob '!*.example*' . 2>/dev/null; then
    emit_issue "local/cred-scan" "security" "blocker" "." 1 \
      "JWT secret may be hardcoded" "JWT_SECRET with long value found" \
      "JWT secrets should be in environment variables, not code" 0.85 \
      "Move to environment variable, rotate the secret"
  fi

  popd >/dev/null
}

########################################
# TODO/FIXME Aging with git blame
########################################
run_todo_aging() {
  say "Running TODO/FIXME age analysis..."
  local root
  root="$(repo_root)"
  
  is_git_repo || return 0

  pushd "$root" >/dev/null

  # Find TODOs and get their age via git blame
  rg -n --no-heading '(?i)\b(TODO|FIXME|XXX|HACK)\b' \
    --glob '!node_modules/*' \
    --glob '!.git/*' \
    --glob '!vendor/*' \
    --glob '!dist/*' \
    . 2>/dev/null | head -200 | while IFS=: read -r file line_num content; do
    [[ -z "$file" ]] && continue
    [[ "$line_num" =~ ^[0-9]+$ ]] || continue
    
    # Get blame info for this line
    local blame_info
    blame_info=$(git blame -L "$line_num,$line_num" --porcelain "$file" 2>/dev/null | head -20)
    
    if [[ -n "$blame_info" ]]; then
      local author_time commit_hash author_name
      commit_hash=$(echo "$blame_info" | head -1 | cut -d' ' -f1)
      author_time=$(echo "$blame_info" | grep '^author-time' | cut -d' ' -f2)
      author_name=$(echo "$blame_info" | grep '^author ' | cut -d' ' -f2-)
      
      if [[ -n "$author_time" ]]; then
        local now_epoch days_old severity
        now_epoch=$(date +%s)
        days_old=$(( (now_epoch - author_time) / 86400 ))
        
        # Escalate severity based on age
        if [[ "$days_old" -gt 365 ]]; then
          severity="blocker"
        elif [[ "$days_old" -gt 180 ]]; then
          severity="high"
        elif [[ "$days_old" -gt 90 ]]; then
          severity="medium"
        else
          severity="low"
        fi
        
        # Only report if older than 30 days
        if [[ "$days_old" -gt 30 ]]; then
          emit_issue "local/todo-aging" "tech-debt" "$severity" "$file" "$line_num" \
            "Stale TODO/FIXME ($days_old days old)" \
            "$content" \
            "TODO introduced by $author_name $days_old days ago. Old TODOs indicate neglected tech debt" \
            0.8 \
            "Either fix the TODO or remove it if no longer relevant"
        fi
      fi
    fi
  done || true

  popd >/dev/null
}

########################################
# Slopsquatting Defense - Package Hallucination Detection
########################################
run_slopsquatting_check() {
  [[ "$SLOP_ENABLE_SLOPSQUATTING" == "1" ]] || return 0
  
  say "Running slopsquatting defense (package hallucination detection)..."
  local root
  root="$(repo_root)"

  # Check npm packages
  if [[ -f "$root/package.json" ]]; then
    tool "Validating npm dependencies against registry..."
    
    python3 - "$root" "$ISSUES_JSONL" "$SLOP_PRIVATE_SCOPES" "$SLOP_SKIP_REGISTRY_CHECK" <<'PYTHON'
import sys
import json
import urllib.request
import urllib.error
import os

root = sys.argv[1]
issues_jsonl = sys.argv[2]
private_scopes = sys.argv[3] if len(sys.argv) > 3 else ""
skip_packages = sys.argv[4] if len(sys.argv) > 4 else ""

# Parse private scopes (e.g., "@mycorp,@internal")
private_scope_list = [s.strip() for s in private_scopes.split(",") if s.strip()]
skip_package_list = [s.strip() for s in skip_packages.split(",") if s.strip()]

try:
    with open(f"{root}/package.json", "r") as f:
        pkg = json.load(f)
except:
    sys.exit(0)

deps = {}
deps.update(pkg.get("dependencies", {}))
deps.update(pkg.get("devDependencies", {}))

# Known hallucination patterns (AI commonly invents these)
hallucination_patterns = [
    "flask-", "django-ai", "react-helper", "vue-utils", "express-ai",
    "fastapi-helper", "nextjs-utils", "-gpt-", "-ai-helper", "-llm-",
    "huggingface-cli", "openai-helper", "anthropic-helper"
]

def is_private_scope(name):
    """Check if package is from a private scope"""
    for scope in private_scope_list:
        if name.startswith(scope):
            return True
    return False

def should_skip(name):
    """Check if package should be skipped"""
    return name in skip_package_list

for dep_name in list(deps.keys())[:100]:  # Limit to first 100
    # Skip private scopes (can't validate against public registry)
    if dep_name.startswith("@"):
        if is_private_scope(dep_name):
            continue
        # For other scoped packages, skip validation (public scopes like @types are fine)
        continue
    
    # Skip explicitly whitelisted packages
    if should_skip(dep_name):
        continue
    
    # Check if matches hallucination pattern
    is_suspicious = any(pattern in dep_name.lower() for pattern in hallucination_patterns)
    
    # Validate against npm registry
    try:
        url = f"https://registry.npmjs.org/{dep_name}"
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("Accept", "application/json")
        urllib.request.urlopen(req, timeout=5)
        # Package exists
        if is_suspicious:
            # Warn about suspicious name even if it exists
            issue = {
                "source": "slopsquatting/npm",
                "category": "supply-chain",
                "severity": "medium",
                "file": "package.json",
                "line": 1,
                "title": f"Suspicious package name pattern: {dep_name}",
                "evidence": f"Package exists but name matches AI hallucination patterns",
                "why": "This package name matches patterns commonly hallucinated by AI. Verify it's the intended package.",
                "confidence": 0.6,
                "fix": f"Verify {dep_name} is the correct package and not a typosquat/slopsquat"
            }
            with open(issues_jsonl, "a") as f:
                f.write(json.dumps(issue) + "\n")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Package doesn't exist!
            issue = {
                "source": "slopsquatting/npm",
                "category": "supply-chain",
                "severity": "blocker",
                "file": "package.json",
                "line": 1,
                "title": f"HALLUCINATED PACKAGE: {dep_name} does not exist on npm",
                "evidence": f"npm registry returned 404 for {dep_name}",
                "why": "This package does not exist on npm. It was likely hallucinated by AI. This is a critical supply chain risk.",
                "confidence": 0.95,
                "fix": f"Remove {dep_name} from dependencies and find the correct package name"
            }
            with open(issues_jsonl, "a") as f:
                f.write(json.dumps(issue) + "\n")
        elif e.code == 401 or e.code == 403:
            # Auth required - likely private registry, skip
            pass
    except Exception:
        pass  # Network issues, skip

if private_scope_list:
    print(f"  Skipped private scopes: {', '.join(private_scope_list)}")
PYTHON
  fi

  # Check Python packages
  if [[ -f "$root/requirements.txt" ]]; then
    tool "Validating Python dependencies against PyPI..."
    
    python3 - "$root" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json
import urllib.request
import urllib.error
import re

root = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(f"{root}/requirements.txt", "r") as f:
        lines = f.readlines()
except:
    sys.exit(0)

# Known hallucination patterns
hallucination_patterns = [
    "flask-gpt", "django-ai", "fastapi-helper", "pytorch-helper",
    "tensorflow-helper", "huggingface-cli", "openai-helper", 
    "anthropic-helper", "-llm-", "-gpt-", "-ai-utils"
]

for line in lines[:100]:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        continue
    
    # Extract package name (before any version specifier)
    match = re.match(r'^([a-zA-Z0-9_-]+)', line)
    if not match:
        continue
    
    pkg_name = match.group(1).lower()
    
    is_suspicious = any(pattern in pkg_name for pattern in hallucination_patterns)
    
    try:
        url = f"https://pypi.org/pypi/{pkg_name}/json"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        urllib.request.urlopen(req, timeout=5)
        
        if is_suspicious:
            issue = {
                "source": "slopsquatting/pypi",
                "category": "supply-chain",
                "severity": "medium",
                "file": "requirements.txt",
                "line": 1,
                "title": f"Suspicious package name pattern: {pkg_name}",
                "evidence": f"Package exists but name matches AI hallucination patterns",
                "why": "This package name matches patterns commonly hallucinated by AI.",
                "confidence": 0.6,
                "fix": f"Verify {pkg_name} is the correct package"
            }
            with open(issues_jsonl, "a") as f:
                f.write(json.dumps(issue) + "\n")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            issue = {
                "source": "slopsquatting/pypi",
                "category": "supply-chain",
                "severity": "blocker",
                "file": "requirements.txt",
                "line": 1,
                "title": f"HALLUCINATED PACKAGE: {pkg_name} does not exist on PyPI",
                "evidence": f"PyPI returned 404 for {pkg_name}",
                "why": "This package does not exist on PyPI. Likely AI hallucination.",
                "confidence": 0.95,
                "fix": f"Remove {pkg_name} and find the correct package name"
            }
            with open(issues_jsonl, "a") as f:
                f.write(json.dumps(issue) + "\n")
    except Exception:
        pass
PYTHON
  fi
}

########################################
# Biome (Fast JS/TS/JSON/CSS Linter)
########################################
run_biome() {
  [[ "$SLOP_ENABLE_BIOME" == "1" ]] || return 0
  need_cmd biome || { warn "Biome not installed, skipping"; return 0; }
  
  has_files "*.ts" || has_files "*.tsx" || has_files "*.js" || has_files "*.jsx" || return 0
  
  tool "Running Biome (JS/TS/JSON/CSS linting)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/biome.json"
  
  biome lint --reporter=json "$root" 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

diagnostics = data.get("diagnostics", [])

for diag in diagnostics[:500]:  # Cap at 500
    severity_map = {"error": "high", "warning": "medium", "info": "low"}
    sev = severity_map.get(diag.get("severity", "warning"), "medium")
    
    location = diag.get("location", {})
    file_path = location.get("path", {}).get("file", "unknown")
    span = location.get("span", {})
    line = span.get("start", {}).get("line", 1)
    
    issue = {
        "source": "biome",
        "category": diag.get("category", "lint"),
        "severity": sev,
        "file": file_path,
        "line": line,
        "title": diag.get("message", "Biome issue"),
        "evidence": "",
        "why": diag.get("description", ""),
        "confidence": 0.85,
        "fix": ""
    }
    
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# Ruff (Fast Python Linter)
########################################
run_ruff() {
  [[ "$SLOP_ENABLE_RUFF" == "1" ]] || return 0
  need_cmd ruff || { warn "Ruff not installed, skipping"; return 0; }
  
  has_files "*.py" || return 0
  
  tool "Running Ruff (Python linting - 800+ rules)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/ruff.json"
  
  ruff check --output-format=json "$root" 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

# Ruff severity mapping based on rule codes
high_severity_codes = ["E9", "F", "B", "S", "C90"]  # Errors, Flake8, Bugbear, Security, Complexity

for issue in data[:500]:  # Cap at 500
    code = issue.get("code", "")
    
    sev = "medium"
    if any(code.startswith(prefix) for prefix in high_severity_codes):
        sev = "high"
    elif code.startswith("W"):
        sev = "low"
    
    item = {
        "source": "ruff",
        "category": f"python/{code}",
        "severity": sev,
        "file": issue.get("filename", "unknown"),
        "line": issue.get("location", {}).get("row", 1),
        "title": f"[{code}] {issue.get('message', 'Ruff issue')}",
        "evidence": "",
        "why": issue.get("message", ""),
        "confidence": 0.85,
        "fix": issue.get("fix", {}).get("message", "") if issue.get("fix") else ""
    }
    
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(item) + "\n")
PYTHON
  fi
}

########################################
# Knip (Unused exports/deps/files for JS/TS)
########################################
run_knip() {
  [[ "$SLOP_ENABLE_KNIP" == "1" ]] || return 0
  need_cmd npx || { warn "npx not available, skipping Knip"; return 0; }
  
  has_files "*.ts" || has_files "*.js" || return 0
  [[ -f "package.json" ]] || return 0
  
  tool "Running Knip (unused exports, dependencies, files)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/knip.json"
  
  # Run knip with JSON output
  npx knip --reporter json 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

# Process unused files
for file in data.get("files", [])[:100]:
    issue = {
        "source": "knip",
        "category": "dead-code/file",
        "severity": "medium",
        "file": file,
        "line": 1,
        "title": f"Unused file: {file}",
        "evidence": "",
        "why": "This file is not imported anywhere in the project",
        "confidence": 0.8,
        "fix": "Delete the file if no longer needed"
    }
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")

# Process unused exports
for file, exports in data.get("exports", {}).items():
    for exp in exports[:10]:  # Limit per file
        issue = {
            "source": "knip",
            "category": "dead-code/export",
            "severity": "medium",
            "file": file,
            "line": exp.get("line", 1),
            "title": f"Unused export: {exp.get('name', 'unknown')}",
            "evidence": "",
            "why": "This export is not imported anywhere in the project",
            "confidence": 0.75,
            "fix": "Remove the export or mark as internal"
        }
        with open(issues_jsonl, "a") as f:
            f.write(json.dumps(issue) + "\n")

# Process unused dependencies
for dep in data.get("dependencies", [])[:50]:
    issue = {
        "source": "knip",
        "category": "dead-code/dependency",
        "severity": "high",
        "file": "package.json",
        "line": 1,
        "title": f"Unused dependency: {dep}",
        "evidence": "",
        "why": "This package is listed in dependencies but never imported",
        "confidence": 0.85,
        "fix": f"Remove {dep} from package.json"
    }
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")

# Process unlisted dependencies
for dep in data.get("unlisted", [])[:50]:
    issue = {
        "source": "knip",
        "category": "missing-dependency",
        "severity": "high",
        "file": "package.json",
        "line": 1,
        "title": f"Unlisted dependency: {dep}",
        "evidence": "",
        "why": "This package is imported but not listed in package.json",
        "confidence": 0.9,
        "fix": f"Add {dep} to package.json dependencies"
    }
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# Vulture (Python Dead Code)
########################################
run_vulture() {
  [[ "$SLOP_ENABLE_VULTURE" == "1" ]] || return 0
  need_cmd vulture || { warn "Vulture not installed, skipping"; return 0; }
  
  has_files "*.py" || return 0
  
  tool "Running Vulture (Python dead code detection)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/vulture.txt"
  
  vulture "$root" --min-confidence 70 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    while IFS= read -r line; do
      # Parse vulture output: file:line: message (confidence% confidence)
      if [[ "$line" =~ ^(.+):([0-9]+):\ (.+)\ \(([0-9]+)%\ confidence\)$ ]]; then
        local file="${BASH_REMATCH[1]}"
        local line_num="${BASH_REMATCH[2]}"
        local message="${BASH_REMATCH[3]}"
        local confidence="${BASH_REMATCH[4]}"
        
        local severity="medium"
        [[ "$confidence" -ge 90 ]] && severity="high"
        [[ "$confidence" -ge 100 ]] && severity="blocker"
        
        emit_issue "vulture" "dead-code/python" "$severity" "$file" "$line_num" \
          "Dead code: $message" "" \
          "Vulture detected unused code with $confidence% confidence" \
          "0.$confidence" \
          "Remove the unused code or add to whitelist if intentional"
      fi
    done < "$out"
  fi
}

########################################
# Semgrep (SAST Security Scanner)
########################################
run_semgrep() {
  [[ "$SLOP_ENABLE_SEMGREP" == "1" ]] || return 0
  need_cmd semgrep || { warn "Semgrep not installed, skipping"; return 0; }
  
  tool "Running Semgrep (SAST security scanning)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/semgrep.json"
  
  # Run with auto config (uses recommended rules)
  semgrep scan --config=auto --json --quiet "$root" 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

results = data.get("results", [])

severity_map = {
    "ERROR": "blocker",
    "WARNING": "high",
    "INFO": "medium"
}

for result in results[:300]:  # Cap at 300
    sev = severity_map.get(result.get("extra", {}).get("severity", "WARNING"), "high")
    
    issue = {
        "source": "semgrep",
        "category": f"security/{result.get('check_id', 'unknown')}",
        "severity": sev,
        "file": result.get("path", "unknown"),
        "line": result.get("start", {}).get("line", 1),
        "title": result.get("extra", {}).get("message", "Semgrep finding"),
        "evidence": result.get("extra", {}).get("lines", ""),
        "why": result.get("extra", {}).get("metadata", {}).get("description", ""),
        "confidence": 0.85,
        "fix": result.get("extra", {}).get("fix", "")
    }
    
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# Bandit (Python Security)
########################################
run_bandit() {
  [[ "$SLOP_ENABLE_BANDIT" == "1" ]] || return 0
  need_cmd bandit || { warn "Bandit not installed, skipping"; return 0; }
  
  has_files "*.py" || return 0
  
  tool "Running Bandit (Python security scanning)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/bandit.json"
  
  bandit -r "$root" -f json --quiet 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

results = data.get("results", [])

severity_map = {
    "HIGH": "blocker",
    "MEDIUM": "high",
    "LOW": "medium"
}

for result in results[:200]:
    sev = severity_map.get(result.get("issue_severity", "MEDIUM"), "high")
    
    issue = {
        "source": "bandit",
        "category": f"security/python/{result.get('test_id', 'unknown')}",
        "severity": sev,
        "file": result.get("filename", "unknown"),
        "line": result.get("line_number", 1),
        "title": f"[{result.get('test_id')}] {result.get('issue_text', 'Security issue')}",
        "evidence": result.get("code", ""),
        "why": result.get("issue_text", ""),
        "confidence": float(result.get("issue_confidence", "MEDIUM") == "HIGH") * 0.3 + 0.6,
        "fix": result.get("more_info", "")
    }
    
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# Gitleaks (Secrets Scanning)
########################################
run_gitleaks() {
  [[ "$SLOP_ENABLE_GITLEAKS" == "1" ]] || return 0
  need_cmd gitleaks || { warn "Gitleaks not installed, skipping"; return 0; }
  
  tool "Running Gitleaks (secrets detection)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/gitleaks.json"
  
  gitleaks detect --source="$root" --report-format=json --report-path="$out" --no-git 2>/dev/null || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

for finding in data[:100]:
    issue = {
        "source": "gitleaks",
        "category": f"security/secret/{finding.get('RuleID', 'unknown')}",
        "severity": "blocker",
        "file": finding.get("File", "unknown"),
        "line": finding.get("StartLine", 1),
        "title": f"Secret detected: {finding.get('Description', 'Potential secret')}",
        "evidence": finding.get("Match", "")[:100] + "...",
        "why": f"Rule: {finding.get('RuleID')} - {finding.get('Description')}",
        "confidence": 0.9,
        "fix": "Remove the secret and rotate it immediately"
    }
    
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# dependency-cruiser (Circular Dependencies)
########################################
run_depcruise() {
  [[ "$SLOP_ENABLE_DEPCRUISE" == "1" ]] || return 0
  need_cmd npx || { warn "npx not available, skipping dependency-cruiser"; return 0; }
  
  has_files "*.ts" || has_files "*.js" || return 0
  
  tool "Running dependency-cruiser (circular dependencies, orphans)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/depcruise.json"
  
  # Run depcruise
  npx depcruise --output-type json --include-only "^src" "$root/src" 2>/dev/null > "$out" || \
  npx depcruise --output-type json --include-only "^app" "$root/app" 2>/dev/null > "$out" || \
  npx depcruise --output-type json "$root" 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

# Check for violations
for violation in data.get("summary", {}).get("violations", [])[:100]:
    rule = violation.get("rule", {})
    
    severity_map = {"error": "high", "warn": "medium", "info": "low"}
    sev = severity_map.get(rule.get("severity", "warn"), "medium")
    
    from_module = violation.get("from", "unknown")
    to_module = violation.get("to", "unknown")
    
    issue = {
        "source": "depcruise",
        "category": f"architecture/{rule.get('name', 'unknown')}",
        "severity": sev,
        "file": from_module,
        "line": 1,
        "title": f"{rule.get('name', 'Dependency issue')}: {from_module} -> {to_module}",
        "evidence": "",
        "why": rule.get("comment", "Dependency architecture violation"),
        "confidence": 0.85,
        "fix": "Refactor to break the dependency cycle or violation"
    }
    
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")

# Check for orphans
for module in data.get("modules", []):
    if module.get("orphan"):
        issue = {
            "source": "depcruise",
            "category": "dead-code/orphan",
            "severity": "medium",
            "file": module.get("source", "unknown"),
            "line": 1,
            "title": f"Orphan module: {module.get('source')}",
            "evidence": "",
            "why": "This module is not imported anywhere",
            "confidence": 0.8,
            "fix": "Delete if unused or add import where needed"
        }
        with open(issues_jsonl, "a") as f:
            f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# OSV-Scanner (Vulnerability Scanning)
########################################
run_osv_scanner() {
  [[ "$SLOP_ENABLE_OSV" == "1" ]] || return 0
  need_cmd osv-scanner || { warn "OSV-Scanner not installed, skipping"; return 0; }
  
  tool "Running OSV-Scanner (dependency vulnerabilities)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/osv.json"
  
  osv-scanner scan --format json "$root" 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

results = data.get("results", [])

for result in results:
    source_file = result.get("source", {}).get("path", "unknown")
    
    for pkg in result.get("packages", []):
        pkg_name = pkg.get("package", {}).get("name", "unknown")
        pkg_version = pkg.get("package", {}).get("version", "unknown")
        
        for vuln in pkg.get("vulnerabilities", [])[:10]:
            severity_map = {"CRITICAL": "blocker", "HIGH": "blocker", "MODERATE": "high", "LOW": "medium"}
            
            # Get severity from database_specific or default
            db_specific = vuln.get("database_specific", {})
            sev = severity_map.get(db_specific.get("severity", "MODERATE"), "high")
            
            issue = {
                "source": "osv-scanner",
                "category": f"security/vuln/{vuln.get('id', 'unknown')}",
                "severity": sev,
                "file": source_file,
                "line": 1,
                "title": f"Vulnerability in {pkg_name}@{pkg_version}: {vuln.get('id')}",
                "evidence": vuln.get("summary", ""),
                "why": vuln.get("details", "")[:500],
                "confidence": 0.95,
                "fix": f"Upgrade {pkg_name} to a patched version"
            }
            
            with open(issues_jsonl, "a") as f:
                f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# actionlint (GitHub Actions Validation)
########################################
run_actionlint() {
  [[ "$SLOP_ENABLE_ACTIONLINT" == "1" ]] || return 0
  need_cmd actionlint || { warn "actionlint not installed, skipping"; return 0; }
  
  [[ -d ".github/workflows" ]] || return 0
  
  tool "Running actionlint (GitHub Actions validation)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/actionlint.json"
  
  actionlint -format '{{json .}}' 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      
      python3 - "$line" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

line = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    data = json.loads(line)
except:
    sys.exit(0)

issue = {
    "source": "actionlint",
    "category": "ci/github-actions",
    "severity": "high" if data.get("kind") == "error" else "medium",
    "file": data.get("filepath", "unknown"),
    "line": data.get("line", 1),
    "title": f"GitHub Actions: {data.get('message', 'Issue found')}",
    "evidence": "",
    "why": data.get("message", ""),
    "confidence": 0.9,
    "fix": ""
}

with open(issues_jsonl, "a") as f:
    f.write(json.dumps(issue) + "\n")
PYTHON
    done < "$out"
  fi
}

########################################
# git-sizer (Repo Health)
########################################
run_git_sizer() {
  [[ "$SLOP_ENABLE_GITSIZER" == "1" ]] || return 0
  need_cmd git-sizer || { warn "git-sizer not installed, skipping"; return 0; }
  
  is_git_repo || return 0
  
  tool "Running git-sizer (repo health metrics)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/git-sizer.json"
  
  git-sizer --json 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

# Check for problematic metrics
thresholds = {
    "uniqueBlobSize": {"value": 10 * 1024 * 1024, "msg": "Blob larger than 10MB", "sev": "high"},
    "maxPathDepth": {"value": 15, "msg": "Path depth exceeds 15 levels", "sev": "medium"},
    "maxPathLength": {"value": 200, "msg": "Path length exceeds 200 characters", "sev": "medium"},
}

for metric, config in thresholds.items():
    value = data.get(metric, {}).get("value", 0)
    if value > config["value"]:
        issue = {
            "source": "git-sizer",
            "category": "repo-hygiene",
            "severity": config["sev"],
            "file": ".",
            "line": 1,
            "title": config["msg"],
            "evidence": f"{metric} = {value}",
            "why": "Large/deep paths can cause issues with some tools and file systems",
            "confidence": 0.8,
            "fix": "Consider restructuring or using Git LFS for large files"
        }
        with open(issues_jsonl, "a") as f:
            f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# lychee (Broken Link Detection)
########################################
run_lychee() {
  [[ "$SLOP_ENABLE_LYCHEE" == "1" ]] || return 0
  need_cmd lychee || { warn "lychee not installed, skipping"; return 0; }
  
  has_files "*.md" || return 0
  
  tool "Running lychee (broken link detection in docs)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/lychee.json"
  
  lychee --format json --output "$out" "$root"/*.md "$root"/**/*.md 2>/dev/null || true
  
  if [[ -s "$out" ]]; then
    python3 - "$out" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

out_file = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    with open(out_file, "r") as f:
        data = json.load(f)
except:
    sys.exit(0)

for fail in data.get("fail_map", {}).items():
    file_path, links = fail
    for link in links[:10]:
        issue = {
            "source": "lychee",
            "category": "docs/broken-link",
            "severity": "medium",
            "file": file_path,
            "line": 1,
            "title": f"Broken link: {link.get('url', 'unknown')}",
            "evidence": f"Status: {link.get('status', 'unknown')}",
            "why": "Broken links frustrate users and indicate stale documentation",
            "confidence": 0.9,
            "fix": "Update or remove the broken link"
        }
        with open(issues_jsonl, "a") as f:
            f.write(json.dumps(issue) + "\n")
PYTHON
  fi
}

########################################
# typos (Spell Checking)
########################################
run_typos() {
  [[ "$SLOP_ENABLE_TYPOS" == "1" ]] || return 0
  need_cmd typos || { warn "typos not installed, skipping"; return 0; }
  
  tool "Running typos (spell checking)..."
  local root
  root="$(repo_root)"

  local out="$WORKDIR/typos.json"
  
  typos --format json "$root" 2>/dev/null > "$out" || true
  
  if [[ -s "$out" ]]; then
    head -100 "$out" | while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      
      python3 - "$line" "$ISSUES_JSONL" <<'PYTHON'
import sys
import json

line = sys.argv[1]
issues_jsonl = sys.argv[2]

try:
    data = json.loads(line)
except:
    sys.exit(0)

if data.get("type") == "typo":
    issue = {
        "source": "typos",
        "category": "code-quality/typo",
        "severity": "low",
        "file": data.get("path", "unknown"),
        "line": data.get("line_num", 1),
        "title": f"Typo: '{data.get('typo')}' -> '{data.get('corrections', ['?'])[0]}'",
        "evidence": data.get("context", {}).get("line", ""),
        "why": "Typos in code/docs reduce professionalism and can cause confusion",
        "confidence": 0.7,
        "fix": f"Replace with: {data.get('corrections', ['?'])[0]}"
    }
    with open(issues_jsonl, "a") as f:
        f.write(json.dumps(issue) + "\n")
PYTHON
    done
  fi
}

########################################
# Claude API
########################################
call_claude() {
  local prompt="$1"
  local out_file="$2"
  local model="${3:-$SLOP_CLAUDE_MODEL}"
  
  [[ -n "$SLOP_CLAUDE_API_KEY" ]] || return 1

  # Check cache first
  local cache_key_val
  cache_key_val=$(cache_key "$prompt" "$model")
  if cached=$(cache_get "$cache_key_val" 2>/dev/null); then
    echo "$cached" > "$out_file"
    return 0
  fi

  # Build request body
  local request_body
  request_body=$(jq -nc \
    --arg model "$model" \
    --argjson max_tokens "$SLOP_CLAUDE_MAX_TOKENS" \
    --arg prompt "$prompt" \
    '{model: $model, max_tokens: $max_tokens, messages: [{role: "user", content: $prompt}]}')

  # Use retry wrapper
  if curl_with_retry \
    "https://api.anthropic.com/v1/messages" \
    "$request_body" \
    "$out_file" \
    "x-api-key: ${SLOP_CLAUDE_API_KEY}" \
    "application/json"; then
    
    # Add anthropic-version header (curl_with_retry doesn't support multiple headers easily)
    # So let's do this properly:
    :
  fi
  
  # Fallback to direct call if wrapper fails  
  local attempt=0
  local delay="$SLOP_LLM_RETRY_DELAY"
  
  while [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; do
    ((attempt++))
    
    local http_code
    http_code=$(curl -s -w "%{http_code}" -X POST "https://api.anthropic.com/v1/messages" \
      -H "Content-Type: application/json" \
      -H "x-api-key: ${SLOP_CLAUDE_API_KEY}" \
      -H "anthropic-version: 2023-06-01" \
      -d "$request_body" \
      -o "$out_file" \
      --max-time 120 2>/dev/null)
    
    case "$http_code" in
      200|201)
        # Success - cache and return
        cache_set "$cache_key_val" "$(cat "$out_file")"
        return 0
        ;;
      429)
        # Rate limited - exponential backoff
        if [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; then
          warn "  Claude rate limited (429), retrying in ${delay}s (attempt $attempt/$SLOP_LLM_MAX_RETRIES)"
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        fi
        ;;
      500|502|503|504)
        # Server error - retry
        if [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; then
          warn "  Claude server error ($http_code), retrying in ${delay}s"
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        fi
        ;;
      *)
        # Other error - fail
        warn "  Claude API error: HTTP $http_code"
        return 1
        ;;
    esac
  done
  
  return 1
}

run_claude_analysis() {
  [[ "$SLOP_ENABLE_CLAUDE" == "1" ]] || return 0
  [[ -n "$CLAUDE_AUTH_METHOD" ]] || { warn "No Claude auth available, skipping"; return 0; }

  say "Running Claude analysis (method: $CLAUDE_AUTH_METHOD, mode: $MODE)..."

  local context
  context=$(head -100 "$ISSUES_JSONL" | jq -rs 'map("\(.file):\(.line) [\(.severity)] \(.title)") | join("\n")')

  local file_samples=""
  while IFS= read -r f; do
    [[ -f "$f" ]] && file_samples+="=== $f ===\n$(head -80 "$f")\n\n"
  done < <(find . -type f \( -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.rs" \) \
    ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" 2>/dev/null | shuf | head -15)

  if [[ "$MODE" == "deep" ]]; then
    # Multi-agent mode: run specialized prompts in parallel
    run_claude_multiagent "$context" "$file_samples"
  else
    # Standard single-prompt mode
    run_claude_single "$context" "$file_samples"
  fi
}

run_claude_single() {
  local context="$1"
  local file_samples="$2"

  local prompt="You are a ruthless code auditor hunting for 'AI slop' - code that looks complete but isn't.

AUTOMATED TOOL FINDINGS:
$context

SAMPLE FILES:
$file_samples

Find additional issues focusing on:
1. Functions that claim to do X but actually do Y (or nothing)
2. AI-generated placeholder phrases ('here is a simple', 'you would need to')
3. Tests that don't test anything meaningful
4. Missing error handling
5. Hardcoded values where logic should be
6. Security shortcuts
7. Hallucinated imports/dependencies

Return ONLY valid JSON:
{\"summary\": \"brief summary\", \"issues\": [{\"severity\": \"blocker|high|medium|low\", \"category\": \"string\", \"file\": \"string\", \"line\": number, \"title\": \"string\", \"evidence\": \"string\", \"why\": \"string\", \"confidence\": number, \"fix\": \"string\"}]}

Be specific with file paths and line numbers. Fewer high-confidence issues are better than many guesses."

  local out="$WORKDIR/claude_analysis.json"

  if [[ "$CLAUDE_AUTH_METHOD" == "claude-code" ]]; then
    say "  Using Claude Code CLI..."
    
    if claude -p "$prompt" \
        --output-format json \
        --max-turns "$SLOP_CLAUDE_CODE_MAX_TURNS" \
        --max-budget-usd "$SLOP_CLAUDE_CODE_BUDGET" \
        --allowedTools "Read" \
        --allowedTools "Bash(rg *)" \
        --allowedTools "Bash(find *)" \
        --disallowedTools "Edit" \
        > "$out" 2>"$WORKDIR/claude_stderr.log"; then
      
      local content
      content=$(jq -r '.result // .response // .content // ""' "$out" 2>/dev/null)
      # Sanitize chatty LLM output (handles "Here is the JSON: ```json {...}```")
      content=$(clean_json "$content")
      
      if echo "$content" | jq -e '.issues' >/dev/null 2>&1; then
        parse_claude_issues "$content"
      fi
    fi
  else
    say "  Using Claude API..."
    
    if call_claude "$prompt" "$out"; then
      local content
      content=$(jq -r '.content[0].text // ""' "$out" 2>/dev/null)
      # Sanitize chatty LLM output
      content=$(clean_json "$content")
      
      if echo "$content" | jq -e '.issues' >/dev/null 2>&1; then
        parse_claude_issues "$content"
      fi
    fi
  fi
}

run_claude_multiagent() {
  local context="$1"
  local file_samples="$2"

  say "  Running multi-agent analysis (4 specialists)..."

  # Architect prompt - structural issues
  local prompt_arch="You are 'SlopScan-Architect'. Your job is to identify STRUCTURAL slop:
- Messy module boundaries and unclear responsibilities
- Broken layering (UI calling DB directly, etc)
- Dead exports and unused code paths
- Over-engineering (abstractions with no benefit)
- Suspicious scaffolds (empty classes, stub methods)

CONTEXT:
$context

SAMPLE FILES:
$file_samples

Return ONLY valid JSON:
{\"issues\": [{\"severity\": \"blocker|high|medium|low\", \"category\": \"architecture\", \"file\": \"string\", \"line\": number, \"title\": \"string\", \"evidence\": \"string\", \"why\": \"string\", \"confidence\": number, \"fix\": \"string\"}]}"

  # TestLead prompt - test quality
  local prompt_test="You are 'SlopScan-TestLead'. Your job is to identify TEST QUALITY issues:
- Missing test coverage for critical paths
- Fake tests (no assertions, snapshot-only, always pass)
- Tests that don't test real behavior
- Flaky test patterns (timing, order-dependent)
- Mocked everything (no integration coverage)

CONTEXT:
$context

SAMPLE FILES:
$file_samples

Return ONLY valid JSON:
{\"issues\": [{\"severity\": \"blocker|high|medium|low\", \"category\": \"test-quality\", \"file\": \"string\", \"line\": number, \"title\": \"string\", \"evidence\": \"string\", \"why\": \"string\", \"confidence\": number, \"fix\": \"string\"}]}"

  # TechWriter prompt - docs vs reality
  local prompt_docs="You are 'SlopScan-TechWriter'. Your job is to identify DOC DRIFT:
- README claims that don't match code reality
- Outdated setup instructions
- API docs that don't match implementations
- Inconsistent architecture claims
- Broken examples

CONTEXT:
$context

SAMPLE FILES:
$file_samples

Return ONLY valid JSON:
{\"issues\": [{\"severity\": \"blocker|high|medium|low\", \"category\": \"doc-drift\", \"file\": \"string\", \"line\": number, \"title\": \"string\", \"evidence\": \"string\", \"why\": \"string\", \"confidence\": number, \"fix\": \"string\"}]}"

  # SecOps prompt - security + supply chain
  local prompt_sec="You are 'SlopScan-SecOps'. Your job is to identify SECURITY & SUPPLY CHAIN risks:
- Hardcoded secrets or credentials
- Missing input validation
- SQL injection, XSS, path traversal
- Suspicious dependencies (slopsquatting candidates)
- Weak crypto or auth patterns
- Missing rate limiting or access control

CONTEXT:
$context

SAMPLE FILES:
$file_samples

Return ONLY valid JSON:
{\"issues\": [{\"severity\": \"blocker|high|medium|low\", \"category\": \"security\", \"file\": \"string\", \"line\": number, \"title\": \"string\", \"evidence\": \"string\", \"why\": \"string\", \"confidence\": number, \"fix\": \"string\"}]}"

  # Run all prompts (parallel if API, sequential if Claude Code)
  if [[ "$CLAUDE_AUTH_METHOD" == "claude-code" ]]; then
    # Sequential for Claude Code (resource constraints)
    for name in arch test docs sec; do
      local prompt_var="prompt_$name"
      local out="$WORKDIR/claude_${name}.json"
      say "    Running $name specialist..."
      
      if claude -p "${!prompt_var}" \
          --output-format json \
          --max-turns 5 \
          --max-budget-usd 1.00 \
          --allowedTools "Read" \
          --disallowedTools "Edit" \
          > "$out" 2>/dev/null; then
        local content
        content=$(jq -r '.result // .response // .content // ""' "$out" 2>/dev/null)
        content=$(clean_json "$content")
        if echo "$content" | jq -e '.issues' >/dev/null 2>&1; then
          parse_claude_issues "$content"
        fi
      fi
    done
  else
    # Parallel for API
    local pids=()
    for name in arch test docs sec; do
      local prompt_var="prompt_$name"
      local out="$WORKDIR/claude_${name}.json"
      (
        if call_claude "${!prompt_var}" "$out" 2>/dev/null; then
          local content
          content=$(jq -r '.content[0].text // ""' "$out" 2>/dev/null)
          content=$(clean_json "$content")
          if echo "$content" | jq -e '.issues' >/dev/null 2>&1; then
            parse_claude_issues "$content"
          fi
        fi
      ) &
      pids+=($!)
    done
    
    # Wait for all parallel jobs
    for pid in "${pids[@]}"; do
      wait "$pid" 2>/dev/null || true
    done
  fi

  say "  Multi-agent analysis complete"
}

parse_claude_issues() {
  local content="$1"
  
  echo "$content" | jq -c '.issues[]' 2>/dev/null | while read -r issue; do
    local sev=$(echo "$issue" | jq -r '.severity // "medium"')
    local cat=$(echo "$issue" | jq -r '.category // "llm-analysis"')
    local file=$(echo "$issue" | jq -r '.file // "unknown"')
    local line=$(echo "$issue" | jq -r '.line // 1')
    local title=$(echo "$issue" | jq -r '.title // "Untitled"')
    local evidence=$(echo "$issue" | jq -r '.evidence // ""')
    local why=$(echo "$issue" | jq -r '.why // ""')
    local conf=$(echo "$issue" | jq -r '.confidence // 0.5')
    local fix=$(echo "$issue" | jq -r '.fix // ""')
    
    emit_issue "claude" "$cat" "$sev" "$file" "$line" "$title" "$evidence" "$why" "$conf" "$fix"
  done
}

########################################
# Gemini via Vertex AI
########################################
run_gemini_analysis() {
  [[ "$SLOP_ENABLE_GEMINI" == "1" ]] || return 0
  [[ -n "$VERTEX_AUTH_METHOD" ]] || { warn "No Vertex auth available, skipping Gemini"; return 0; }
  [[ -n "$SLOP_GCP_PROJECT" ]] || { warn "SLOP_GCP_PROJECT not set, skipping Gemini"; return 0; }

  say "Running Gemini analysis (method: $VERTEX_AUTH_METHOD, model: $SLOP_GEMINI_MODEL)..."

  local token="$VERTEX_ACCESS_TOKEN"
  if [[ -z "$token" ]]; then
    token=$(gcloud auth print-access-token 2>/dev/null) || { warn "gcloud auth failed"; return 0; }
  fi

  local context
  context=$(head -80 "$ISSUES_JSONL" | jq -rs 'map("\(.file):\(.line) [\(.severity)] \(.title)") | join("\n")')

  local prompt="Analyze this codebase for 'AI slop' - incomplete/faked code. Local signals:
$context

Return ONLY JSON: {\"summary\": \"...\", \"issues\": [{\"severity\": \"blocker|high|medium|low\", \"category\": \"...\", \"file\": \"...\", \"line\": N, \"title\": \"...\", \"evidence\": \"...\", \"why\": \"...\", \"confidence\": 0.0-1.0, \"fix\": \"...\"}]}"

  local url="https://${SLOP_VERTEX_LOCATION}-aiplatform.googleapis.com/v1/projects/${SLOP_GCP_PROJECT}/locations/${SLOP_VERTEX_LOCATION}/publishers/google/models/${SLOP_GEMINI_MODEL}:generateContent"

  local out="$WORKDIR/gemini_analysis.json"
  local gemini_body
  gemini_body=$(jq -nc --arg p "$prompt" '{contents: [{parts: [{text: $p}]}], generationConfig: {temperature: 0.1, maxOutputTokens: 8192}}')
  
  # Use retry logic (same as Claude) to handle 429/5xx errors
  local attempt=0
  local delay="$SLOP_LLM_RETRY_DELAY"
  local success=0
  
  while [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; do
    ((attempt++))
    
    local http_code
    http_code=$(curl -s -w "%{http_code}" -X POST "$url" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      -d "$gemini_body" \
      -o "$out" \
      --max-time 120 2>/dev/null)
    
    case "$http_code" in
      200|201)
        success=1
        break
        ;;
      429)
        # Rate limited - exponential backoff
        if [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; then
          warn "  Gemini rate limited (429), retrying in ${delay}s (attempt $attempt/$SLOP_LLM_MAX_RETRIES)"
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        fi
        ;;
      500|502|503|504)
        # Server error - retry
        if [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; then
          warn "  Gemini server error ($http_code), retrying in ${delay}s"
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        fi
        ;;
      *)
        # Other error - fail
        warn "  Gemini API error: HTTP $http_code"
        return 0
        ;;
    esac
  done
  
  if [[ $success -eq 0 ]]; then
    warn "  Gemini API call failed after $SLOP_LLM_MAX_RETRIES retries"
    return 0
  fi

  if jq -e '.error' "$out" >/dev/null 2>&1; then
    local err_msg
    err_msg=$(jq -r '.error.message // "Unknown error"' "$out")
    warn "  Gemini error: $err_msg"
    return 0
  fi

  local content
  content=$(jq -r '.candidates[0].content.parts[0].text // ""' "$out" 2>/dev/null)
  # Use clean_json to handle chatty responses
  content=$(clean_json "$content")

  if echo "$content" | jq -e '.issues' >/dev/null 2>&1; then
    echo "$content" | jq -c '.issues[]' 2>/dev/null | while read -r issue; do
      local sev=$(echo "$issue" | jq -r '.severity // "medium"')
      local cat=$(echo "$issue" | jq -r '.category // "llm-analysis"')
      local file=$(echo "$issue" | jq -r '.file // "unknown"')
      local line=$(echo "$issue" | jq -r '.line // 1')
      local title=$(echo "$issue" | jq -r '.title // "Untitled"')
      local evidence=$(echo "$issue" | jq -r '.evidence // ""')
      local why=$(echo "$issue" | jq -r '.why // ""')
      local conf=$(echo "$issue" | jq -r '.confidence // 0.5')
      local fix=$(echo "$issue" | jq -r '.fix // ""')
      
      emit_issue "gemini" "$cat" "$sev" "$file" "$line" "$title" "$evidence" "$why" "$conf" "$fix"
    done
    say "  Gemini analysis complete"
  fi
}

########################################
# Report generation
########################################
generate_report() {
  local root="$1"
  local out_md="$2"

  say "Generating report..."

  python3 - "$root" "$out_md" "$ISSUES_JSONL" "$MODE" "$VERSION" <<'PYTHON'
import sys, json, datetime, collections, pathlib, subprocess, re

root, out_md, issues_path, mode, version = sys.argv[1:6]

def sev_score(s):
    return {"blocker": 5, "high": 4, "medium": 3, "low": 2, "note": 1}.get((s or "note").lower(), 1)

issues = []
seen = {}
with open(issues_path, "r", errors="ignore") as f:
    for line in f:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except:
            continue
        obj["severity"] = (obj.get("severity") or "medium").lower()
        obj["confidence"] = float(obj.get("confidence") or 0.5)
        obj["line"] = int(obj.get("line") or 1)
        
        key = (obj.get("category", ""), obj.get("file", ""), obj["line"], 
               re.sub(r'\s+', ' ', (obj.get("title") or "").lower().strip())[:50])
        
        if key not in seen or (sev_score(obj["severity"]), obj["confidence"]) > \
           (sev_score(seen[key]["severity"]), seen[key]["confidence"]):
            seen[key] = obj

issues = sorted(seen.values(), key=lambda x: (sev_score(x["severity"]), x["confidence"]), reverse=True)

by_sev = collections.Counter(i["severity"] for i in issues)
by_cat = collections.Counter(i.get("category", "unknown").split("/")[0] for i in issues)
by_src = collections.Counter(i.get("source", "unknown").split("/")[0] for i in issues)

git_commit = ""
try:
    git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()[:12]
except:
    pass

now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

sev_emoji = {"blocker": "🛑", "high": "🔥", "medium": "⚠️", "low": "🟡"}

with open(out_md, "w") as out:
    out.write(f"# 🔍 Slop Scanner Ultimate Report\n\n")
    out.write(f"**Generated:** {now}  \n")
    out.write(f"**Root:** `{root}`  \n")
    if git_commit:
        out.write(f"**Commit:** `{git_commit}`  \n")
    out.write(f"**Mode:** `{mode}` | **Version:** `{version}`\n\n")
    out.write("---\n\n")
    
    out.write("## 📊 Summary\n\n")
    out.write(f"**Total Issues:** {len(issues)}\n\n")
    
    if not issues:
        out.write("> ✅ No issues detected! Your codebase is clean.\n")
    else:
        out.write("| Severity | Count |\n|----------|-------|\n")
        for sev in ["blocker", "high", "medium", "low"]:
            if by_sev.get(sev):
                out.write(f"| {sev_emoji.get(sev, '📝')} {sev.title()} | {by_sev[sev]} |\n")
        
        out.write("\n**Top Categories:** ")
        out.write(", ".join(f"{cat} ({cnt})" for cat, cnt in by_cat.most_common(8)))
        out.write("\n\n")
        
        out.write("**Sources:** ")
        out.write(", ".join(f"{src} ({cnt})" for src, cnt in by_src.most_common()))
        out.write("\n\n---\n\n")
        
        out.write("## 🔎 Findings\n\n")
        
        for idx, it in enumerate(issues[:200], 1):
            sev = it["severity"]
            out.write(f"### {idx}. {sev_emoji.get(sev, '📝')} {it.get('title', 'Untitled')}\n\n")
            out.write(f"- **Severity:** {sev} | **Confidence:** {it['confidence']:.0%}\n")
            out.write(f"- **Category:** `{it.get('category', 'unknown')}` | **Source:** `{it.get('source', 'unknown')}`\n")
            out.write(f"- **Location:** `{it.get('file', 'unknown')}:{it['line']}`\n\n")
            
            if it.get("evidence"):
                out.write("**Evidence:**\n```\n")
                out.write(it["evidence"][:500])
                out.write("\n```\n\n")
            
            if it.get("why"):
                out.write(f"**Why:** {it['why']}\n\n")
            
            if it.get("fix"):
                out.write(f"**Fix:** {it['fix']}\n\n")
            
            out.write("---\n\n")

print(f"Report written: {out_md}")
PYTHON
}

########################################
# Plan generation
########################################
########################################
# INTELLIGENT CHUNKING & TOKEN ESTIMATION
########################################
estimate_tokens() {
  # Rough token estimation: ~4 chars per token
  local chars="${1:-0}"
  echo $(( chars / SLOP_CHARS_PER_TOKEN ))
}

chunk_issues_by_category() {
  # Chunk issues.jsonl into category-specific files for parallel processing
  local output_dir="$1"
  mkdir -p "$output_dir"
  
  # Group by category
  python3 - "$ISSUES_JSONL" "$output_dir" "$SLOP_MAX_ISSUES_PER_CHUNK" <<'PYTHON'
import sys, json, os
from collections import defaultdict

issues_path, output_dir, max_per_chunk = sys.argv[1], sys.argv[2], int(sys.argv[3])

# Read all issues
issues = []
with open(issues_path, "r", errors="ignore") as f:
    for line in f:
        try:
            issues.append(json.loads(line.strip()))
        except:
            pass

# Group by category
by_category = defaultdict(list)
for issue in issues:
    cat = issue.get("category", "other")
    by_category[cat].append(issue)

# Write chunks
chunk_manifest = []
for cat, cat_issues in by_category.items():
    # Sort by severity then confidence
    sev_order = {"blocker": 0, "high": 1, "medium": 2, "low": 3}
    cat_issues.sort(key=lambda x: (sev_order.get(x.get("severity", "medium"), 2), -float(x.get("confidence", 0.5))))
    
    # Chunk if too large
    for i in range(0, len(cat_issues), max_per_chunk):
        chunk = cat_issues[i:i+max_per_chunk]
        chunk_id = f"{cat}_{i//max_per_chunk}"
        chunk_file = os.path.join(output_dir, f"chunk_{chunk_id}.jsonl")
        
        with open(chunk_file, "w") as f:
            for issue in chunk:
                f.write(json.dumps(issue) + "\n")
        
        chunk_manifest.append({
            "id": chunk_id,
            "category": cat,
            "file": chunk_file,
            "count": len(chunk),
            "blockers": sum(1 for x in chunk if x.get("severity") == "blocker"),
            "highs": sum(1 for x in chunk if x.get("severity") == "high")
        })

# Write manifest
with open(os.path.join(output_dir, "manifest.json"), "w") as f:
    json.dump({"chunks": chunk_manifest, "total_issues": len(issues)}, f, indent=2)

print(f"Created {len(chunk_manifest)} chunks from {len(issues)} issues")
PYTHON
}

chunk_repo_by_directory() {
  # Chunk repo files by directory for parallel analysis
  local output_dir="$1"
  mkdir -p "$output_dir"
  
  local root
  root="$(repo_root)"
  
  python3 - "$root" "$output_dir" "$SLOP_MAX_FILES_PER_CHUNK" <<'PYTHON'
import sys, os, json
from collections import defaultdict
from pathlib import Path

root, output_dir, max_files = sys.argv[1], sys.argv[2], int(sys.argv[3])

# Collect source files
source_exts = {'.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.rs', '.java', '.rb', '.php', '.cs'}
skip_dirs = {'node_modules', '.git', 'dist', 'build', '.next', '__pycache__', '.venv', 'vendor', 'coverage'}

files_by_dir = defaultdict(list)
all_files = []

for dirpath, dirnames, filenames in os.walk(root):
    # Skip excluded directories
    dirnames[:] = [d for d in dirnames if d not in skip_dirs]
    
    rel_dir = os.path.relpath(dirpath, root)
    if rel_dir == '.':
        rel_dir = 'root'
    
    # Get top-level directory for grouping
    parts = rel_dir.split(os.sep)
    group_dir = parts[0] if parts[0] not in ('.', 'root') else 'root'
    if len(parts) > 1 and parts[0] in ('src', 'lib', 'packages', 'apps'):
        group_dir = os.path.join(parts[0], parts[1]) if len(parts) > 1 else parts[0]
    
    for fname in filenames:
        ext = os.path.splitext(fname)[1].lower()
        if ext in source_exts:
            rel_path = os.path.relpath(os.path.join(dirpath, fname), root)
            files_by_dir[group_dir].append(rel_path)
            all_files.append(rel_path)

# Create chunks
chunks = []
chunk_id = 0

for dir_name, files in files_by_dir.items():
    # Sub-chunk if too large
    for i in range(0, len(files), max_files):
        chunk_files = files[i:i+max_files]
        chunk_name = f"dir_{chunk_id}_{dir_name.replace('/', '_')}"
        chunk_file = os.path.join(output_dir, f"{chunk_name}.json")
        
        # Sample first 80 lines of each file
        file_samples = {}
        for f in chunk_files:
            full_path = os.path.join(root, f)
            try:
                with open(full_path, 'r', errors='ignore') as fp:
                    lines = fp.readlines()[:80]
                    file_samples[f] = ''.join(lines)
            except:
                file_samples[f] = ""
        
        with open(chunk_file, 'w') as fp:
            json.dump({
                "chunk_id": chunk_name,
                "directory": dir_name,
                "files": chunk_files,
                "samples": file_samples
            }, fp, indent=2)
        
        chunks.append({
            "id": chunk_name,
            "directory": dir_name,
            "file": chunk_file,
            "file_count": len(chunk_files)
        })
        chunk_id += 1

# Write manifest
with open(os.path.join(output_dir, "repo_manifest.json"), 'w') as f:
    json.dump({
        "chunks": chunks,
        "total_files": len(all_files),
        "directories": list(files_by_dir.keys())
    }, f, indent=2)

print(f"Created {len(chunks)} repo chunks from {len(all_files)} files in {len(files_by_dir)} directories")
PYTHON
}

########################################
# PARALLEL AGENT ORCHESTRATION
########################################
########################################
# PARALLEL AGENT CHUNK WORKER
# This function is exported for parallel execution
# Uses proper retry logic and avoids injection vulnerabilities
########################################
analyze_chunk_worker() {
  local chunk_file="$1"
  [[ -f "$chunk_file" ]] || return 0
  
  local chunk_id
  chunk_id=$(basename "$chunk_file" .json)
  local result_file="${SLOP_AGENT_RESULTS_DIR}/${chunk_id}_results.json"
  
  # Read chunk content safely
  local chunk_content
  chunk_content=$(head -c 40000 "$chunk_file")
  
  # Construct prompt using the environment variable (safe from injection)
  local prompt="${SLOP_AGENT_PROMPT_BASE}

CHUNK TO ANALYZE:
$chunk_content"

  # Construct request body using jq (handles escaping properly)
  local request_body
  request_body=$(jq -nc \
    --arg model "$SLOP_CLAUDE_MODEL" \
    --arg prompt "$prompt" \
    '{model: $model, max_tokens: 4000, messages: [{role: "user", content: $prompt}]}')

  # Use retry logic to handle rate limits
  local attempt=0
  local delay="$SLOP_LLM_RETRY_DELAY"
  local success=0
  
  while [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; do
    ((attempt++))
    
    local http_code
    http_code=$(curl -s -w "%{http_code}" -X POST "https://api.anthropic.com/v1/messages" \
      -H "Content-Type: application/json" \
      -H "x-api-key: ${SLOP_CLAUDE_API_KEY}" \
      -H "anthropic-version: 2023-06-01" \
      -d "$request_body" \
      -o "$result_file.raw" \
      --max-time 120 2>/dev/null)
    
    case "$http_code" in
      200|201)
        success=1
        break
        ;;
      429)
        # Rate limited - exponential backoff
        if [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; then
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        fi
        ;;
      500|502|503|504)
        # Server error - retry
        if [[ $attempt -lt $SLOP_LLM_MAX_RETRIES ]]; then
          sleep "$delay"
          delay=$((delay * SLOP_LLM_BACKOFF_MULT))
        fi
        ;;
      *)
        # Other error - fail this chunk
        echo "[]" > "$result_file"
        return 0
        ;;
    esac
  done
  
  if [[ $success -eq 1 ]] && [[ -f "$result_file.raw" ]]; then
    # Extract text content
    local raw_content
    raw_content=$(jq -r '.content[0].text // "[]"' "$result_file.raw" 2>/dev/null)
    
    # Clean JSON (handle chatty LLM responses)
    # Inline version of clean_json for parallel safety
    python3 -c "
import sys, re, json
content = sys.argv[1] if len(sys.argv) > 1 else '[]'
content = re.sub(r'^\`\`\`json\s*', '', content, flags=re.MULTILINE)
content = re.sub(r'\`\`\`$', '', content)
try:
    parsed = json.loads(content.strip())
    print(json.dumps(parsed))
except:
    match = re.search(r'\[.*\]', content, re.DOTALL)
    if match:
        try:
            print(json.dumps(json.loads(match.group(0))))
        except:
            print('[]')
    else:
        print('[]')
" "$raw_content" > "$result_file" 2>/dev/null || echo "[]" > "$result_file"
  else
    echo "[]" > "$result_file"
  fi
}

run_parallel_analysis_agents() {
  say "Running parallel analysis agents across repo chunks..."
  
  local chunks_dir="$WORKDIR/repo_chunks"
  chunk_repo_by_directory "$chunks_dir"
  
  local manifest="$chunks_dir/repo_manifest.json"
  [[ -f "$manifest" ]] || { warn "No repo manifest found"; return 0; }
  
  local chunk_count
  chunk_count=$(jq '.chunks | length' "$manifest" 2>/dev/null || echo 0)
  [[ "$chunk_count" -gt 0 ]] || { warn "No chunks to analyze"; return 0; }
  
  say "  Analyzing $chunk_count directory chunks with $SLOP_PARALLEL_AGENTS parallel agents..."
  
  # Agent prompt template (stored in env var for safe export)
  export SLOP_AGENT_PROMPT_BASE="You are a code quality agent analyzing a chunk of a large repository.
Your job is to find REAL issues, not theoretical ones. Focus on:
1. Functions that don't actually work (stub implementations, missing logic)
2. Tests that don't test anything (no assertions, always pass)
3. Security vulnerabilities (hardcoded secrets, injection points)
4. Dead code (unused exports, unreachable branches)
5. AI slop patterns (placeholder phrases, scaffold comments)
6. Missing error handling (bare catches, unhandled promises)

For each issue found, provide:
- Exact file path and line number
- Specific evidence from the code
- Why it's a real problem (not style nitpick)
- Concrete fix steps

Output ONLY valid JSON array:
[{\"severity\":\"blocker|high|medium|low\",\"category\":\"string\",\"file\":\"string\",\"line\":number,\"title\":\"string\",\"evidence\":\"actual code snippet\",\"why\":\"explanation\",\"confidence\":0.0-1.0,\"fix\":\"specific steps\"}]

Be RUTHLESS. Fewer high-confidence issues are better than many guesses."

  # Process chunks in parallel
  export SLOP_AGENT_RESULTS_DIR="$WORKDIR/agent_results"
  mkdir -p "$SLOP_AGENT_RESULTS_DIR"
  
  # Export all needed variables for parallel workers
  export SLOP_CLAUDE_API_KEY SLOP_CLAUDE_MODEL
  export SLOP_LLM_MAX_RETRIES SLOP_LLM_RETRY_DELAY SLOP_LLM_BACKOFF_MULT
  export -f analyze_chunk_worker 2>/dev/null || true
  
  # Build chunk list
  jq -r '.chunks[].file' "$manifest" > "$WORKDIR/chunk_files.txt"
  
  if [[ "$SLOP_USE_PARALLEL" == "1" ]] && need_cmd parallel && [[ -n "$SLOP_CLAUDE_API_KEY" ]]; then
    # Run parallel workers - function name passed to parallel, safe from injection
    cat "$WORKDIR/chunk_files.txt" | parallel -j "$SLOP_PARALLEL_AGENTS" --halt never analyze_chunk_worker '{}' 2>/dev/null || true
  else
    # Sequential fallback (also works without parallel installed)
    while IFS= read -r chunk_file; do
      analyze_chunk_worker "$chunk_file"
    done < "$WORKDIR/chunk_files.txt"
  fi
  
  # Aggregate all agent results into issues.jsonl
  say "  Aggregating agent results..."
  for result_file in "$SLOP_AGENT_RESULTS_DIR"/*.json; do
    [[ -f "$result_file" ]] || continue
    # Parse and emit issues
    python3 - "$result_file" "$ISSUES_JSONL" <<'PYTHON'
import sys, json

result_file, issues_path = sys.argv[1], sys.argv[2]

try:
    with open(result_file, 'r') as f:
        content = f.read().strip()
        # Try to extract JSON array
        if content.startswith('['):
            issues = json.loads(content)
        else:
            # Try to find JSON in response
            import re
            match = re.search(r'\[.*\]', content, re.DOTALL)
            issues = json.loads(match.group()) if match else []
except:
    issues = []

with open(issues_path, 'a') as f:
    for issue in issues:
        if isinstance(issue, dict) and issue.get('file'):
            issue['source'] = 'parallel-agent'
            f.write(json.dumps(issue) + '\n')
PYTHON
  done
  
  say "  Parallel analysis complete"
}

########################################
# ITERATIVE MULTI-PASS PLANNING
########################################
generate_plan() {
  [[ "$SLOP_ENABLE_PLAN" == "1" ]] || return 0
  [[ -n "$CLAUDE_AUTH_METHOD" ]] || { warn "Plan generation requires Claude authentication"; return 0; }

  plan "═══════════════════════════════════════════════════════════════════════════"
  plan "GENERATING COMPREHENSIVE REMEDIATION PLAN (Multi-Pass)"
  plan "═══════════════════════════════════════════════════════════════════════════"

  local root ts plan_dir
  root="$(repo_root)"
  ts="$(ts_utc)"
  plan_dir="$root/.gatekeeper/plans/slop-${ts}"
  mkdir -p "$plan_dir"

  local issue_count
  issue_count=$(wc -l < "$ISSUES_JSONL" | tr -d ' ')
  [[ "$issue_count" -gt 0 ]] || { plan "No issues to plan for"; return 0; }
  
  plan "Total issues to plan: $issue_count"

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 1: CHUNK ISSUES BY CATEGORY
  # ═══════════════════════════════════════════════════════════════════════════
  plan "Phase 1: Chunking issues by category..."
  local chunks_dir="$WORKDIR/issue_chunks"
  chunk_issues_by_category "$chunks_dir"
  
  local chunk_manifest="$chunks_dir/manifest.json"
  local chunk_count
  chunk_count=$(jq '.chunks | length' "$chunk_manifest" 2>/dev/null || echo 0)
  plan "  Created $chunk_count issue chunks"

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 2: PARALLEL CATEGORY PLANNING
  # ═══════════════════════════════════════════════════════════════════════════
  plan "Phase 2: Running $SLOP_PARALLEL_AGENTS parallel planning agents..."
  
  local category_plans_dir="$WORKDIR/category_plans"
  mkdir -p "$category_plans_dir"
  
  # Generate per-category plans in parallel
  # NOTE: Using process substitution to avoid subshell (so wait works)
  while read -r chunk_b64; do
    local chunk_data chunk_id chunk_file chunk_cat
    chunk_data=$(echo "$chunk_b64" | base64 -d)
    chunk_id=$(echo "$chunk_data" | jq -r '.id')
    chunk_file=$(echo "$chunk_data" | jq -r '.file')
    chunk_cat=$(echo "$chunk_data" | jq -r '.category')
    
    # Run planning agent for this chunk
    (
      local issues_content plan_file
      issues_content=$(head -c 30000 "$chunk_file")
      plan_file="$category_plans_dir/${chunk_id}_plan.json"
      
      local plan_prompt="You are a remediation planner for the '$chunk_cat' category.

ISSUES TO FIX:
$issues_content

Create a detailed remediation plan for these issues. Rules:
1. Group related fixes (same file, same pattern)
2. Each task must be ATOMIC and SPECIFIC
3. Include exact file paths and line numbers
4. Verification must be concrete (grep pattern, test command, etc.)
5. Estimate minutes realistically (5-30 per task)

Priority order within category:
- blockers first
- then high severity
- group by file when possible

Output ONLY valid JSON:
{
  \"category\": \"$chunk_cat\",
  \"task_count\": N,
  \"estimated_total_minutes\": N,
  \"tasks\": [
    {
      \"id\": \"${chunk_cat}_1\",
      \"severity\": \"blocker|high|medium|low\",
      \"file\": \"path/to/file.ts\",
      \"line\": 42,
      \"title\": \"Short descriptive title\",
      \"issue_summary\": \"What's wrong\",
      \"steps\": [
        \"Step 1: Specific action with exact changes\",
        \"Step 2: Another specific action\",
        \"Step 3: Final changes needed\"
      ],
      \"verification\": \"Command or check to verify fix\",
      \"estimated_minutes\": 15,
      \"dependencies\": []
    }
  ]
}"

      if call_claude "$plan_prompt" "$plan_file.raw" "$SLOP_CLAUDE_MODEL_PLANNING" 2>/dev/null; then
        # Use robust JSON sanitizer instead of simple sed
        local raw_text
        raw_text=$(jq -r '.content[0].text // "{}"' "$plan_file.raw" 2>/dev/null)
        clean_json "$raw_text" > "$plan_file"
      else
        echo '{"category":"'"$chunk_cat"'","tasks":[]}' > "$plan_file"
      fi
    ) &
    
    # Limit parallel jobs
    while [[ $(jobs -r | wc -l) -ge $SLOP_PARALLEL_AGENTS ]]; do
      sleep 0.5
    done
  done < <(jq -r '.chunks[] | @base64' "$chunk_manifest")
  
  # Wait for all planning jobs
  wait
  plan "  Category plans generated"

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 3: AGGREGATE & MERGE PLANS
  # ═══════════════════════════════════════════════════════════════════════════
  plan "Phase 3: Aggregating category plans..."
  
  local merged_plan="$WORKDIR/merged_plan.json"
  python3 - "$category_plans_dir" "$merged_plan" <<'PYTHON'
import sys, json, os
from collections import defaultdict

plans_dir, output_file = sys.argv[1], sys.argv[2]

all_tasks = []
category_stats = defaultdict(lambda: {"count": 0, "minutes": 0, "blockers": 0})

for fname in os.listdir(plans_dir):
    if not fname.endswith('_plan.json'):
        continue
    
    try:
        with open(os.path.join(plans_dir, fname), 'r') as f:
            content = f.read().strip()
            # Extract JSON
            if '{' in content:
                start = content.index('{')
                end = content.rindex('}') + 1
                plan = json.loads(content[start:end])
            else:
                continue
    except:
        continue
    
    cat = plan.get('category', 'other')
    tasks = plan.get('tasks', [])
    
    for task in tasks:
        task['category'] = cat
        all_tasks.append(task)
        
        category_stats[cat]['count'] += 1
        category_stats[cat]['minutes'] += task.get('estimated_minutes', 15)
        if task.get('severity') == 'blocker':
            category_stats[cat]['blockers'] += 1

# Sort by severity then category priority
sev_order = {'blocker': 0, 'high': 1, 'medium': 2, 'low': 3}
cat_priority = {
    'security': 0, 'cred-scan': 0,
    'test-quality': 1, 'test-coverage': 1,
    'ai-slop': 2, 'slop': 2,
    'dead-code': 3, 'deadcode': 3,
    'supply-chain': 4, 'supplychain': 4,
    'docs': 5, 'doc-drift': 5,
    'ci': 6, 'ci-quality': 6,
    'cleanup': 7, 'structure': 7
}

all_tasks.sort(key=lambda x: (
    sev_order.get(x.get('severity', 'medium'), 2),
    cat_priority.get(x.get('category', 'other'), 10)
))

# Write merged plan
merged = {
    "total_tasks": len(all_tasks),
    "total_minutes": sum(t.get('estimated_minutes', 15) for t in all_tasks),
    "category_stats": dict(category_stats),
    "tasks": all_tasks
}

with open(output_file, 'w') as f:
    json.dump(merged, f, indent=2)

print(f"Merged {len(all_tasks)} tasks from {len(category_stats)} categories")
PYTHON

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 4: PLAN REVIEW & UPGRADE (if enabled)
  # ═══════════════════════════════════════════════════════════════════════════
  if [[ "$SLOP_ENABLE_PLAN_REVIEW" == "1" ]] && [[ "$SLOP_PLAN_ITERATIONS" -gt 1 ]]; then
    plan "Phase 4: Reviewing and upgrading plan ($SLOP_PLAN_ITERATIONS iterations)..."
    
    for ((iteration=1; iteration<=SLOP_PLAN_ITERATIONS; iteration++)); do
      plan "  Iteration $iteration/$SLOP_PLAN_ITERATIONS..."
      
      local review_prompt review_result
      local current_plan
      current_plan=$(head -c 40000 "$merged_plan")
      
      review_prompt="You are a senior engineer reviewing a remediation plan.

CURRENT PLAN:
$current_plan

Review this plan and identify:
1. Missing tasks (issues not covered)
2. Tasks that are too vague (need more specific steps)
3. Tasks that should be combined (duplicate work)
4. Wrong severity assignments
5. Missing verification steps
6. Unrealistic time estimates

For each improvement, provide the EXACT task JSON to add or the EXACT modification.

Output ONLY valid JSON:
{
  \"review_notes\": [\"Note 1\", \"Note 2\"],
  \"tasks_to_add\": [{...task JSON...}],
  \"tasks_to_modify\": [{\"original_id\": \"...\", \"modifications\": {...}}],
  \"tasks_to_remove\": [\"id1\", \"id2\"],
  \"overall_quality_score\": 0.0-1.0
}"

      review_result="$WORKDIR/review_${iteration}.json"
      if call_claude "$review_prompt" "$review_result.raw" "$SLOP_CLAUDE_MODEL_PLANNING" 2>/dev/null; then
        # Use robust JSON sanitizer
        local raw_review
        raw_review=$(jq -r '.content[0].text // "{}"' "$review_result.raw" 2>/dev/null)
        clean_json "$raw_review" > "$review_result"
        
        # Apply review improvements
        python3 - "$merged_plan" "$review_result" <<'PYTHON'
import sys, json

plan_file, review_file = sys.argv[1], sys.argv[2]

try:
    with open(plan_file, 'r') as f:
        plan = json.load(f)
except:
    sys.exit(0)

try:
    with open(review_file, 'r') as f:
        content = f.read().strip()
        if '{' in content:
            start = content.index('{')
            end = content.rindex('}') + 1
            review = json.loads(content[start:end])
        else:
            sys.exit(0)
except:
    sys.exit(0)

# Add new tasks
for task in review.get('tasks_to_add', []):
    if isinstance(task, dict) and task.get('title'):
        plan['tasks'].append(task)
        plan['total_tasks'] = len(plan['tasks'])

# Remove tasks
ids_to_remove = set(review.get('tasks_to_remove', []))
if ids_to_remove:
    plan['tasks'] = [t for t in plan['tasks'] if t.get('id') not in ids_to_remove]
    plan['total_tasks'] = len(plan['tasks'])

# Update total time
plan['total_minutes'] = sum(t.get('estimated_minutes', 15) for t in plan['tasks'])

# Write back
with open(plan_file, 'w') as f:
    json.dump(plan, f, indent=2)

quality = review.get('overall_quality_score', 0)
print(f"Applied review (quality: {quality}). Now {plan['total_tasks']} tasks.")
PYTHON
      fi
    done
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # PHASE 5: CHUNK INTO STAGES
  # ═══════════════════════════════════════════════════════════════════════════
  plan "Phase 5: Chunking into stage files (max $SLOP_MAX_TASKS_PER_STAGE tasks/stage)..."
  
  python3 - "$merged_plan" "$plan_dir" "$SLOP_MAX_TASKS_PER_STAGE" "$VERSION" "$ts" "$issue_count" <<'PYTHON'
import sys, json, os, datetime

plan_file, plan_dir, max_tasks, version, ts, total_issues = sys.argv[1:7]
max_tasks = int(max_tasks)
total_issues = int(total_issues)

try:
    with open(plan_file, 'r') as f:
        plan = json.load(f)
except:
    plan = {"tasks": [], "total_tasks": 0, "total_minutes": 0}

tasks = plan.get('tasks', [])

# Group by severity for stage creation
sev_order = ['blocker', 'high', 'medium', 'low']
tasks_by_sev = {s: [] for s in sev_order}
for task in tasks:
    sev = task.get('severity', 'medium')
    if sev not in tasks_by_sev:
        sev = 'medium'
    tasks_by_sev[sev].append(task)

# Create stages
stages = []
stage_num = 1

# First: all blockers (may span multiple stages)
blocker_tasks = tasks_by_sev['blocker']
for i in range(0, len(blocker_tasks), max_tasks):
    chunk = blocker_tasks[i:i+max_tasks]
    stages.append({
        "number": stage_num,
        "title": f"🛑 Critical Blockers (Part {i//max_tasks + 1})" if len(blocker_tasks) > max_tasks else "🛑 Critical Blockers",
        "priority": "blocker",
        "tasks": chunk,
        "estimated_minutes": sum(t.get('estimated_minutes', 15) for t in chunk)
    })
    stage_num += 1

# Then: high priority
high_tasks = tasks_by_sev['high']
for i in range(0, len(high_tasks), max_tasks):
    chunk = high_tasks[i:i+max_tasks]
    # Group by category for title
    cats = list(set(t.get('category', 'other') for t in chunk))
    cat_str = ', '.join(cats[:3]) + ('...' if len(cats) > 3 else '')
    stages.append({
        "number": stage_num,
        "title": f"🔥 High Priority: {cat_str}",
        "priority": "high",
        "tasks": chunk,
        "estimated_minutes": sum(t.get('estimated_minutes', 15) for t in chunk)
    })
    stage_num += 1

# Then: medium
med_tasks = tasks_by_sev['medium']
for i in range(0, len(med_tasks), max_tasks):
    chunk = med_tasks[i:i+max_tasks]
    cats = list(set(t.get('category', 'other') for t in chunk))
    cat_str = ', '.join(cats[:3]) + ('...' if len(cats) > 3 else '')
    stages.append({
        "number": stage_num,
        "title": f"⚠️ Medium Priority: {cat_str}",
        "priority": "medium",
        "tasks": chunk,
        "estimated_minutes": sum(t.get('estimated_minutes', 15) for t in chunk)
    })
    stage_num += 1

# Finally: low
low_tasks = tasks_by_sev['low']
for i in range(0, len(low_tasks), max_tasks):
    chunk = low_tasks[i:i+max_tasks]
    cats = list(set(t.get('category', 'other') for t in chunk))
    cat_str = ', '.join(cats[:3]) + ('...' if len(cats) > 3 else '')
    stages.append({
        "number": stage_num,
        "title": f"🟡 Low Priority: {cat_str}",
        "priority": "low",
        "tasks": chunk,
        "estimated_minutes": sum(t.get('estimated_minutes', 15) for t in chunk)
    })
    stage_num += 1

# ═══════════════════════════════════════════════════════════════════════════
# WRITE STAGE FILES
# ═══════════════════════════════════════════════════════════════════════════
for stage in stages:
    num = stage['number']
    with open(os.path.join(plan_dir, f'stage-{num}.md'), 'w') as f:
        f.write(f"# Stage {num}: {stage['title']}\n\n")
        f.write(f"**Priority:** {stage['priority']}  \n")
        f.write(f"**Tasks:** {len(stage['tasks'])}  \n")
        f.write(f"**Estimated Time:** ~{stage['estimated_minutes']} minutes  \n\n")
        f.write("---\n\n")
        
        for i, task in enumerate(stage['tasks'], 1):
            task_id = task.get('id', f'{num}.{i}')
            f.write(f"## Task {task_id}: {task.get('title', 'Untitled')}\n\n")
            f.write(f"- **File:** `{task.get('file', 'unknown')}`\n")
            f.write(f"- **Line:** {task.get('line', '?')}\n")
            f.write(f"- **Category:** {task.get('category', 'other')}\n")
            f.write(f"- **Severity:** {task.get('severity', 'medium')}\n")
            f.write(f"- **Est. Time:** {task.get('estimated_minutes', 15)} min\n\n")
            
            if task.get('issue_summary'):
                f.write(f"### Issue\n{task['issue_summary']}\n\n")
            
            if task.get('evidence'):
                f.write(f"### Evidence\n```\n{task['evidence'][:500]}\n```\n\n")
            
            f.write("### Steps\n")
            for step_i, step in enumerate(task.get('steps', ['Complete this task']), 1):
                f.write(f"{step_i}. {step}\n")
            f.write("\n")
            
            if task.get('verification'):
                f.write(f"### Verification\n```bash\n{task['verification']}\n```\n\n")
            
            if task.get('dependencies'):
                f.write(f"### Dependencies\n")
                for dep in task['dependencies']:
                    f.write(f"- {dep}\n")
                f.write("\n")
            
            f.write("### Status\n- [ ] Not Started\n\n")
            f.write("---\n\n")

# ═══════════════════════════════════════════════════════════════════════════
# WRITE OVERVIEW.MD
# ═══════════════════════════════════════════════════════════════════════════
total_tasks = sum(len(s['tasks']) for s in stages)
total_minutes = sum(s['estimated_minutes'] for s in stages)

# Count by severity
by_sev = {'blocker': 0, 'high': 0, 'medium': 0, 'low': 0}
by_cat = {}
for stage in stages:
    for task in stage['tasks']:
        sev = task.get('severity', 'medium')
        by_sev[sev] = by_sev.get(sev, 0) + 1
        cat = task.get('category', 'other')
        by_cat[cat] = by_cat.get(cat, 0) + 1

with open(os.path.join(plan_dir, 'overview.md'), 'w') as f:
    f.write("# 🔧 Slop Remediation Plan\n\n")
    f.write(f"**Plan ID:** `slop-{ts}`  \n")
    f.write(f"**Generated:** {datetime.datetime.utcnow().isoformat()}Z  \n")
    f.write(f"**Scanner Version:** {version}  \n")
    f.write(f"**Planning Mode:** Multi-Pass Parallel  \n\n")
    f.write("---\n\n")
    
    f.write("## 📊 Executive Summary\n\n")
    f.write("| Metric | Value |\n")
    f.write("|--------|-------|\n")
    f.write(f"| Total Issues Scanned | **{total_issues}** |\n")
    f.write(f"| Total Tasks Generated | **{total_tasks}** |\n")
    f.write(f"| Total Stages | **{len(stages)}** |\n")
    f.write(f"| Est. Total Time | **~{total_minutes} min** ({total_minutes//60}h {total_minutes%60}m) |\n\n")
    
    f.write("### By Severity\n\n")
    f.write("| Severity | Count | % |\n")
    f.write("|----------|-------|---|\n")
    for sev in ['blocker', 'high', 'medium', 'low']:
        pct = (by_sev[sev] * 100 // total_tasks) if total_tasks > 0 else 0
        icon = {'blocker': '🛑', 'high': '🔥', 'medium': '⚠️', 'low': '🟡'}[sev]
        f.write(f"| {icon} {sev.title()} | {by_sev[sev]} | {pct}% |\n")
    f.write("\n")
    
    f.write("### By Category\n\n")
    f.write("| Category | Count |\n")
    f.write("|----------|-------|\n")
    for cat, count in sorted(by_cat.items(), key=lambda x: -x[1])[:10]:
        f.write(f"| {cat} | {count} |\n")
    f.write("\n")
    
    f.write("---\n\n")
    f.write("## 📋 Stage Overview\n\n")
    
    for stage in stages:
        num = stage['number']
        f.write(f"### Stage {num}: {stage['title']}\n\n")
        f.write(f"- **Priority:** {stage['priority']}\n")
        f.write(f"- **Tasks:** {len(stage['tasks'])}\n")
        f.write(f"- **Est. Time:** ~{stage['estimated_minutes']} min\n")
        f.write(f"- **File:** [`stage-{num}.md`](stage-{num}.md)\n\n")
        
        # List task titles
        f.write("**Tasks:**\n")
        for task in stage['tasks'][:5]:
            f.write(f"- {task.get('id', '?')}: {task.get('title', 'Untitled')[:60]}...\n")
        if len(stage['tasks']) > 5:
            f.write(f"- ... and {len(stage['tasks'])-5} more\n")
        f.write("\n")
    
    f.write("---\n\n")
    f.write("## 🚀 How to Use This Plan\n\n")
    f.write("### For Humans\n")
    f.write("1. Start with `stage-1.md` (blockers first)\n")
    f.write("2. Complete each task, checking off status\n")
    f.write("3. Run verification commands after each fix\n")
    f.write("4. Update `progress.md` as you go\n")
    f.write("5. Move to next stage when current is complete\n\n")
    
    f.write("### For AI Agents\n")
    f.write("1. Load `overview.md` first to understand scope\n")
    f.write("2. Load current stage file (check `progress.md`)\n")
    f.write("3. Process tasks sequentially within stage\n")
    f.write("4. If context limit approaching:\n")
    f.write("   - Save current position to `progress.md`\n")
    f.write("   - Start new conversation\n")
    f.write("   - Resume from saved position\n")
    f.write("5. Run verification after each task\n")
    f.write("6. Mark tasks complete in stage file\n\n")
    
    f.write("### Context Management\n")
    f.write("- Each stage file is designed to fit in one context window\n")
    f.write(f"- Maximum {len(stage['tasks']) if stages else 0} tasks per stage\n")
    f.write("- If you hit limits mid-stage, note the task ID in progress.md\n")
    f.write("- Next session: resume from that task ID\n\n")

# ═══════════════════════════════════════════════════════════════════════════
# WRITE PROGRESS.MD
# ═══════════════════════════════════════════════════════════════════════════
with open(os.path.join(plan_dir, 'progress.md'), 'w') as f:
    f.write("# 📈 Remediation Progress\n\n")
    f.write(f"**Plan ID:** `slop-{ts}`  \n")
    f.write(f"**Started:** {datetime.datetime.utcnow().isoformat()}Z  \n")
    f.write(f"**Last Updated:** {datetime.datetime.utcnow().isoformat()}Z  \n\n")
    f.write("---\n\n")
    
    f.write("## Current Status\n\n")
    f.write("| Stage | Status | Completed | Total |\n")
    f.write("|-------|--------|-----------|-------|\n")
    for stage in stages:
        f.write(f"| Stage {stage['number']} | ⏳ Not Started | 0 | {len(stage['tasks'])} |\n")
    f.write("\n")
    
    f.write("## Session Log\n\n")
    f.write("### Session 1\n")
    f.write(f"- **Started:** {datetime.datetime.utcnow().isoformat()}Z\n")
    f.write("- **Current Stage:** 1\n")
    f.write("- **Current Task:** 1.1\n")
    f.write("- **Notes:** Starting fresh\n\n")
    
    f.write("---\n\n")
    f.write("## How to Update\n\n")
    f.write("After completing tasks, update this file:\n\n")
    f.write("```markdown\n")
    f.write("| Stage 1 | ✅ Complete | 12 | 12 |\n")
    f.write("| Stage 2 | 🔄 In Progress | 5 | 10 |\n")
    f.write("```\n\n")
    f.write("When resuming in a new session:\n\n")
    f.write("```markdown\n")
    f.write("### Session 2\n")
    f.write("- **Started:** [timestamp]\n")
    f.write("- **Current Stage:** 2\n")
    f.write("- **Current Task:** 2.6\n")
    f.write("- **Notes:** Resuming from task 2.6\n")
    f.write("```\n")

print(f"Generated {len(stages)} stage files + overview.md + progress.md")
print(f"Total: {total_tasks} tasks, ~{total_minutes} minutes estimated")
PYTHON

  plan "═══════════════════════════════════════════════════════════════════════════"
  plan "Plan generated: $plan_dir"
  plan "  - overview.md: Executive summary & stage list"
  plan "  - progress.md: Progress tracking for multi-session work"
  plan "  - stage-N.md: Detailed tasks for each stage"
  plan "═══════════════════════════════════════════════════════════════════════════"
  
  echo "$plan_dir"
}

########################################
# Main
########################################
main() {
  local root ts out_md
  root="$(repo_root)"
  cd "$root"
  ts="$(ts_utc)"
  out_md="$root/cleanup-${ts}.md"

  WORKDIR="$(mktemp -d)"
  ISSUES_JSONL="$WORKDIR/issues.jsonl"
  touch "$ISSUES_JSONL"

  trap 'rm -rf "$WORKDIR"' EXIT

  echo ""
  echo -e "${WHITE}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
  if [[ "$SLOP_CERTIFY_MODE" == "1" ]]; then
    echo -e "${WHITE}║     SLOP SCANNER v${VERSION} — RELEASE CERTIFICATION MODE                        ║${NC}"
    echo -e "${WHITE}║     \"If it passes, I'm signing off that this can ship to customers\"          ║${NC}"
  else
    echo -e "${WHITE}║           SLOP SCANNER ULTIMATE v${VERSION} — The Ultimate AI Slop Detector       ║${NC}"
  fi
  echo -e "${WHITE}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  say "Root: $root"
  say "Mode: $MODE"
  say "Jobs: $SLOP_JOBS"
  [[ "$SLOP_CERTIFY_MODE" == "1" ]] && say "Certify: ENABLED (strict mode)"
  [[ "$SLOP_FULL_COVERAGE" == "1" ]] && say "Full Coverage: ENABLED (no truncation)"
  [[ "$SLOP_REDACT_SECRETS" == "1" ]] && say "Secret Redaction: ENABLED"
  [[ "$SLOP_LOCAL_DEPS" == "1" ]] && say "Local Deps: ENABLED (safe for laptops)"
  [[ -n "$SLOP_CACHE_DIR" ]] && say "LLM Caching: ENABLED ($SLOP_CACHE_DIR)"
  echo ""

  # Early requirements check (fail fast)
  check_requirements

  # Bootstrap dependencies (respects SLOP_LOCAL_DEPS)
  bootstrap

  detect_all_auth

  local start=$SECONDS

  # ═══════════════════════════════════════════════════════════════════════════
  # Contract Generation Mode (--generate-contract / --init)
  # ═══════════════════════════════════════════════════════════════════════════
  if [[ "$SLOP_GENERATE_CONTRACT" == "1" ]]; then
    say "Contract Generation Mode"
    echo ""
    
    generate_goldrecord_contract
    
    echo ""
    say "Next steps:"
    say "  1. Review and complete the generated goldrecord.yaml"
    say "  2. Run './slop-scanner-ultimate.sh --certify' to validate"
    echo ""
    
    # Exit after generation unless also running scan
    if [[ "$MODE" == "deep" ]] && [[ "$SLOP_CERTIFY_MODE" != "1" ]]; then
      exit 0
    fi
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # Stage 0: Contract & Build Verification (v6.0 - Proof of Life)
  # ═══════════════════════════════════════════════════════════════════════════
  if [[ "$SLOP_CERTIFY_MODE" == "1" ]] || [[ "$SLOP_REQUIRE_GOLDRECORD" == "1" ]]; then
    say "Stage 0: Contract validation..."
    validate_goldrecord
  fi

  if [[ "$SLOP_ENABLE_BUILD_CHECK" == "1" ]] && [[ "$MODE" != "fast" ]]; then
    say "Stage 0b: Build verification..."
    run_build_check
  fi

  if [[ "$SLOP_ENABLE_TEST_RUN" == "1" ]] && [[ "$MODE" != "fast" ]]; then
    say "Stage 0c: Test execution..."
    run_test_execution
  fi

  # Full coverage parallel scan (all files, no truncation)
  if [[ "$SLOP_FULL_COVERAGE" == "1" ]] && [[ "$MODE" != "fast" ]]; then
    say "Stage 0d: Full coverage scan..."
    run_full_coverage_scan
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # Stage 0e-0n: Certify Mode Deep Verification (v6.0 - God of Releases)
  # ═══════════════════════════════════════════════════════════════════════════
  if [[ "$SLOP_CERTIFY_MODE" == "1" ]]; then
    say "Stage 0e: Building surface area inventory..."
    build_inventory
    
    say "Stage 0f: Validating traceability matrix..."
    validate_traceability
    
    # V2 CONTRACT: Execute defined commands
    say "Stage 0g: Executing contract commands..."
    execute_contract_commands "build"
    execute_contract_commands "lint"
    execute_contract_commands "typecheck"
    execute_contract_commands "unit_tests"
    execute_contract_commands "integration_tests"
    execute_contract_commands "e2e_tests"
    execute_contract_commands "security"
    
    say "Stage 0h: Enforcing placeholder policy..."
    enforce_placeholder_policy
    
    say "Stage 0i: Checking test integrity..."
    check_test_integrity
    
    say "Stage 0j: Running flow-tagged tests..."
    run_flow_tagged_tests
    
    say "Stage 0k: Runtime verification..."
    run_runtime_check
    
    say "Stage 0l: Parsing coverage reports..."
    parse_coverage_report
    
    say "Stage 0m: Hard stub enforcement..."
    run_hard_stub_check
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # Stage 1: Pattern Scans & Heuristics (always run first - provides context)
  # ═══════════════════════════════════════════════════════════════════════════
  say "Stage 1: Pattern scans & heuristics..."
  run_pattern_scans
  run_structural_checks
  run_doc_drift_checks
  run_empty_file_detection   # AI scaffold detection
  run_broken_path_checks     # Doc path validation
  run_lockfile_checks        # Package manager confusion
  run_test_signals           # Test infrastructure analysis
  run_agentic_mess_detection # Cleanup stray AI work artifacts
  run_docs_quality_check     # README/ARCH completeness
  run_api_docs_check         # Swagger/OpenAPI coverage
  run_code_docs_check        # JSDoc/docstrings
  run_ci_quality_check       # CI/CD hygiene
  run_test_quality_deep      # Test reality checks
  run_credential_deep_scan   # Credential leak deep scan
  run_todo_aging

  # ═══════════════════════════════════════════════════════════════════════════
  # Stages 2-7: Tool Analysis (can run in parallel for --deep mode)
  # ═══════════════════════════════════════════════════════════════════════════
  if [[ "$MODE" == "deep" ]] && [[ "$SLOP_USE_PARALLEL" == "1" ]] && need_cmd parallel; then
    say "Running tool stages in parallel (jobs=$SLOP_JOBS)..."
    
    # Export functions for parallel execution
    export -f run_slopsquatting_check run_biome run_ruff run_knip run_vulture \
              run_semgrep run_bandit run_gitleaks run_depcruise run_osv_scanner \
              run_actionlint run_git_sizer run_lychee run_typos \
              emit_issue say warn tool need_cmd repo_root is_git_repo has_files 2>/dev/null || true
    export ISSUES_JSONL WORKDIR MODE VERSION SLOP_ENABLE_BIOME SLOP_ENABLE_RUFF \
           SLOP_ENABLE_KNIP SLOP_ENABLE_SEMGREP SLOP_ENABLE_BANDIT SLOP_ENABLE_VULTURE \
           SLOP_ENABLE_DEPCRUISE SLOP_ENABLE_GITLEAKS SLOP_ENABLE_OSV SLOP_ENABLE_ACTIONLINT \
           SLOP_ENABLE_GITSIZER SLOP_ENABLE_LYCHEE SLOP_ENABLE_TYPOS SLOP_ENABLE_SLOPSQUATTING
    export GREEN YELLOW RED CYAN PURPLE WHITE NC
    
    # Run independent tools in parallel
    printf '%s\n' \
      run_slopsquatting_check \
      run_biome \
      run_ruff \
      run_knip \
      run_vulture \
      run_semgrep \
      run_bandit \
      run_gitleaks \
      run_depcruise \
      run_osv_scanner \
      run_actionlint \
      run_git_sizer \
      run_lychee \
      run_typos \
    | parallel -j "$SLOP_JOBS" --halt never '{}' 2>/dev/null || {
      # Fallback to sequential if parallel fails
      warn "Parallel execution failed, falling back to sequential"
      run_slopsquatting_check
      run_biome; run_ruff
      run_knip; run_vulture
      run_semgrep; run_bandit; run_gitleaks
      run_depcruise; run_osv_scanner
      run_actionlint; run_git_sizer; run_lychee; run_typos
    }
  else
    # Sequential execution (default for fast mode or when parallel unavailable)
    
    # Stage 2: Slopsquatting Defense (supply chain)
    say "Stage 2: Supply chain analysis..."
    run_slopsquatting_check

    # Stage 3: Fast Linters (Biome, Ruff)
    say "Stage 3: Fast linters..."
    run_biome
    run_ruff

    # Stage 4: Dead Code Detection (Knip, Vulture)
    say "Stage 4: Dead code detection..."
    run_knip
    run_vulture

    # Stage 5: Security Scanning (Semgrep, Bandit, Gitleaks)
    say "Stage 5: Security scanning..."
    run_semgrep
    run_bandit
    run_gitleaks

    # Stage 6: Dependency Analysis (dependency-cruiser, OSV)
    say "Stage 6: Dependency analysis..."
    run_depcruise
    run_osv_scanner

    # Stage 7: Code Quality (actionlint, git-sizer, lychee, typos)
    say "Stage 7: Code quality..."
    run_actionlint
    run_git_sizer
    run_lychee
    run_typos
  fi

  # ═══════════════════════════════════════════════════════════════════════════
  # Stage 8: LLM Analysis (Claude, Gemini) - runs last for full context
  # ═══════════════════════════════════════════════════════════════════════════
  say "Stage 8: LLM analysis..."
  
  # In deep mode, run parallel analysis agents across repo chunks first
  if [[ "$MODE" == "deep" ]] && [[ -n "$CLAUDE_AUTH_METHOD" ]]; then
    say "  Running parallel analysis agents for deep scan..."
    run_parallel_analysis_agents
  fi
  
  run_claude_analysis
  run_gemini_analysis

  # ═══════════════════════════════════════════════════════════════════════════
  # DEDUPLICATION & ISSUE AGGREGATION
  # ═══════════════════════════════════════════════════════════════════════════
  say "Deduplicating issues..."
  python3 - "$ISSUES_JSONL" <<'PYTHON'
import sys, json
from collections import defaultdict

issues_path = sys.argv[1]

# Read all issues
issues = []
with open(issues_path, 'r', errors='ignore') as f:
    for line in f:
        try:
            issues.append(json.loads(line.strip()))
        except:
            pass

# Deduplicate by (file, line, title) - keep highest severity/confidence
seen = {}
sev_order = {"blocker": 0, "high": 1, "medium": 2, "low": 3}

for issue in issues:
    key = (
        issue.get('file', ''),
        issue.get('line', 0),
        issue.get('title', '')[:50]  # Truncate title for matching
    )
    
    if key in seen:
        existing = seen[key]
        # Keep if higher severity or same severity with higher confidence
        existing_sev = sev_order.get(existing.get('severity', 'medium'), 2)
        new_sev = sev_order.get(issue.get('severity', 'medium'), 2)
        
        if new_sev < existing_sev:
            seen[key] = issue
        elif new_sev == existing_sev:
            if float(issue.get('confidence', 0.5)) > float(existing.get('confidence', 0.5)):
                seen[key] = issue
    else:
        seen[key] = issue

# Write deduplicated issues
deduped = list(seen.values())
deduped.sort(key=lambda x: (
    sev_order.get(x.get('severity', 'medium'), 2),
    -float(x.get('confidence', 0.5))
))

with open(issues_path, 'w') as f:
    for issue in deduped:
        f.write(json.dumps(issue) + '\n')

print(f"Deduplicated: {len(issues)} -> {len(deduped)} issues")
PYTHON

  # Truncate if too many issues
  local count
  count=$(wc -l < "$ISSUES_JSONL")
  if [[ "$count" -gt "$SLOP_MAX_TOTAL_ISSUES" ]]; then
    warn "Issues exceed cap ($count > $SLOP_MAX_TOTAL_ISSUES), truncating"
    head -n "$SLOP_MAX_TOTAL_ISSUES" "$ISSUES_JSONL" > "$WORKDIR/issues_trunc.jsonl"
    mv "$WORKDIR/issues_trunc.jsonl" "$ISSUES_JSONL"
    count=$SLOP_MAX_TOTAL_ISSUES
  fi

  # Report
  generate_report "$root" "$out_md"

  # Plan
  local plan_dir=""
  if [[ "$SLOP_ENABLE_PLAN" == "1" ]]; then
    plan_dir=$(generate_plan)
  fi

  # Dossier and Attestation (certify mode only)
  if [[ "$SLOP_CERTIFY_MODE" == "1" ]]; then
    generate_dossier
    generate_attestation
  fi

  local dur=$((SECONDS - start))
  local blockers
  blockers=$(grep -c '"severity":"blocker"' "$ISSUES_JSONL" 2>/dev/null || echo 0)

  echo ""
  echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════${NC}"
  say "Completed in ${dur}s"
  say "Issues found: $count"
  say "Blockers: $blockers"
  say "Report: $out_md"
  [[ -n "$plan_dir" ]] && plan "Plan: $plan_dir"
  
  if [[ "$SLOP_CERTIFY_MODE" == "1" ]]; then
    echo ""
    if [[ "$blockers" -eq 0 ]]; then
      echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
      echo -e "${GREEN}║                    ✓ CERTIFIED FOR RELEASE                                ║${NC}"
      echo -e "${GREEN}║     All checks passed. This code can ship.                                ║${NC}"
      echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    else
      echo -e "${RED}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
      echo -e "${RED}║                    ✗ NOT CERTIFIED                                        ║${NC}"
      echo -e "${RED}║     $blockers blocker(s) must be resolved before release.                     ║${NC}"
      echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    fi
  fi
  
  echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════${NC}"
  echo ""

  # Exit code based on blockers
  [[ "$blockers" -eq 0 ]] || exit 1
}

main "$@"
