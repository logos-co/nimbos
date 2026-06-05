#!/usr/bin/env bash
# nimbos Nim style check — PostToolUse hook for Write/Edit.
#
# Reads the hook JSON from stdin, extracts the modified file path, and runs
# grep-based checks for common style violations from
# `~/.claude/projects/<sanitized-cwd>/memory/feedback_nimbos_code_style.md`.
#
# Always exits 0 (violations are reminders, not hard failures). Output goes
# to stderr so it surfaces in the tool result the model sees.

set -u

PROJECT_ROOT="/Users/rahul/Work/repos/logos-chain/nimbos"

file=$(jq -r '.tool_input.file_path // empty' 2>/dev/null || echo "")

# Only inspect .nim files inside this project
[[ "$file" == "$PROJECT_ROOT"/*.nim ]] || exit 0
[[ -r "$file" ]] || exit 0

emit() {
  local label="$1"; shift
  local matches="$*"
  [[ -z "$matches" ]] && return
  echo "" >&2
  echo "  [$label]" >&2
  echo "$matches" | sed 's/^/    /' >&2
}

rust_refs=$(grep -nE '^[[:space:]]*##.*([Mm]irrors? Rust|Rust:|cryptarchia/mod\.rs|ledger/src/|mantle/ops/|core/src/)' "$file" 2>/dev/null || true)
# Banner detection: a comment line containing the box-drawing char `─` is
# almost certainly a section banner — that character isn't used in regular
# prose comments.
banners=$(grep -n '^[[:space:]]*#.*─' "$file" 2>/dev/null || true)
var_seqs=$(grep -nE '^[[:space:]]*var[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*:[[:space:]]*seq\[' "$file" 2>/dev/null || true)

consec=$(awk '
  BEGIN { pkw=""; pind=""; pln=0 }
  /^[[:space:]]*(let|var)[[:space:]]/ {
    s = $0; sub(/[^[:space:]].*$/, "", s); ind = s
    rest = $0; sub(/^[[:space:]]+/, "", rest); kw = substr(rest, 1, 3)
    if (kw == pkw && ind == pind && NR == pln + 1) {
      print pln":"$0
    }
    pkw = kw; pind = ind; pln = NR
    next
  }
  { pkw = ""; pind = ""; pln = 0 }
' "$file" 2>/dev/null || true)

two_step=$(awk '
  BEGIN { window=4 }
  {
    for (n in seen) { if (NR - seen[n] > window) delete seen[n] }

    if (match($0, /^[[:space:]]*let[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=/)) {
      line = substr($0, RSTART, RLENGTH)
      sub(/^[[:space:]]*let[[:space:]]+/, "", line)
      sub(/[[:space:]]*=.*$/, "", line)
      seen[line] = NR
    }

    if (match($0, /if[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*\.isErr/)) {
      part = substr($0, RSTART, RLENGTH)
      sub(/^if[[:space:]]+/, "", part)
      sub(/\.isErr.*$/, "", part)
      if (part in seen) {
        print seen[part]"-"NR": "part" (use valueOr: instead)"
      }
    }
  }
' "$file" 2>/dev/null || true)

if [[ -z "$rust_refs$banners$var_seqs$consec$two_step" ]]; then
  exit 0
fi

echo "" >&2
echo "── nimbos style check: $(basename "$file") ──" >&2
emit "Rust ref in ## doc-comment (drop the Rust mention)" "$rust_refs"
emit "Section banner comment (style guide forbids)" "$banners"
emit "var X: seq[T] — preallocate via newSeqOfCap if loop bound is known" "$var_seqs"
emit "Consecutive let/var — merge into a let:/var: block" "$consec"
emit "Two-step let-isErr-get — use valueOr: block instead" "$two_step"
echo "── see memory/feedback_nimbos_code_style.md ──" >&2

exit 0
