#!/usr/bin/env bash
#
# upgrade-deps.sh - bring this repo's dependencies and toolchain up to date.
#
# The site is dormant and Renovate already lands in-range bumps and lockfile
# refreshes on its own. This script covers what Renovate can't do unattended:
#
#   * major-version jumps (Docusaurus 3 -> 4, React 19 -> 20, ...)
#   * the Node pin, which is duplicated across package.json, .node-version
#     and both workflows
#   * proving the site still builds - docusaurus.config.js sets
#     onBrokenLinks: "throw", so a dependency bump really can break the build
#   * proving `yarn check-format` still passes, which is the PR gate
#
# It never commits, pushes, or opens a PR. It leaves reviewable changes in the
# working tree and prints the suggested next steps.
#
# Note on approach: we rewrite the package.json ranges ourselves from the
# registry rather than leaning on `yarn upgrade --latest`. Yarn 1 only rewrites
# a declared range when the *resolved* version changes, so a range like
# "^3.8.0" is left untouched when 3.9.6 already satisfies it - the manifest
# silently stays stale. Pinning each range to the newest version also matches
# the `rangeStrategy: "bump"` that renovate.json already uses.
#
set -euo pipefail

# ---------------------------------------------------------------- options ----

DRY_RUN=0
IN_RANGE=0
NODE_SPEC="lts"
SKIP_NODE=0
SKIP_BUILD=0
RUN_FORMAT=0
ALLOW_DIRTY=0

usage() {
  # Print the header comment block (line 3 through the first non-comment line).
  awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"
  cat <<'USAGE'
Usage: scripts/upgrade-deps.sh [options]

  --dry-run       Report what would change; write nothing.
  --in-range      Hold anything that needs a major jump; take the rest.
  --node <spec>   Node target: "lts" (default), "latest", or an explicit
                  version such as 26.8.1.
  --skip-node     Leave the Node pins alone.
  --skip-build    Skip `yarn build`. Faster, but you lose the real gate.
  --format        Run `yarn format` if the Prettier check fails.
  --allow-dirty   Don't require a clean working tree.
  -h, --help      Show this help.

Typical use, a few times a year:

  scripts/upgrade-deps.sh --dry-run     # see what's out there
  scripts/upgrade-deps.sh --format      # do it, absorb formatting churn
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --in-range) IN_RANGE=1 ;;
    --node) shift; [ $# -gt 0 ] || { echo "--node needs a value" >&2; exit 2; }; NODE_SPEC="$1" ;;
    --skip-node) SKIP_NODE=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --format) RUN_FORMAT=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; echo "try --help" >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------- output -----

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$(printf '\033[1m'); R=$(printf '\033[31m'); G=$(printf '\033[32m')
  Y=$(printf '\033[33m'); Z=$(printf '\033[0m')
else
  B=""; R=""; G=""; Y=""; Z=""
fi

step() { printf '\n%s==> %s%s\n' "$B" "$1" "$Z"; }
info() { printf '    %s\n' "$1"; }
ok()   { printf '    %s%s%s\n' "$G" "$1" "$Z"; }
warn() { printf '    %s%s%s\n' "$Y" "$1" "$Z"; }
die()  { printf '\n%serror:%s %s\n' "$R" "$Z" "$1" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TAB=$(printf '\t')

# ---------------------------------------------------------------- helpers ----

# Exit 0 if $1 < $2, comparing dotted numeric versions.
version_lt() {
  node -e '
    const a = process.argv[1].split(".").map(Number);
    const b = process.argv[2].split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      const x = a[i] || 0, y = b[i] || 0;
      if (x < y) process.exit(0);
      if (x > y) process.exit(1);
    }
    process.exit(1);
  ' "$1" "$2"
}

# Portable in-place sed (BSD and GNU disagree about -i).
sed_inplace() {
  local expr="$1" file="$2" tmp
  tmp="$WORK/sed.tmp"
  sed -e "$expr" "$file" >"$tmp"
  mv "$tmp" "$file"
}

# "dependencies<TAB>name<TAB>range" for every direct dependency.
list_deps() {
  node -e '
    const pkg = require("./package.json");
    for (const field of ["dependencies", "devDependencies"]) {
      for (const name of Object.keys(pkg[field] || {}).sort()) {
        console.log([field, name, pkg[field][name]].join("\t"));
      }
    }
  '
}

# "^3.10.2" -> "3";  ">=24.20.0" -> "24"
major_of() { printf '%s' "$1" | sed -e 's/^[^0-9]*//' -e 's/[.].*$//'; }
# "^3.10.2" -> "^";  ">=24.20.0" -> ">=";  "3.10.2" -> ""
prefix_of() { printf '%s' "$1" | sed -e 's/[0-9].*$//'; }
# "^3.10.2" -> "3.10.2"
bare_of() { printf '%s' "$1" | sed -e 's/^[^0-9]*//'; }

json_field() {
  node -e '
    const pkg = require("./package.json");
    const v = process.argv[1].split(".").reduce((o, k) => (o || {})[k], pkg);
    process.stdout.write(v == null ? "" : String(v));
  ' "$1"
}

# ---------------------------------------------------------------- preflight --

step "Preflight"

for tool in git node yarn npm curl awk; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found"
done

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || die "not inside a git repository"
cd "$ROOT"

[ -f package.json ] || die "no package.json at repo root ($ROOT)"
[ -f docusaurus.config.js ] || die "no docusaurus.config.js - is this the pixee/docs repo?"

YARN_VERSION=$(yarn --version)
case "$YARN_VERSION" in
  1.*) ;;
  *) die "expected Yarn 1.x (the repo has a v1 yarn.lock), found $YARN_VERSION" ;;
esac
info "yarn $YARN_VERSION, node $(node --version)"

if [ "$ALLOW_DIRTY" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ -n "$(git status --porcelain)" ]; then
  die "working tree is dirty. Commit or stash first, or pass --allow-dirty.
       This run rewrites package.json, yarn.lock and the workflows, and you
       want those changes reviewable on their own."
fi

npm ping >/dev/null 2>&1 || die "cannot reach the npm registry - check your network or proxy"
ok "registry reachable"

# ---------------------------------------------------------------- node pin ---

NODE_CURRENT=$(bare_of "$(json_field engines.node)")
NODE_TARGET=""
[ -n "$NODE_CURRENT" ] || die "could not read engines.node from package.json"

step "Node pin"
if [ "$SKIP_NODE" -eq 1 ]; then
  info "skipped (--skip-node); staying on $NODE_CURRENT"
else
  NODE_RESOLVED=$(
    curl -fsS https://nodejs.org/dist/index.json | node -e '
      let raw = "";
      process.stdin.on("data", c => (raw += c)).on("end", () => {
        const releases = JSON.parse(raw);
        const spec = process.argv[1];
        let pick;
        if (spec === "latest") {
          pick = releases[0];
        } else if (spec === "lts") {
          pick = releases.find(r => r.lts);
        } else {
          pick = releases.find(r => r.version === "v" + spec.replace(/^v/, ""));
        }
        if (!pick) {
          console.error("cannot resolve Node spec: " + spec);
          process.exit(1);
        }
        process.stdout.write(pick.version.replace(/^v/, "") + "\t" + (pick.lts || "current"));
      });
    ' "$NODE_SPEC"
  ) || die "failed to resolve a Node version for --node $NODE_SPEC"

  NODE_TARGET=$(printf '%s' "$NODE_RESOLVED" | cut -f1)
  NODE_LINE=$(printf '%s' "$NODE_RESOLVED" | cut -f2)

  if [ "$NODE_TARGET" = "$NODE_CURRENT" ]; then
    ok "already on $NODE_CURRENT (Node $NODE_LINE)"
  else
    info "$NODE_CURRENT -> ${B}${NODE_TARGET}${Z} (Node $NODE_LINE)"
    if [ "$(major_of "$NODE_CURRENT")" != "$(major_of "$NODE_TARGET")" ]; then
      warn "this crosses a Node major line - read the release notes"
    fi
    if [ "$NODE_LINE" = "current" ]; then
      warn "$NODE_TARGET is not an LTS release; running CI on a non-LTS line is a choice, not a default"
    fi
    if [ "$DRY_RUN" -eq 0 ]; then
      sed_inplace "s/\(\"node\":[[:space:]]*\">=\)[0-9][0-9.]*\"/\1${NODE_TARGET}\"/" package.json
      PINNED="package.json"
      # .node-version drives fnm/nvm auto-switching for anyone working locally.
      if [ -f .node-version ]; then
        printf '%s\n' "$NODE_TARGET" >.node-version
        PINNED="$PINNED, .node-version"
      fi
      for wf in .github/workflows/*.yml; do
        [ -f "$wf" ] || continue
        grep -q 'node-version:' "$wf" || continue
        sed_inplace "s/\(node-version:[[:space:]]*\)[0-9][0-9.]*/\1${NODE_TARGET}/" "$wf"
        PINNED="$PINNED, $(basename "$wf")"
      done
      ok "pinned $PINNED"
    fi
  fi
fi

# Catch drift between the places the version lives, even when no bump is due -
# e.g. .node-version left behind by a hand-edit of engines.
if [ -f .node-version ] && [ "$DRY_RUN" -eq 0 ]; then
  NODE_FILE_VERSION=$(tr -d ' \t\n' <.node-version)
  NODE_EXPECTED=${NODE_TARGET:-$NODE_CURRENT}
  if [ "$NODE_FILE_VERSION" != "$NODE_EXPECTED" ]; then
    printf '%s\n' "$NODE_EXPECTED" >.node-version
    warn ".node-version said $NODE_FILE_VERSION; corrected to $NODE_EXPECTED"
  fi
fi

# We are about to build with the *local* Node, whatever the pin now says.
# Yarn 1 enforces engines on `yarn run` too, not just install, so a mismatch
# would otherwise fail every verification step with a confusing error.
NODE_LOCAL=$(node --version | sed 's/^v//')
NODE_FLOOR=${NODE_TARGET:-$NODE_CURRENT}
IGNORE_ENGINES=""
ENGINE_MISMATCH=0
if version_lt "$NODE_LOCAL" "$NODE_FLOOR"; then
  ENGINE_MISMATCH=1
  IGNORE_ENGINES="--ignore-engines"
  warn "local Node is $NODE_LOCAL but the repo requires >=$NODE_FLOOR."
  warn "Continuing with --ignore-engines, but the verification below will NOT"
  warn "match CI. Install Node $NODE_FLOOR for a trustworthy result."
fi

# ---------------------------------------------------------------- plan -------

step "Querying the registry"

list_deps >"$WORK/before.tsv"
: >"$WORK/plan.tsv"

DEP_COUNT=$(wc -l <"$WORK/before.tsv" | tr -d ' ')
info "$DEP_COUNT direct dependencies"

while IFS="$TAB" read -r field name range; do
  [ -n "$name" ] || continue
  latest=$(npm view "$name" version 2>/dev/null | tail -1 || true)
  current=$(bare_of "$range")
  prefix=$(prefix_of "$range")

  if [ -z "$latest" ]; then
    status="unknown"; target="$range"
  elif [ "$current" = "$latest" ]; then
    status="current"; target="$range"
  elif [ "$(major_of "$range")" != "$(major_of "$latest")" ]; then
    if [ "$IN_RANGE" -eq 1 ]; then
      status="held"; target="$range"
    else
      status="major"; target="${prefix}${latest}"
    fi
  else
    status="minor"; target="${prefix}${latest}"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$field" "$name" "$range" "$latest" "$target" "$status" \
    >>"$WORK/plan.tsv"
done <"$WORK/before.tsv"

MINORS=$(grep -c "${TAB}minor$" "$WORK/plan.tsv" || true)
MAJORS=$(grep -c "${TAB}major$" "$WORK/plan.tsv" || true)
HELD=$(grep -c "${TAB}held$" "$WORK/plan.tsv" || true)
UNKNOWN=$(grep -c "${TAB}unknown$" "$WORK/plan.tsv" || true)
PLANNED=$((MINORS + MAJORS))

step "Plan"
if [ "$PLANNED" -eq 0 ] && [ "$HELD" -eq 0 ] && [ "$UNKNOWN" -eq 0 ]; then
  ok "every direct dependency is already at its latest version"
else
  while IFS="$TAB" read -r field name range latest target status; do
    case "$status" in
      minor) printf '    %-32s %-12s -> %s%s%s\n' "$name" "$range" "$B" "$target" "$Z" ;;
      major) printf '    %-32s %-12s -> %s%s%s  %sMAJOR%s\n' "$name" "$range" "$B" "$target" "$Z" "$Y" "$Z" ;;
      held)  printf '    %-32s %-12s    %sheld at major %s (--in-range; latest is %s)%s\n' \
               "$name" "$range" "$Y" "$(major_of "$range")" "$latest" "$Z" ;;
      unknown) printf '    %-32s %-12s    %scould not query the registry%s\n' "$name" "$range" "$R" "$Z" ;;
    esac
  done <"$WORK/plan.tsv"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  printf '\n'
  info "would change: $PLANNED ($MAJORS major)"
  [ -n "$NODE_TARGET" ] && [ "$NODE_TARGET" != "$NODE_CURRENT" ] \
    && info "node pin:     $NODE_CURRENT -> $NODE_TARGET"
  step "Dry run complete - nothing written"
  exit 0
fi

# ---------------------------------------------------------------- apply ------

if [ "$PLANNED" -gt 0 ]; then
  step "Rewriting package.json"
  WROTE=$(node -e '
    const fs = require("fs");
    const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
    let n = 0;
    for (const line of fs.readFileSync(process.argv[1], "utf8").split("\n")) {
      if (!line) continue;
      const [field, name, , , target, status] = line.split("\t");
      if (status !== "minor" && status !== "major") continue;
      if (!pkg[field] || pkg[field][name] === undefined) continue;
      pkg[field][name] = target;
      n++;
    }
    fs.writeFileSync("package.json", JSON.stringify(pkg, null, 2) + "\n");
    process.stdout.write(String(n));
  ' "$WORK/plan.tsv") || die "failed to rewrite package.json"
  ok "updated $WROTE range(s)"
else
  step "Rewriting package.json"
  info "nothing to change"
fi

step "Resolving the lockfile"
info "yarn install"
yarn install $IGNORE_ENGINES >"$WORK/install.log" 2>&1 \
  || { tail -40 "$WORK/install.log"; die "install failed against the new ranges - see output above"; }
ok "yarn.lock resolved"

# ---------------------------------------------------------------- verify -----

step "Verifying (this mirrors CI)"

info "yarn install --frozen-lockfile"
yarn install --frozen-lockfile $IGNORE_ENGINES >"$WORK/frozen.log" 2>&1 \
  || { tail -40 "$WORK/frozen.log"; die "package.json and yarn.lock disagree - see output above"; }
ok "lockfile is in sync"

FORMAT_STATUS="passed"
info "yarn check-format"
if yarn $IGNORE_ENGINES check-format >"$WORK/format.log" 2>&1; then
  ok "prettier check passed"
elif [ "$RUN_FORMAT" -eq 1 ]; then
  warn "prettier check failed - running yarn format"
  yarn $IGNORE_ENGINES format >"$WORK/format-write.log" 2>&1 \
    || { tail -20 "$WORK/format-write.log"; die "yarn format failed - see output above"; }
  FORMAT_COUNT=$(git status --porcelain | grep -cv 'package.json\|yarn.lock\|workflows' || true)
  FORMAT_STATUS="reformatted, ~$FORMAT_COUNT extra file(s) touched"
  warn "$FORMAT_STATUS - keep that in its own commit"
else
  FORMAT_STATUS="FAILING (rerun with --format, or run yarn format)"
  warn "prettier check failed. A Prettier major bump reformats the whole repo;"
  warn "rerun with --format, or run 'yarn format' yourself."
fi

BUILD_STATUS="skipped"
if [ "$SKIP_BUILD" -eq 1 ]; then
  warn "yarn build skipped (--skip-build) - the broken-link gate did not run"
else
  info "yarn build (onBrokenLinks: throw, so this catches real breakage)"
  if yarn $IGNORE_ENGINES build >"$WORK/build.log" 2>&1; then
    BUILD_STATUS="passed"
    ok "build succeeded"
  else
    BUILD_STATUS="FAILED"
    printf '\n'
    tail -60 "$WORK/build.log"
    printf '\n'
    cp "$WORK/build.log" ./upgrade-deps-build.log 2>/dev/null \
      && warn "full log saved to ./upgrade-deps-build.log (delete before committing)"
  fi
fi

# ---------------------------------------------------------------- report -----

step "Summary"

CHANGED=0
while IFS="$TAB" read -r field name range latest target status; do
  case "$status" in
    minor) CHANGED=$((CHANGED + 1)); printf '    %-32s %s -> %s\n' "$name" "$range" "$target" ;;
    major) CHANGED=$((CHANGED + 1)); printf '    %-32s %s -> %s  %sMAJOR%s\n' "$name" "$range" "$target" "$Y" "$Z" ;;
  esac
done <"$WORK/plan.tsv"
[ "$CHANGED" -eq 0 ] && info "no dependency ranges changed"

printf '\n'
info "dependencies:  $CHANGED changed ($MAJORS major)"
[ "$HELD" -gt 0 ] && info "held back:     $HELD (needs a major jump; drop --in-range to take them)"
[ "$UNKNOWN" -gt 0 ] && warn "unqueryable:   $UNKNOWN (registry lookup failed)"
if [ -n "$NODE_TARGET" ] && [ "$NODE_TARGET" != "$NODE_CURRENT" ]; then
  info "node pin:      $NODE_CURRENT -> $NODE_TARGET"
fi
info "build:         $BUILD_STATUS"
info "format:        $FORMAT_STATUS"
[ "$ENGINE_MISMATCH" -eq 1 ] && warn "verified on Node $NODE_LOCAL, but CI uses $NODE_FLOOR"

RESOLUTIONS=$(node -e '
  const r = require("./package.json").resolutions || {};
  console.log(Object.keys(r).map(k => k + "@" + r[k]).join(", "));
')
if [ -n "$RESOLUTIONS" ]; then
  printf '\n'
  warn "package.json still pins resolutions: $RESOLUTIONS"
  warn "Those force patched transitive versions. After a major bump the upstream"
  warn "dependency may already satisfy them - check, and drop what is stale."
fi

if [ "$MAJORS" -gt 0 ]; then
  printf '\n'
  warn "$MAJORS major bump(s) landed. Before merging, at minimum:"
  warn "  * yarn start, and click through the docs locally"
  warn "  * confirm the sidebar still renders (it is autogenerated from docs/)"
  warn "  * confirm the client redirects in docusaurus.config.js still resolve"
fi

step "Next steps"
cat <<'NEXT'
    Review, then commit in pieces so a bisect stays useful:

      git diff --stat
      git switch -c chore/dependency-refresh
      git add package.json yarn.lock .github/workflows
      git commit -m "Upgrade dependencies and Node pin"
      # if --format reformatted content, commit that separately:
      git add -A && git commit -m "Reformat with new Prettier"
      git push -u origin HEAD && gh pr create --fill

    Open a PR rather than pushing to main: a push to main deploys to
    pixee/internal-docs, which is what serves docs.pixee.ai.
NEXT

[ "$BUILD_STATUS" = "FAILED" ] && exit 1
exit 0
