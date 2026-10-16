#!/usr/bin/env bash
# Build the engine and service wheels reproducibly from one commit, and check them.
#
# Usage: scripts/build_wheels.sh COMMIT OUT_DIR
#
# The wheels are built twice, each time from a fresh worktree of COMMIT at a
# different path, with SOURCE_DATE_EPOCH set to the commit time and the build
# backend pinned by hash in build-constraints.txt. The script fails unless both
# builds are byte-identical and both wheels pass scripts/verify_wheel.py. The
# wheels in OUT_DIR are copied and hashed before any of their code runs; a
# separate copy is then installed, with hash-locked dependencies, into a clean
# virtual environment where `ship-no-ship --help` must run, and OUT_DIR is
# hashed again afterwards. Uncommitted changes never reach the wheels.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 COMMIT OUT_DIR" >&2
  exit 2
fi

root=$(git rev-parse --show-toplevel)
commit=$(git -C "$root" rev-parse --verify "$1^{commit}")
out=$2
work=$(mktemp -d)

cleanup() {
  for tree in "$work"/src-*; do
    [ -d "$tree" ] && git -C "$root" worktree remove --force "$tree" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

sums() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$@"
  else
    shasum -a 256 -- "$@"
  fi
}

python=(uv run --no-project --quiet python)
version=$(git -C "$root" show "$commit:packages/engine/pyproject.toml" |
  "${python[@]}" -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["project"]["version"])')
SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct "$commit")
export SOURCE_DATE_EPOCH
engine="ship_no_ship-$version-py3-none-any.whl"
service="ship_no_ship_service-$version-py3-none-any.whl"
echo "Building $version from $commit with SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

for run in a b; do
  git -C "$root" worktree add --detach --quiet "$work/src-$run" "$commit"
  (
    cd "$work/src-$run"
    uv build --all-packages --wheel --no-cache \
      --build-constraints build-constraints.txt --require-hashes \
      --out-dir "$work/dist-$run"
  )
  (cd "$work/dist-$run" && ls) >"$work/names-$run"
  printf '%s\n' "$engine" "$service" | sort >"$work/expected-names"
  if ! diff -u "$work/expected-names" "$work/names-$run"; then
    echo "build $run did not produce exactly the expected wheels" >&2
    exit 1
  fi
  (cd "$work/dist-$run" && sums "$engine" "$service") >"$work/sums-$run"
done

if ! diff -u "$work/sums-a" "$work/sums-b"; then
  echo "the two builds differ: the wheels are not reproducible" >&2
  exit 1
fi
echo "Both builds are byte-identical:"
cat "$work/sums-a"

# Keep and hash the release copies before anything from the build runs.
mkdir -p "$out"
cp "$work/dist-a/$engine" "$work/dist-a/$service" "$out/"
(cd "$out" && sums "$engine" "$service") >"$work/release-sums"
sha() { awk -v f="$1" '$2 == f { print $1 }' "$work/release-sums"; }

src="$work/src-a"
"${python[@]}" "$root/scripts/verify_wheel.py" "$out/$engine" --sha256 "$(sha "$engine")" --version "$version" \
  --package ship_no_ship --console-script 'ship-no-ship=ship_no_ship.engine.cli:main' \
  --requires-dist-from "$src/packages/engine/pyproject.toml"
"${python[@]}" "$root/scripts/verify_wheel.py" "$out/$service" --sha256 "$(sha "$service")" --version "$version" \
  --package ship_no_ship_service --requires-dist-from "$src/packages/service/pyproject.toml"

# Smoke-test separate copies. Third-party dependencies come from the commit's
# uv.lock and must match its hashes; the wheels install without an index.
mkdir "$work/smoke-wheels"
cp "$out/$engine" "$out/$service" "$work/smoke-wheels/"
(cd "$src" && uv export --all-packages --no-dev --no-emit-workspace --locked --no-header --quiet \
  --output-file "$work/smoke-requirements.txt")
(
  cd "$work"
  uv venv --quiet smoke
  uv pip install --quiet --python smoke/bin/python --require-hashes -r smoke-requirements.txt
  uv pip install --quiet --python smoke/bin/python --no-deps --no-index \
    "smoke-wheels/$engine" "smoke-wheels/$service"
  smoke/bin/ship-no-ship --help >/dev/null
  smoke/bin/python - "$version" <<'EOF'
import importlib.metadata
import sys

import ship_no_ship_service  # noqa: F401

for name in ("ship-no-ship", "ship-no-ship-service"):
    assert importlib.metadata.version(name) == sys.argv[1], name
EOF
)
echo "The wheels install together and ship-no-ship --help runs."

if ! (cd "$out" && sums "$engine" "$service") | diff -u "$work/release-sums" -; then
  echo "the release wheels changed during the smoke test" >&2
  exit 1
fi
echo "Release wheels:"
cat "$work/release-sums"
