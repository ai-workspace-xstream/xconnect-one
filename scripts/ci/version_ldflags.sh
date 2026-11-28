#!/usr/bin/env bash
# Resolves ldflags for cmd/xconnect so release binaries report the tag version,
# CI build number, and git commit rather than static fallback constants.
resolve_xconnect_ldflags() {
  local fallback_ver="${1:-}"
  local ver="${XCONNECT_VERSION:-}"
  if [ -z "$ver" ] && [ -n "$fallback_ver" ] && [ "$fallback_ver" != "0.1.0" ]; then
    ver="v${fallback_ver#v}"
  fi
  if [ -z "$ver" ]; then
    ver="$(git describe --tags --exact-match 2>/dev/null || git describe --tags --abbrev=0 2>/dev/null || echo dev)"
  fi
  local build_num="${XCONNECT_BUILD_NUMBER:-${GITHUB_RUN_NUMBER:-0}}"
  local commit="${XCONNECT_GIT_COMMIT:-$(git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)}"
  commit="${commit:0:7}"
  printf '%s' "-s -w -X main.version=${ver} -X main.buildNumber=${build_num} -X main.gitCommit=${commit}"
}
