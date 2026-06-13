#!/usr/bin/env bash
# verify-runtime-scope.sh - OPT-IN: the HONEST edges of the Tetragon shell-kill (M8).
# Linux/macOS twin of verify-runtime-scope.ps1 (same probes; logic validated via the .ps1 on
# the Windows host). Measures the kill's SCOPE so the control is neither over- nor under-claimed:
#   Station A  selective in-kernel kill   (sh rc=137, id rc=0)
#   Station D  match-scope is execve-of-shell  (a non-shell exec AND a file read survive)
# Stations B/C are documented (not asserted) - see notes + labs/m8/README.md. Does NOT change
# ED1 (still VERIFIED) and does NOT touch the always-on verify.sh 21/21 suite.
set -u
CTX=kind-cloudsec; NS=shop; fail=0
DBPOD=$(kubectl --context "$CTX" -n "$NS" get pod -l tier=data -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -z "$DBPOD" ] && { echo "SKIP: no tier=data pod in $NS (run scripts/up.sh first)"; exit 0; }

probe() {  # label expect cmd...
  local label="$1" expect="$2"; shift 2
  kubectl --context "$CTX" -n "$NS" exec "$DBPOD" -- "$@" >/dev/null 2>&1; local rc=$?
  if [ "$rc" -eq "$expect" ]; then echo "  ${label} rc=${rc} expect ${expect} PASS"
  else echo "  ${label} rc=${rc} expect ${expect} FAIL"; fail=1; fi
}

echo "== Tetragon shell-kill SCOPE (detection != prevention; ED1 unchanged) =="
echo "-- Station A: selective in-kernel kill --"
probe "id (non-shell binary) survives        " 0   id
probe "sh -c (shell execve) SIGKILLed         " 137 sh -c 'echo x'
echo "-- Station D: match-scope is execve-of-shell-names only --"
probe "cat /etc/passwd (file read) survives   " 0   cat /etc/passwd
echo "----------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
  echo "PASS: kill is selective + scope-limited to execve-of-[/sh,/bash,/dash,/ash,/busybox]."
else echo "FAIL above."; fi

cat <<'NOTE'

HONEST NOTES (documented, not asserted here - see labs/m8/README.md + THREAT_MODEL.md):
  SCOPE/bypass: the rule matches execve arg0 by shell-name postfix - it is NOT a robust
    shell-block. Bypassable via renamed binary (cp /bin/busybox /tmp/x && /tmp/x sh -> arg0
    unmatched), execveat (unhooked syscall), and fd-exec. ED1 = "naive direct shell-named
    execve is killed", NOT "a shell cannot run". Robust fix: matchBinaries / sched_process_exec /
    LSM security_bprm_creds_for_exec, or a data-tier exec allowlist.
  B (execve timing, DOCUMENTED not measured here): execve+Sigkill is pre-image-load. The pod
    HAS writable emptyDirs at /tmp etc.; the moot-ness is the timing, not lack of writable paths.
  C (I/O window): a write()+Sigkill rule kills the process but the kernel may already have done
    the I/O (synchronous-process-kill != pre-operation); prevention-grade needs Sigkill+Override.
    SKIP-prone on kind (tetragon#4883); see labs/m8/tracingpolicy-write-window.yaml.
  io_uring: a non-execve I/O path is invisible to Tetragon's DEFAULT syscall policies (ARMO
    "Curing" 2025); LSM/KRSI hooks would see it. The shipped execve rule is unaffected.
NOTE
exit "$fail"
