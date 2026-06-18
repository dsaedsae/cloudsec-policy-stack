#!/usr/bin/env bash
# verify-runtime-scope.sh - OPT-IN (M8): measure the DELTA between the selective shell-kill
# (M4's naive primitive) and the ZERO-EXEC rule that is the SHIPPED default. It applies each
# rule to the live db pod, probes, and RESTORES the shipped zero-exec on exit. Linux/macOS twin
# of verify-runtime-scope.ps1 (same probes).
#   Phase 1  selective (M4)   -> a non-shell exec (id) SURVIVES, a shell exec dies (137)
#   Phase 2  zero-exec (ship) -> id ALSO dies (137): the name-independent gap is closed
# The renamed/execveat/fd-exec bypasses that defeat the selective rule are documented below -
# they are WHY shipped = zero-exec (ADR 0001). Does NOT change ED1 (VERIFIED) or the 80% metric.
# NOTE: this temporarily swaps the data-tier TracingPolicy on the running db; the trap restores
# the shipped zero-exec. Run it standalone (not alongside verify.sh).
set -u
CTX=kind-cloudsec; NS=shop; fail=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEL="$ROOT/labs/m4/tracingpolicy.solution.yaml"   # selective shell-kill (M4 primitive)
ZERO="$ROOT/k8s/tracingpolicy.yaml"               # zero-exec (shipped default)
SEL_NAME=block-shell-in-data-tier; ZERO_NAME=data-tier-no-exec
DBPOD=$(kubectl --context "$CTX" -n "$NS" get pod -l tier=data -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[ -z "$DBPOD" ] && { echo "SKIP: no tier=data pod in $NS (run scripts/up.sh first)"; exit 0; }

restore() {  # final state = shipped zero-exec only (selective removed)
  kubectl --context "$CTX" delete tracingpolicy "$SEL_NAME" >/dev/null 2>&1 || true
  kubectl --context "$CTX" apply -f "$ZERO" >/dev/null 2>&1
  echo "(restored shipped zero-exec: k8s/tracingpolicy.yaml; selective rule removed)"
}
trap restore EXIT

only() {  # apply exactly ONE rule (delete both first, so the two policies never overlap), let eBPF load
  kubectl --context "$CTX" delete tracingpolicy "$SEL_NAME" "$ZERO_NAME" >/dev/null 2>&1 || true
  kubectl --context "$CTX" apply -f "$1" >/dev/null 2>&1
  sleep 6
}

probe() {  # label expect cmd...
  local label="$1" expect="$2"; shift 2
  kubectl --context "$CTX" -n "$NS" exec "$DBPOD" -- "$@" >/dev/null 2>&1; local rc=$?
  if [ "$rc" -eq "$expect" ]; then echo "  ${label} rc=${rc} expect ${expect} PASS"
  else echo "  ${label} rc=${rc} expect ${expect} FAIL"; fail=1; fi
}

echo "== M8: selective (M4 primitive) vs zero-exec (shipped) - measure the DELTA =="
echo "-- Phase 1: SELECTIVE rule (M4 naive cut) - apply + measure --"
only "$SEL"
probe "id (non-shell binary) SURVIVES     " 0   id
probe "sh -c (shell execve) SIGKILLed      " 137 sh -c 'echo x'
probe "cat /etc/passwd (file read) survives" 0   cat /etc/passwd
echo "   -> selective: only shell-name execve dies; id + file-read live (this is the GAP)."
echo "-- Phase 2: ZERO-EXEC rule (shipped default) - apply + measure --"
only "$ZERO"
probe "id (non-shell binary) now KILLED    " 137 id
probe "sh -c (shell execve) KILLED          " 137 sh -c 'echo x'
echo "   -> zero-exec: ALL data-tier exec dies, name-independent (closes the renamed/execveat gap)."
echo "----------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
  echo "PASS: selective lets id run (the gap); zero-exec (shipped) closes it - name-independent."
else echo "FAIL above."; fi

cat <<'NOTE'

HONEST NOTES (documented, not asserted here - see labs/m8/README.md + THREAT_MODEL.md + ADR 0001):
  WHY zero-exec is shipped: the selective rule matches execve arg0 by shell-name postfix - it is
    NOT a robust shell-block. Bypassable via renamed binary (cp /bin/busybox /tmp/x && /tmp/x sh ->
    arg0 unmatched), execveat (a separate, unhooked syscall), and fd-exec. matchBinaries is the
    WRONG fix (it matches the CALLER, not the launched image). Since the data tier runs only its
    main process (db probes are httpGet, not exec), the shipped default forbids ALL exec - name-
    independent, covers execveat. The selective primitive + "over-blocking is a defect" lesson live
    on in the M4 lab; this script shows why M8/ADR 0001 promoted zero-exec to the default.
  B (execve timing, DOCUMENTED not measured here): execve+Sigkill is pre-image-load. The pod HAS
    writable emptyDirs at /tmp etc.; the moot-ness is the timing, not lack of writable paths.
  C (I/O window): a write()+Sigkill rule kills the process but the kernel may already have done the
    I/O (synchronous-process-kill != pre-operation); prevention-grade needs Sigkill+Override.
    SKIP-prone on kind (tetragon#4883); see labs/m8/tracingpolicy-write-window.yaml.
  io_uring: a non-execve I/O path is invisible to Tetragon's DEFAULT syscall policies (ARMO
    "Curing" 2025); LSM/KRSI hooks would see it. The execve-based rules here are unaffected.
NOTE
exit "$fail"
