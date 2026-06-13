# verify-runtime-scope.ps1 - OPT-IN: the HONEST edges of the Tetragon shell-kill (M8).
# M4/ED1 proves the shell-exec kill WORKS (sh -> 137, id -> 0). This script measures its
# SCOPE and timing semantics so the control is not over- or under-claimed:
#   Station A  selective in-kernel kill is real           (sh rc=137, id rc=0)
#   Station D  the rule's match-scope is execve-of-shell  (a non-shell exec AND a file read survive)
# Stations B/C are documented (not asserted here) - see notes printed at the end + labs/m8/README.md.
# Does NOT change ED1 (still VERIFIED) and does NOT touch the always-on verify.sh 21/21 suite.
$ErrorActionPreference = "Continue"
$ctx = "kind-cloudsec"; $ns = "shop"; $fail = 0
$DBPOD = kubectl --context $ctx -n $ns get pod -l tier=data -o "jsonpath={.items[0].metadata.name}" 2>$null
if (-not $DBPOD) { Write-Host "SKIP: no tier=data pod in $ns (run scripts\up.ps1 first)"; exit 0 }

function Probe($label, $expect, [scriptblock]$cmd) {
    & $cmd *> $null; $rc = $LASTEXITCODE
    $ok = ($rc -eq $expect)
    if (-not $ok) { $script:fail = 1 }
    Write-Host ("  {0,-52} rc={1,-4} expect {2,-4} {3}" -f $label, $rc, $expect, $(if ($ok) { "PASS" } else { "FAIL" }))
}

Write-Host "== Tetragon shell-kill SCOPE (detection != prevention; ED1 unchanged) =="
Write-Host "-- Station A: selective in-kernel kill --"
Probe "id (non-shell binary) survives"          0   { kubectl --context $ctx -n $ns exec $DBPOD -- id }
Probe "sh -c (shell execve) SIGKILLed"           137 { kubectl --context $ctx -n $ns exec $DBPOD -- sh -c "echo x" }
Write-Host "-- Station D: match-scope is execve-of-shell-names only --"
Probe "cat /etc/passwd (file read) survives"     0   { kubectl --context $ctx -n $ns exec $DBPOD -- cat /etc/passwd }

Write-Host "----------------------------------------------------------------"
if ($fail -eq 0) {
    Write-Host "PASS: kill is selective + scope-limited to execve-of-[/sh,/bash,/dash,/ash,/busybox]."
} else { Write-Host "FAIL above." }
Write-Host ""
Write-Host "HONEST NOTES (documented, not asserted here - see labs/m8/README.md + THREAT_MODEL.md):"
Write-Host "  SCOPE/bypass: the rule matches execve arg0 by shell-name postfix - NOT a robust shell-block."
Write-Host "    Bypassable via renamed binary (cp /bin/busybox /tmp/x && /tmp/x sh -> arg0 unmatched),"
Write-Host "    execveat (unhooked syscall), and fd-exec. ED1 = 'naive direct shell-named execve is killed',"
Write-Host "    NOT 'a shell cannot run'. Robust: matchBinaries / sched_process_exec / LSM, or exec allowlist."
Write-Host "  B (execve timing, DOCUMENTED not measured here): execve+Sigkill is pre-image-load"
Write-Host "    ('before the shell initializes'), so the shell never runs its first command -> no"
Write-Host "    measurable side-effect window for execve. (The pod HAS writable emptyDirs at /tmp,"
Write-Host "    /var/cache/nginx, /var/run; the moot-ness is the pre-image-load timing, not a lack of writable paths.)"
Write-Host "  C (I/O window): Tetragon's docs state a SIGKILL in a write() syscall does NOT guarantee"
Write-Host "    the bytes are not written - synchronous-process-kill != pre-operation. Making a kprobe"
Write-Host "    rule prevention-grade for I/O needs Sigkill + the Override action. Our shell rule is"
Write-Host "    Sigkill-only = prevention-grade for execve, detection-grade for I/O. SKIP-prone on kind"
Write-Host "    (Tetragon #4883); see labs/m8/tracingpolicy-write-window.yaml to explore it live."
Write-Host "  io_uring: a non-execve I/O path (e.g. IORING_OP_READ) is invisible to Tetragon's DEFAULT"
Write-Host "    syscall policies (ARMO 'Curing', 2025); LSM/KRSI hooks WOULD see it. The shipped"
Write-Host "    execve rule itself is unaffected (io_uring has no execve opcode)."
exit $fail
