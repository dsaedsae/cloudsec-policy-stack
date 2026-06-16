# verify-runtime-scope.ps1 - OPT-IN (M8): measure the DELTA between the selective shell-kill
# (M4's naive primitive) and the ZERO-EXEC rule that is the SHIPPED default. Applies each rule to
# the live db pod, probes, and RESTORES the shipped zero-exec on exit. Windows twin of
# verify-runtime-scope.sh (same probes).
#   Phase 1  selective (M4)   -> a non-shell exec (id) SURVIVES, a shell exec dies (137)
#   Phase 2  zero-exec (ship) -> id ALSO dies (137): the name-independent gap is closed
# Does NOT change ED1 (VERIFIED) or the 75% metric. NOTE: temporarily swaps the data-tier
# TracingPolicy on the running db; the finally block restores shipped zero-exec. Run standalone.
$ErrorActionPreference = "Continue"
$ctx = "kind-cloudsec"; $ns = "shop"; $fail = 0
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
$SEL  = Join-Path $ROOT "labs\m4\tracingpolicy.solution.yaml"   # selective (M4 primitive)
$ZERO = Join-Path $ROOT "k8s\tracingpolicy.yaml"               # zero-exec (shipped default)
$SEL_NAME = "block-shell-in-data-tier"; $ZERO_NAME = "data-tier-no-exec"
$DBPOD = kubectl --context $ctx -n $ns get pod -l tier=data -o "jsonpath={.items[0].metadata.name}" 2>$null
if (-not $DBPOD) { Write-Host "SKIP: no tier=data pod in $ns (run scripts\up.ps1 first)"; exit 0 }

function Only($file) {  # apply exactly ONE rule (delete both first so they never overlap), let eBPF load
    kubectl --context $ctx delete tracingpolicy $SEL_NAME $ZERO_NAME *> $null
    kubectl --context $ctx apply -f $file *> $null
    Start-Sleep -Seconds 6
}
function Probe($label, $expect, [string[]]$cmd) {
    kubectl --context $ctx -n $ns exec $DBPOD -- @cmd *> $null; $rc = $LASTEXITCODE
    $ok = ($rc -eq $expect); if (-not $ok) { $script:fail = 1 }
    Write-Host ("  {0,-40} rc={1,-4} expect {2,-4} {3}" -f $label, $rc, $expect, $(if ($ok) { "PASS" } else { "FAIL" }))
}

try {
    Write-Host "== M8: selective (M4 primitive) vs zero-exec (shipped) - measure the DELTA =="
    Write-Host "-- Phase 1: SELECTIVE rule (M4 naive cut) - apply + measure --"
    Only $SEL
    Probe "id (non-shell binary) SURVIVES"      0   @("id")
    Probe "sh -c (shell execve) SIGKILLed"       137 @("sh", "-c", "echo x")
    Probe "cat /etc/passwd (file read) survives" 0   @("cat", "/etc/passwd")
    Write-Host "   -> selective: only shell-name execve dies; id + file-read live (this is the GAP)."
    Write-Host "-- Phase 2: ZERO-EXEC rule (shipped default) - apply + measure --"
    Only $ZERO
    Probe "id (non-shell binary) now KILLED"     137 @("id")
    Probe "sh -c (shell execve) KILLED"           137 @("sh", "-c", "echo x")
    Write-Host "   -> zero-exec: ALL data-tier exec dies, name-independent (closes the renamed/execveat gap)."
    Write-Host "----------------------------------------------------------------"
    if ($fail -eq 0) { Write-Host "PASS: selective lets id run (the gap); zero-exec (shipped) closes it - name-independent." }
    else { Write-Host "FAIL above." }
}
finally {
    kubectl --context $ctx delete tracingpolicy $SEL_NAME *> $null
    kubectl --context $ctx apply -f $ZERO *> $null
    Write-Host "(restored shipped zero-exec: k8s/tracingpolicy.yaml; selective rule removed)"
}

Write-Host ""
Write-Host "HONEST NOTES (documented, not asserted here - see labs/m8/README.md + THREAT_MODEL.md + ADR 0001):"
Write-Host "  WHY zero-exec is shipped: the selective rule matches execve arg0 by shell-name postfix - NOT a"
Write-Host "    robust shell-block. Bypassable via renamed binary (cp /bin/busybox /tmp/x && /tmp/x sh -> arg0"
Write-Host "    unmatched), execveat (a separate unhooked syscall), and fd-exec. matchBinaries is the WRONG fix"
Write-Host "    (it matches the CALLER, not the launched image). The data tier runs only its main process (db"
Write-Host "    probes are httpGet, not exec), so the shipped default forbids ALL exec - name-independent,"
Write-Host "    covers execveat. The selective primitive + 'over-blocking is a defect' lesson live on in M4;"
Write-Host "    this shows why M8/ADR 0001 promoted zero-exec to the default."
Write-Host "  B (execve timing, DOCUMENTED not measured here): execve+Sigkill is pre-image-load. The pod HAS"
Write-Host "    writable emptyDirs at /tmp etc.; the moot-ness is the timing, not a lack of writable paths."
Write-Host "  C (I/O window): a write()+Sigkill rule kills the process but the kernel may already have done the"
Write-Host "    I/O (synchronous-process-kill != pre-operation); prevention-grade needs Sigkill+Override."
Write-Host "    SKIP-prone on kind (Tetragon #4883); see labs/m8/tracingpolicy-write-window.yaml."
Write-Host "  io_uring: a non-execve I/O path is invisible to Tetragon's DEFAULT syscall policies (ARMO"
Write-Host "    'Curing' 2025); LSM/KRSI hooks would see it. The execve-based rules here are unaffected."
exit $fail
