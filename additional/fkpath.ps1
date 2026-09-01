param (
    [string[]]$Directory = @("C:\Windows"),
    [ValidateRange(1, 20)]
    [int]$Depth = 5,

    [string]$ProbeExecutable = "$env:WINDIR\System32\cmd.exe",
    [string]$ProbeArguments = "/d /c exit 0",

    [ValidateRange(250, 30000)]
    [int]$ExecTimeoutMs = 3000,

    [string]$CsvPath = ".\fkpathprobe.csv",

    [switch]$NoExec,
    [switch]$NoAclEscalation
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $NoExec -and -not (Test-Path -LiteralPath $ProbeExecutable -PathType Leaf)) {
    throw "Probe executable not found: $ProbeExecutable"
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentAccount  = $currentIdentity.Name
$currentSid      = $currentIdentity.User

# Build a SID set for the current logon token once. This avoids account-name
# translation for every ACE in every directory.
$tokenSids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
[void]$tokenSids.Add($currentSid.Value)

foreach ($sid in $currentIdentity.Groups) {
    if ($null -ne $sid) {
        [void]$tokenSids.Add($sid.Value)
    }
}

# Common token SIDs which may not always appear in WindowsIdentity.Groups.
[void]$tokenSids.Add('S-1-1-0')   # Everyone
[void]$tokenSids.Add('S-1-5-11')  # Authenticated Users

$probeHash = $null
if (-not $NoExec) {
    try {
        $probeHash = (Get-FileHash -LiteralPath $ProbeExecutable -Algorithm SHA256).Hash
    }
    catch {}
}

function Invoke-DirectoryProbe {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $id = [guid]::NewGuid().ToString('N')
    $writeProbe = Join-Path $Path ".fkpathprobe_$id.tmp"
    $exeProbe   = Join-Path $Path ".fkpathprobe_$id.exe"

    $write      = $false
    $read       = $false
    $delete     = $false
    $copyExe    = $false
    $execute    = $false
    $cleanupExe = $false
    $writeError = $null
    $execError  = $null

    try {
        [System.IO.File]::WriteAllText($writeProbe, "FKPATHPROBE_$id")
        $write = $true
    }
    catch {
        $writeError = $_.Exception.Message
    }

    if ($write) {
        try {
            if ([System.IO.File]::ReadAllText($writeProbe) -eq "FKPATHPROBE_$id") {
                $read = $true
            }
        }
        catch {}

        try {
            Remove-Item -LiteralPath $writeProbe -Force -ErrorAction Stop
            $delete = $true
        }
        catch {}

        if (-not $NoExec) {
            try {
                Copy-Item -LiteralPath $ProbeExecutable -Destination $exeProbe -Force -ErrorAction Stop
                $copyExe = $true
            }
            catch {
                $execError = $_.Exception.Message
            }

            if ($copyExe) {
                $process = $null
                try {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = $exeProbe
                    $psi.Arguments = $ProbeArguments
                    $psi.WorkingDirectory = $Path
                    $psi.UseShellExecute = $false
                    $psi.CreateNoWindow = $true

                    $process = [System.Diagnostics.Process]::Start($psi)
                    if ($null -ne $process) {
                        # Successful process creation proves execution from the path.
                        $execute = $true

                        if (-not $process.WaitForExit($ExecTimeoutMs)) {
                            try { $process.Kill() } catch {}
                        }
                    }
                }
                catch {
                    $execError = $_.Exception.Message
                }
                finally {
                    if ($null -ne $process) {
                        try { $process.Dispose() } catch {}
                    }
                }

                try {
                    Remove-Item -LiteralPath $exeProbe -Force -ErrorAction Stop
                    $cleanupExe = $true
                }
                catch {}
            }
        }
    }

    return [PSCustomObject]@{
        Writable       = $write
        Readable       = $read
        Deletable      = $delete
        ProbeCopied    = $copyExe
        Executable     = $execute
        ProbeCleanup   = $cleanupExe
        WriteError     = $writeError
        ExecutionError = $execError
    }
}

function Get-EffectiveControlRights {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.DirectorySecurity]$Acl
    )

    $canWriteDac   = $false
    $canWriteOwner = $false

    # An object's owner has the implicit right to change its DACL.
    try {
        $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier])
        if ($null -ne $ownerSid -and $ownerSid.Value -eq $currentSid.Value) {
            $canWriteDac = $true
        }
    }
    catch {}

    try {
        $rules = $Acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )

        # AccessCheck semantics for a single requested right are simple here:
        # walk the canonical DACL in order. The first matching deny/allow that
        # covers that still-unresolved right decides it. Inherit-only ACEs do
        # not apply to the directory object itself.
        $writeDacResolved   = $canWriteDac
        $writeOwnerResolved = $false

        foreach ($rule in $rules) {
            if ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
                continue
            }

            $sid = $rule.IdentityReference.Value
            if (-not $tokenSids.Contains($sid)) {
                continue
            }

            $rights = [System.Security.AccessControl.FileSystemRights]$rule.FileSystemRights

            if (-not $writeDacResolved -and ($rights -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions)) {
                $writeDacResolved = $true
                $canWriteDac = ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
            }

            if (-not $writeOwnerResolved -and ($rights -band [System.Security.AccessControl.FileSystemRights]::TakeOwnership)) {
                $writeOwnerResolved = $true
                $canWriteOwner = ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
            }

            if ($writeDacResolved -and $writeOwnerResolved) {
                break
            }
        }
    }
    catch {}

    return [PSCustomObject]@{
        WriteDac   = $canWriteDac
        WriteOwner = $canWriteOwner
    }
}

function Grant-CurrentUserModifyFast {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.DirectorySecurity]$Acl
    )

    try {
        # This ACE applies to the directory itself. It intentionally does not
        # rewrite existing child ACLs. The change is persistent.
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentSid,
            [System.Security.AccessControl.FileSystemRights]::Modify,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        [void]$Acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $Acl -ErrorAction Stop

        return [PSCustomObject]@{ Success = $true; Detail = $null }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Detail = $_.Exception.Message }
    }
}

function Set-CurrentUserOwnerFast {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.DirectorySecurity]$Acl
    )

    try {
        $Acl.SetOwner($currentSid)
        Set-Acl -LiteralPath $Path -AclObject $Acl -ErrorAction Stop
        return [PSCustomObject]@{ Success = $true; Detail = $null }
    }
    catch {
        return [PSCustomObject]@{ Success = $false; Detail = $_.Exception.Message }
    }
}

Write-Host ""
Write-Host "fkpathprobe" -ForegroundColor Cyan
Write-Host "-----------" -ForegroundColor DarkGray
Write-Host "Roots       : $($Directory -join ', ')"
Write-Host "Depth       : $Depth"
Write-Host "User        : $currentAccount"

if (-not $NoExec) {
    Write-Host "Probe       : $ProbeExecutable"
    Write-Host "Probe SHA256: $probeHash"
}

if ($NoAclEscalation) {
    Write-Host "ACL probing : disabled"
}
else {
    Write-Host "ACL probing : token-filtered; successful changes are PERSISTENT" -ForegroundColor Yellow
}

Write-Host ""

$folders = foreach ($root in $Directory) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        Write-Host "[NOT FOUND] $root" -ForegroundColor DarkYellow
        continue
    }

    Get-Item -LiteralPath $root -ErrorAction SilentlyContinue

    Get-ChildItem `
        -LiteralPath $root `
        -Directory `
        -Recurse `
        -Depth ($Depth - 1) `
        -Force `
        -ErrorAction SilentlyContinue
}

$folders = $folders |
    Where-Object { $_ } |
    Sort-Object FullName -Unique

Write-Host "Found $($folders.Count) directories."
Write-Host ""

$results = New-Object 'System.Collections.Generic.List[object]'
$processed = 0
$aclCandidates = 0

foreach ($folder in $folders) {
    $processed++
    $path = $folder.FullName

    # Fast path: practical write/exec probe first. No Get-Acl call is needed
    # for already writable paths.
    $initialProbe = Invoke-DirectoryProbe -Path $path

    $candidateWriteDac   = $false
    $candidateWriteOwner = $false
    $aclGrantAttempted   = $false
    $aclGrantSucceeded   = $false
    $aclGrantError       = $null
    $ownerChangeAttempted = $false
    $ownerChangeSucceeded = $false
    $ownerChangeError     = $null
    $escalationMethod     = $null
    $finalProbe           = $initialProbe

    $originalOwner = $null
    $originalSddl  = $null
    $finalOwner    = $null
    $finalSddl     = $null

    # Slow path only for non-writable directories.
    if (-not $initialProbe.Writable -and -not $NoAclEscalation) {
        $acl = $null

        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            $originalOwner = $acl.Owner
            $originalSddl  = $acl.Sddl
        }
        catch {}

        if ($null -ne $acl) {
            $control = Get-EffectiveControlRights -Acl $acl
            $candidateWriteDac   = $control.WriteDac
            $candidateWriteOwner = $control.WriteOwner

            if ($candidateWriteDac -or $candidateWriteOwner) {
                $aclCandidates++
            }

            # Only attempt a persistent DACL mutation if the current token's
            # ACEs/ownership indicate that ChangePermissions is actually usable.
            if ($candidateWriteDac) {
                $aclGrantAttempted = $true
                $grantResult = Grant-CurrentUserModifyFast -Path $path -Acl $acl

                if ($grantResult.Success) {
                    $aclGrantSucceeded = $true
                    $escalationMethod = 'DACL'
                }
                else {
                    $aclGrantError = $grantResult.Detail
                }
            }

            # If direct DACL control was unavailable or failed, test WRITE_OWNER.
            if (-not $aclGrantSucceeded -and $candidateWriteOwner) {
                $ownerChangeAttempted = $true
                $ownerResult = Set-CurrentUserOwnerFast -Path $path -Acl $acl

                if ($ownerResult.Success) {
                    $ownerChangeSucceeded = $true
                    $escalationMethod = 'OWNER'

                    # Re-read after ownership change; the owner can then alter the DACL.
                    try {
                        $ownedAcl = Get-Acl -LiteralPath $path -ErrorAction Stop
                        $aclGrantAttempted = $true
                        $grantAfterOwner = Grant-CurrentUserModifyFast -Path $path -Acl $ownedAcl

                        if ($grantAfterOwner.Success) {
                            $aclGrantSucceeded = $true
                            $escalationMethod = 'OWNER+DACL'
                        }
                        else {
                            $aclGrantError = $grantAfterOwner.Detail
                        }
                    }
                    catch {
                        $aclGrantError = $_.Exception.Message
                    }
                }
                else {
                    $ownerChangeError = $ownerResult.Detail
                }
            }

            if ($aclGrantSucceeded -or $ownerChangeSucceeded) {
                $finalProbe = Invoke-DirectoryProbe -Path $path

                try {
                    $finalAcl = Get-Acl -LiteralPath $path -ErrorAction Stop
                    $finalOwner = $finalAcl.Owner
                    $finalSddl  = $finalAcl.Sddl
                }
                catch {}
            }
        }
    }

    $interesting = (
        $initialProbe.Writable -or
        $candidateWriteDac -or
        $candidateWriteOwner -or
        $aclGrantSucceeded -or
        $ownerChangeSucceeded -or
        $finalProbe.Writable
    )

    if (-not $interesting) {
        if (($processed % 500) -eq 0) {
            Write-Host "Processed $processed/$($folders.Count)..." -ForegroundColor DarkGray
        }
        continue
    }

    $result = [PSCustomObject]@{
        Path                    = $path
        InitiallyWritable       = $initialProbe.Writable
        InitiallyExecutable     = $initialProbe.Executable

        CandidateWriteDac       = $candidateWriteDac
        CandidateWriteOwner     = $candidateWriteOwner
        AclGrantAttempted       = $aclGrantAttempted
        AclGrantSucceeded       = $aclGrantSucceeded
        OwnerChangeAttempted    = $ownerChangeAttempted
        OwnerChangeSucceeded    = $ownerChangeSucceeded
        EscalationMethod        = $escalationMethod

        Writable                = $finalProbe.Writable
        Readable                = $finalProbe.Readable
        Deletable               = $finalProbe.Deletable
        ProbeCopied             = $finalProbe.ProbeCopied
        Executable              = $finalProbe.Executable

        OriginalOwner           = $originalOwner
        OriginalSDDL            = $originalSddl
        FinalOwner              = $finalOwner
        FinalSDDL               = $finalSddl

        ProbeSHA256             = $probeHash
        ProbeCleanup            = $finalProbe.ProbeCleanup
        WriteError              = $finalProbe.WriteError
        ExecutionError          = $finalProbe.ExecutionError
        AclGrantError           = $aclGrantError
        OwnerChangeError        = $ownerChangeError
    }

    $results.Add($result)

    if (-not $initialProbe.Writable -and $aclGrantSucceeded -and $finalProbe.Executable) {
        Write-Host "[$escalationMethod -> WRITE + EXEC] $path" -ForegroundColor Magenta
    }
    elseif (-not $initialProbe.Writable -and $aclGrantSucceeded -and $finalProbe.Writable) {
        Write-Host "[$escalationMethod -> WRITE ONLY]   $path" -ForegroundColor Magenta
    }
    elseif ($candidateWriteDac -or $candidateWriteOwner) {
        Write-Host "[ACL CONTROL]  $path  WDAC=$candidateWriteDac WO=$candidateWriteOwner" -ForegroundColor Magenta
    }
    elseif ($finalProbe.Executable) {
        Write-Host "[WRITE + EXEC] $path" -ForegroundColor Red
    }
    elseif ($finalProbe.ProbeCopied) {
        Write-Host "[WRITE ONLY]   $path" -ForegroundColor Yellow
    }
    else {
        Write-Host "[WRITABLE]     $path" -ForegroundColor DarkYellow
    }
}

$results |
    Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Finished." -ForegroundColor Cyan
Write-Host "Scanned                  : $($folders.Count)"
Write-Host "ACL-control candidates   : $aclCandidates"
Write-Host "Initially writable       : $(($results | Where-Object InitiallyWritable).Count)"
Write-Host "DACL grant succeeded     : $(($results | Where-Object AclGrantSucceeded).Count)"
Write-Host "Owner change succeeded   : $(($results | Where-Object OwnerChangeSucceeded).Count)"
Write-Host "Final writable           : $(($results | Where-Object Writable).Count)"
Write-Host "Final writable+executable: $(($results | Where-Object Executable).Count)"
Write-Host "Results                   : $CsvPath"

if (-not $NoAclEscalation) {
    Write-Host ""
    Write-Host "Successful ACL/owner changes were NOT reverted." -ForegroundColor Yellow
    Write-Host "Original Owner and SDDL are stored in the CSV for evidence/manual rollback." -ForegroundColor Yellow
}
