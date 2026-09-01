param (
    [string[]]$Directory = @("C:\Windows"),
    [ValidateRange(1, 20)]
    [int]$Depth = 5,

    # Benign executable used for execution testing.
    # Can be replaced with your own unsigned binary.
    [string]$ProbeExecutable = "$env:WINDIR\System32\cmd.exe",

    # Arguments for the default cmd.exe probe.
    # Set to "" when using a custom PoC that does not need arguments.
    [string]$ProbeArguments = "/d /c exit 0",

    [ValidateRange(250, 30000)]
    [int]$ExecTimeoutMs = 3000,

    [string]$CsvPath = ".\fkpathprobe.csv",

    # Only perform write/read/delete testing.
    [switch]$NoExec,

    # Do not attempt persistent DACL/owner changes on non-writable directories.
    [switch]$NoAclEscalation
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $NoExec -and -not (Test-Path -LiteralPath $ProbeExecutable -PathType Leaf)) {
    throw "Probe executable not found: $ProbeExecutable"
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentAccount = $currentIdentity.Name
$probeHash = $null

if (-not $NoExec) {
    try {
        $probeHash = (Get-FileHash -LiteralPath $ProbeExecutable -Algorithm SHA256).Hash
    }
    catch {}
}

function Get-AclSnapshot {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop

        return [PSCustomObject]@{
            Owner = $acl.Owner
            Sddl  = $acl.Sddl
        }
    }
    catch {
        return [PSCustomObject]@{
            Owner = $null
            Sddl  = $null
        }
    }
}

function Grant-CurrentUserModify {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # Intentionally grant Modify only on this directory itself. No /T and no
    # inheritance flags are used, so existing child ACLs are not recursively changed.
    # The permission change is intentionally persistent.
    $grant = "${currentAccount}:(M)"
    $output = & icacls.exe $Path /grant $grant /Q 2>&1
    $exitCode = $LASTEXITCODE

    return [PSCustomObject]@{
        Success  = ($exitCode -eq 0)
        ExitCode = $exitCode
        Detail   = (($output | Out-String).Trim())
    }
}

function Set-CurrentUserOwner {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # This attempts an actual owner change instead of only inferring WRITE_OWNER
    # from ACEs. A successful change is intentionally left in place.
    $output = & icacls.exe $Path /setowner $currentAccount /Q 2>&1
    $exitCode = $LASTEXITCODE

    return [PSCustomObject]@{
        Success  = ($exitCode -eq 0)
        ExitCode = $exitCode
        Detail   = (($output | Out-String).Trim())
    }
}

function Invoke-DirectoryProbe {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $id = [guid]::NewGuid().ToString("N")

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

    # 1. Effective write test
    try {
        [System.IO.File]::WriteAllText(
            $writeProbe,
            "FKPATHPROBE_$id"
        )

        $write = $true
    }
    catch {
        $writeError = $_.Exception.Message
    }

    if ($write) {

        # 2. Read test
        try {
            $content = [System.IO.File]::ReadAllText($writeProbe)

            if ($content -eq "FKPATHPROBE_$id") {
                $read = $true
            }
        }
        catch {}

        # 3. Delete test
        try {
            Remove-Item `
                -LiteralPath $writeProbe `
                -Force `
                -ErrorAction Stop

            $delete = $true
        }
        catch {}

        # 4. Actual executable test
        if (-not $NoExec) {

            try {
                Copy-Item `
                    -LiteralPath $ProbeExecutable `
                    -Destination $exeProbe `
                    -Force `
                    -ErrorAction Stop

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

                        # Process creation itself is enough to prove execution.
                        $execute = $true

                        if (-not $process.WaitForExit($ExecTimeoutMs)) {
                            try {
                                $process.Kill()
                            }
                            catch {}
                        }
                    }
                }
                catch {
                    $execError = $_.Exception.Message
                }
                finally {
                    if ($null -ne $process) {
                        try {
                            $process.Dispose()
                        }
                        catch {}
                    }
                }

                # Cleanup executable probe. ACL/owner changes are NOT cleaned up.
                try {
                    Remove-Item `
                        -LiteralPath $exeProbe `
                        -Force `
                        -ErrorAction Stop

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
    Write-Host "ACL probing : enabled; successful changes are PERSISTENT" -ForegroundColor Yellow
}

Write-Host ""

# Collect root directories + descendants.
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

$results = @()
$processed = 0

foreach ($folder in $folders) {

    $processed++
    $path = $folder.FullName

    $originalAcl = Get-AclSnapshot -Path $path

    $initialProbe = Invoke-DirectoryProbe -Path $path

    $aclGrantAttempted = $false
    $aclGrantSucceeded = $false
    $aclGrantError = $null

    $ownerChangeAttempted = $false
    $ownerChangeSucceeded = $false
    $ownerChangeError = $null

    $escalationMethod = $null
    $finalProbe = $initialProbe

    # If direct file creation is denied, test the two permission-control paths
    # by actually attempting the changes rather than only parsing ACL text.
    if (-not $initialProbe.Writable -and -not $NoAclEscalation) {

        # First try to grant ourselves Modify. Success proves effective ability
        # to change the DACL (for example WRITE_DAC, or owner-equivalent control).
        $aclGrantAttempted = $true
        $grantResult = Grant-CurrentUserModify -Path $path

        if ($grantResult.Success) {
            $aclGrantSucceeded = $true
            $escalationMethod = "DACL"
        }
        else {
            $aclGrantError = $grantResult.Detail

            # If direct DACL modification failed, try changing the owner to the
            # current user. Success can expose a WRITE_OWNER-style path. Once we
            # own it, retry the persistent Modify grant.
            $ownerChangeAttempted = $true
            $ownerResult = Set-CurrentUserOwner -Path $path

            if ($ownerResult.Success) {
                $ownerChangeSucceeded = $true
                $escalationMethod = "OWNER"

                $aclGrantAttempted = $true
                $grantAfterOwner = Grant-CurrentUserModify -Path $path

                if ($grantAfterOwner.Success) {
                    $aclGrantSucceeded = $true
                    $escalationMethod = "OWNER+DACL"
                }
                else {
                    $aclGrantError = $grantAfterOwner.Detail
                }
            }
            else {
                $ownerChangeError = $ownerResult.Detail
            }
        }

        if ($aclGrantSucceeded -or $ownerChangeSucceeded) {
            $finalProbe = Invoke-DirectoryProbe -Path $path
        }
    }

    $finalAcl = Get-AclSnapshot -Path $path

    # Keep the same general output philosophy as the original script: only
    # store interesting paths, now including successful ACL/owner control.
    $interesting = (
        $initialProbe.Writable -or
        $finalProbe.Writable -or
        $aclGrantSucceeded -or
        $ownerChangeSucceeded
    )

    if (-not $interesting) {
        continue
    }

    $result = [PSCustomObject]@{
        Path                   = $path

        InitiallyWritable      = $initialProbe.Writable
        InitiallyExecutable    = $initialProbe.Executable

        AclGrantAttempted      = $aclGrantAttempted
        AclGrantSucceeded      = $aclGrantSucceeded
        OwnerChangeAttempted   = $ownerChangeAttempted
        OwnerChangeSucceeded   = $ownerChangeSucceeded
        EscalationMethod       = $escalationMethod

        Writable               = $finalProbe.Writable
        Readable               = $finalProbe.Readable
        Deletable              = $finalProbe.Deletable
        ProbeCopied            = $finalProbe.ProbeCopied
        Executable             = $finalProbe.Executable

        OriginalOwner          = $originalAcl.Owner
        OriginalSDDL           = $originalAcl.Sddl
        FinalOwner             = $finalAcl.Owner
        FinalSDDL              = $finalAcl.Sddl

        ProbeSHA256            = $probeHash
        ProbeCleanup           = $finalProbe.ProbeCleanup
        WriteError             = $finalProbe.WriteError
        ExecutionError         = $finalProbe.ExecutionError
        AclGrantError          = $aclGrantError
        OwnerChangeError       = $ownerChangeError
    }

    $results += $result

    if (-not $initialProbe.Writable -and $aclGrantSucceeded -and $finalProbe.Executable) {
        Write-Host "[$escalationMethod -> WRITE + EXEC] $path" -ForegroundColor Magenta
    }
    elseif (-not $initialProbe.Writable -and $aclGrantSucceeded -and $finalProbe.Writable) {
        Write-Host "[$escalationMethod -> WRITE ONLY]   $path" -ForegroundColor Magenta
    }
    elseif (-not $initialProbe.Writable -and $ownerChangeSucceeded) {
        Write-Host "[$escalationMethod CONTROL]         $path" -ForegroundColor Magenta
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
    Export-Csv `
        -LiteralPath $CsvPath `
        -NoTypeInformation `
        -Encoding UTF8

Write-Host ""
Write-Host "Finished." -ForegroundColor Cyan
Write-Host "Scanned                 : $($folders.Count)"
Write-Host "Initially writable      : $(($results | Where-Object InitiallyWritable).Count)"
Write-Host "DACL grant succeeded    : $(($results | Where-Object AclGrantSucceeded).Count)"
Write-Host "Owner change succeeded  : $(($results | Where-Object OwnerChangeSucceeded).Count)"
Write-Host "Final writable          : $(($results | Where-Object Writable).Count)"
Write-Host "Final writable+executable: $(($results | Where-Object Executable).Count)"
Write-Host "Results                  : $CsvPath"

if (-not $NoAclEscalation) {
    Write-Host ""
    Write-Host "Successful ACL/owner changes were NOT reverted." -ForegroundColor Yellow
    Write-Host "Original Owner and SDDL are stored in the CSV for evidence/manual rollback." -ForegroundColor Yellow
}
