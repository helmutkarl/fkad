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
    [switch]$NoExec
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $NoExec -and -not (Test-Path -LiteralPath $ProbeExecutable -PathType Leaf)) {
    throw "Probe executable not found: $ProbeExecutable"
}

$probeHash = $null

if (-not $NoExec) {
    try {
        $probeHash = (Get-FileHash -LiteralPath $ProbeExecutable -Algorithm SHA256).Hash
    }
    catch {}
}

Write-Host ""
Write-Host "fkpathprobe" -ForegroundColor Cyan
Write-Host "-----------" -ForegroundColor DarkGray
Write-Host "Roots       : $($Directory -join ', ')"
Write-Host "Depth       : $Depth"

if (-not $NoExec) {
    Write-Host "Probe       : $ProbeExecutable"
    Write-Host "Probe SHA256: $probeHash"
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

    $id = [guid]::NewGuid().ToString("N")

    $writeProbe = Join-Path $folder.FullName ".fkpathprobe_$id.tmp"
    $exeProbe   = Join-Path $folder.FullName ".fkpathprobe_$id.exe"

    $write      = $false
    $read       = $false
    $delete     = $false
    $copyExe    = $false
    $execute    = $false
    $cleanupExe = $false

    $writeError = $null
    $execError  = $null

    #
    # 1. Effective write test
    #
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

    if (-not $write) {
        continue
    }

    #
    # 2. Read test
    #
    try {
        $content = [System.IO.File]::ReadAllText($writeProbe)

        if ($content -eq "FKPATHPROBE_$id") {
            $read = $true
        }
    }
    catch {}

    #
    # 3. Delete test
    #
    try {
        Remove-Item `
            -LiteralPath $writeProbe `
            -Force `
            -ErrorAction Stop

        $delete = $true
    }
    catch {}

    #
    # 4. Actual executable test
    #
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
                $psi.WorkingDirectory = $folder.FullName
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

            #
            # Cleanup executable probe
            #
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

    $result = [PSCustomObject]@{
        Path           = $folder.FullName
        Writable       = $write
        Readable       = $read
        Deletable      = $delete
        ProbeCopied    = $copyExe
        Executable     = $execute
        ProbeSHA256    = $probeHash
        ProbeCleanup   = $cleanupExe
        WriteError     = $writeError
        ExecutionError = $execError
    }

    $results += $result

    if ($execute) {
        Write-Host "[WRITE + EXEC] $($folder.FullName)" -ForegroundColor Red
    }
    elseif ($copyExe) {
        Write-Host "[WRITE ONLY]   $($folder.FullName)" -ForegroundColor Yellow
    }
    else {
        Write-Host "[WRITABLE]     $($folder.FullName)" -ForegroundColor DarkYellow
    }
}

$results |
    Export-Csv `
        -LiteralPath $CsvPath `
        -NoTypeInformation `
        -Encoding UTF8

Write-Host ""
Write-Host "Finished." -ForegroundColor Cyan
Write-Host "Scanned            : $($folders.Count)"
Write-Host "Writable           : $(($results | Where-Object Writable).Count)"
Write-Host "Writable+Executable: $(($results | Where-Object Executable).Count)"
Write-Host "Results             : $CsvPath"
