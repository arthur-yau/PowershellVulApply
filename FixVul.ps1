<#
.SYNOPSIS
    Apply registry from XML – ONE manifest.json for all runs.
    Backup .reg files per-run, rollback any previous run.

.PARAMETER XmlPath   Path to the XML file
.PARAMETER IDs       Comma-separated IDs or "all"
.PARAMETER Rollback  Restore the *last* apply (or specify RunId)
.PARAMETER VerifyOnly Verify selected IDs only
#>

param(
    [Parameter(Mandatory)][string]$XmlPath,
    [string]$IDs = "all",
    [switch]$Rollback,
    [string]$RunId,               # optional – rollback a specific run
    [switch]$VerifyOnly
)

# -------------------------------------------------------------------------
# 0. Configuration
# -------------------------------------------------------------------------
$BaseDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$ManifestPath = Join-Path $BaseDir "manifest.json"
$BackupRoot   = Join-Path $BaseDir "Backups"

# Ensure folders exist
foreach ($p in @($BaseDir,$BackupRoot)) { if(-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

# -------------------------------------------------------------------------
# 1. Helper Functions
# -------------------------------------------------------------------------
function Convert-Hive { param([string]$p)
    $m = @{"HKLM:"="HKEY_LOCAL_MACHINE"; "HKCU:"="HKEY_CURRENT_USER"; "HKCR:"="HKEY_CLASSES_ROOT"; "HKU:"="HKEY_USERS"; "HKCC:"="HKEY_CURRENT_CONFIG"}
    foreach ($k in $m.Keys) { if ($p -like "$k*") { return $p -replace "^$([regex]::Escape($k))", $m[$k] } }
    $p
}
function Get-RegValue { param($Path,$Name)
    try {
        $i = Get-Item $Path -EA SilentlyContinue
        if ($i) {
            $v = if ($Name -eq "(Default)") { $i.GetValue("") } else { $i.GetValue($Name) }
            $t = if ($Name -eq "(Default)") { "String" } else { $i.GetValueKind($Name) }
            return @{Value=$v; Type=$t}
        }
    }catch{}
    return @{Value=$null; Type=$null}
}
function New-RegBackup { param($Path,$Name,$Value,$Type,$ID,$RunFolder)
    $hive = Convert-Hive $Path
    $safe = if ($Name -eq "(Default)") { "@" } else { "`"$Name`"" }
    $file = Join-Path $RunFolder "reg_files" ("$ID`_$( ($hive -replace '[:\\]','_') ).reg")

    $lines = @("Windows Registry Editor Version 5.00","","[$hive]")
    if ($null -eq $Value -and $Name -ne "(Default)") { $lines += "-$safe" }
    elseif ($Type -eq "DWORD")   { $lines += "$safe=dword:$('{0:x8}' -f [uint32]$Value)" }
    elseif ($Type -eq "QWORD")   { $lines += "$safe=hex(b):$([BitConverter]::GetBytes([uint64]$Value)|%{$_.ToString('x2')}-join ',')" }
    elseif ($Type -eq "Binary")  { $lines += "$safe=hex:$($Value|%{$_.ToString('x2')}-join ',')" }
    elseif ($Type -eq "MultiString") {
        $esc = ($Value -join "`0") + "`0"
        $hex = ([Text.Encoding]::Unicode.GetBytes($esc)|%{$_.ToString('x2')}-join ',')
        $lines += "$safe=hex(7):$hex"
    }
    else { $lines += "$safe=`"$Value`"" }

    $lines | Out-File $file -Encoding ASCII
    return $file
}

# -------------------------------------------------------------------------
# 2. Load / Init Manifest
# -------------------------------------------------------------------------
if (Test-Path $ManifestPath) {
    $Manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
} else {
    $Manifest = @()
}

# -------------------------------------------------------------------------
# 3. ROLLBACK MODE
# -------------------------------------------------------------------------
if ($Rollback) {
    if (-not $Manifest) { throw "No manifest – nothing to roll back." }

    # Choose run: last one, or specific RunId
    $run = if ($RunId) { $Manifest | Where-Object RunId -eq $RunId } else { $Manifest[-1] }
    if (-not $run) { throw "RunId $RunId not found." }

    Write-Host "Rolling back RunId $($run.RunId) ($($run.Timestamp)) ..." -ForegroundColor Yellow
    foreach ($e in $run.Entries) {
        if (Test-Path $e.RegFile) {
            Write-Host "  [ID:$($e.ID)] Importing $($e.RegFile)" -ForegroundColor Cyan
            $out = reg import $e.RegFile 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Host "  Success" -ForegroundColor Green }
            else { Write-Warning "  FAILED: $out" }
        }
    }
    Write-Host "Rollback complete." -ForegroundColor Green
    return
}

# -------------------------------------------------------------------------
# 4. Load XML & Select IDs
# -------------------------------------------------------------------------
[xml]$xml = Get-Content $XmlPath
$all = $xml.RegistrySettings.Entry
$sel = if ($IDs -eq "all") { $all } else { $all | Where-Object { $_.ID -in ($IDs -split ',' | % Trim) } }
if (-not $sel) { throw "No entries match IDs: $IDs" }

# -------------------------------------------------------------------------
# 5. VERIFY ONLY
# -------------------------------------------------------------------------
if ($VerifyOnly) {
    $ok = $true
    foreach ($e in $sel) {
        $cur = Get-RegValue $e.Path $e.Name
        $exp = $e.Value
        if ($e.Type -match "DWord|QWord") { $exp = [int64]$exp }
        $match = ($cur.Value -eq $exp)
        if (-not $match) { $ok=$false; Write-Host "  [ID:$($e.ID)] MISMATCH" -ForegroundColor Red }
        else { Write-Host "  [ID:$($e.ID)] OK" -ForegroundColor Green }
    }
    return
}

# -------------------------------------------------------------------------
# 6. APPLY MODE – create run folder + backup + apply
# -------------------------------------------------------------------------
$runId      = (Get-Date).ToString("yyyyMMdd_HHmmss")
$runFolder  = Join-Path $BackupRoot $runId
New-Item -ItemType Directory -Path $runFolder -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $runFolder "reg_files") -Force | Out-Null

$runLog = @()

foreach ($e in $sel) {
    $path = $e.Path; $name = $e.Name; $type = $TypeMap[$e.Type]; $id = $e.ID
    $value = $e.Value

    # ----- value conversion -----
    switch ($type) {
        "DWORD"       { $value = [uint32][int]$value }
        "QWORD"       { $value = [uint64][long]$value }
        "MultiString" { $value = $value -split "`n" }
    }

    # ----- ensure key exists -----
    if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }

    # ----- backup current state -----
    $cur = Get-RegValue $path $name
    $regFile = New-RegBackup $path $name $cur.Value $cur.Type $id $runFolder

    # ----- apply new value -----
    try {
        if ($name -eq "(Default)") { Set-Item $path -Value $value -Force }
        else { Set-ItemProperty $path -Name $name -Value $value -Type $type -Force }
        Write-Host "  [ID:$id] Applied" -ForegroundColor Green
    } catch { Write-Error "  [ID:$id] FAILED: $_" }

    # ----- log entry for this run -----
    $runLog += [pscustomobject]@{
        ID      = $id
        Path     = $path
        Name    = $name
        OldVal  = $cur.Value
        OldType = $cur.Type
        RegFile = $regFile
    }
}

# ----- Append run to global manifest -----
$Manifest += [pscustomobject]@{
    RunId     = $runId
    Timestamp = (Get-Date).ToString("o")
    XmlFile   = $XmlPath
    IDs       = $IDs
    Entries   = $runLog
}
$Manifest | ConvertTo-Json -Depth 10 | Set-Content $ManifestPath -Encoding UTF8

Write-Host "`nRun $runId saved. Manifest updated." -ForegroundColor Magenta
Write-Host "Rollback last run:  $($MyInvocation.MyCommand.Path) -XmlPath `"$XmlPath`" -Rollback" -ForegroundColor Yellow
Write-Host "Rollback specific:  -Rollback -RunId $runId" -ForegroundColor Yellow
