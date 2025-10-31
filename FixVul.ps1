<#
.SYNOPSIS
    Apply registry from XML – ONE manifest.xml for all runs.
    Appends every change, supports rollback by RunId.

.PARAMETER XmlPath     Path to the settings XML
.PARAMETER IDs         Comma-separated IDs or "all"
.PARAMETER Rollback    Restore last run (or use -RunId)
.PARAMETER RunId       Specific run to rollback
.PARAMETER VerifyOnly  Verify only
#>

param(
    [Parameter(Mandatory)][string]$XmlPath,
    [string]$IDs = "all",
    [switch]$Rollback,
    [string]$RunId,
    [switch]$VerifyOnly
)

# -------------------------------------------------------------------------
# 0. Paths & Admin Check
# -------------------------------------------------------------------------
$BaseDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$ManifestPath = Join-Path $BaseDir "manifest.xml"
$BackupRoot   = Join-Path $BaseDir "Backups"

# Ensure folders
foreach ($p in @($BaseDir, $BackupRoot)) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsPrincipal]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator"
}

# -------------------------------------------------------------------------
# 1. Helper Functions
# -------------------------------------------------------------------------
$TypeMap = @{"String"="String"; "ExpandString"="ExpandString"; "DWord"="DWORD"; "QWord"="QWORD"; "Binary"="Binary"; "MultiString"="MultiString"}

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
    } catch {}
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
# 2. Load / Create manifest.xml
# -------------------------------------------------------------------------
if (Test-Path $ManifestPath) {
    [xml]$ManifestXml = Get-Content $ManifestPath -Raw
    $ManifestNode = $ManifestXml.DocumentElement
} else {
    $xml = @"
<RegistryManifest>
  <!-- All runs are appended here -->
</RegistryManifest>
"@
    [xml]$ManifestXml = $xml
    $ManifestNode = $ManifestXml.DocumentElement
}

# -------------------------------------------------------------------------
# 3. ROLLBACK MODE
# -------------------------------------------------------------------------
if ($Rollback) {
    if (-not $ManifestNode.HasChildNodes) { throw "No runs in manifest.xml" }

    $runNode = if ($RunId) {
        $ManifestNode.Run | Where-Object { $_.RunId -eq $RunId }
    } else {
        $ManifestNode.Run | Select-Object -Last 1
    }

    if (-not $runNode) { throw "RunId $RunId not found in manifest.xml" }

    Write-Host "Rolling back RunId $($runNode.RunId) ($($runNode.Timestamp)) ..." -ForegroundColor Yellow
    foreach ($e in $runNode.Entry) {
        $regFile = $e.RegFile
        if (Test-Path $regFile) {
            Write-Host "  [ID:$($e.ID)] Importing $regFile" -ForegroundColor Cyan
            $out = reg import $regFile 2>&1
            if ($LASTEXITCODE -eq 0) { Write-Host "  Success" -ForegroundColor Green }
            else { Write-Warning "  FAILED: $out" }
        } else {
            Write-Warning "  [ID:$($e.ID)] Backup file missing: $regFile"
        }
    }
    Write-Host "Rollback complete." -ForegroundColor Green
    return
}

# -------------------------------------------------------------------------
# 4. Load Settings XML & Filter IDs
# -------------------------------------------------------------------------
[xml]$SettingsXml = Get-Content $XmlPath
$all = $SettingsXml.RegistrySettings.Entry
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
    if ($ok) { Write-Host "All verified." -ForegroundColor Green } else { Write-Host "Verification failed." -ForegroundColor Red }
    return
}

# -------------------------------------------------------------------------
# 6. APPLY MODE – create run + backup + apply + append to manifest.xml
# -------------------------------------------------------------------------
$runId     = (Get-Date).ToString("yyyyMMdd_HHmmss")
$runFolder = Join-Path $BackupRoot $runId
New-Item -ItemType Directory -Path $runFolder -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $runFolder "reg_files") -Force | Out-Null

$runNode = $ManifestXml.CreateElement("Run")
$runNode.SetAttribute("RunId", $runId)
$runNode.SetAttribute("Timestamp", (Get-Date).ToString("o"))
$runNode.SetAttribute("XmlFile", $XmlPath)
$runNode.SetAttribute("IDs", $IDs)

foreach ($e in $sel) {
    $path = $e.Path; $name = $e.Name; $type = $TypeMap[$e.Type]; $id = $e.ID
    $value = $e.Value

    # Convert value
    switch ($type) {
        "DWORD"       { $value = [uint32][int]$value }
        "QWORD"       { $value = [uint64][long]$value }
        "MultiString" { $value = $value -split "`n" }
    }

    # Ensure key
    if (-not (Test-Path $path)) { New-Item $path -Force | Out-Null }

    # Backup
    $cur = Get-RegValue $path $name
    $regFile = New-RegBackup $path $name $cur.Value $cur.Type $id $runFolder

    # Apply
    try {
        if ($name -eq "(Default)") { Set-Item $path -Value $value -Force }
        else { Set-ItemProperty $path -Name $name -Value $value -Type $type -Force }
        Write-Host "  [ID:$id] Applied" -ForegroundColor Green
    } catch { Write-Error "  [ID:$id] FAILED: $_" }

    # Add entry to run
    $entryNode = $ManifestXml.CreateElement("Entry")
    $entryNode.SetAttribute("ID", $id)
    $entryNode.SetAttribute("Path", $path)
    $entryNode.SetAttribute("Name", $name)
    $entryNode.SetAttribute("OldValue", ($cur.Value -is [array] ? ($cur.Value -join ',') : $cur.Value))
    $entryNode.SetAttribute("OldType", $cur.Type)
    $entryNode.SetAttribute("RegFile", $regFile)
    $runNode.AppendChild($entryNode) | Out-Null
}

# Append run to manifest
$ManifestNode.AppendChild($runNode) | Out-Null

# Save updated manifest.xml
$ManifestXml.Save($ManifestPath)

Write-Host "`nRun $runId saved to manifest.xml" -ForegroundColor Magenta
Write-Host "Rollback last:   $($MyInvocation.MyCommand.Path) -XmlPath `"$XmlPath`" -Rollback" -ForegroundColor Yellow
Write-Host "Rollback run:    -Rollback -RunId $runId" -ForegroundColor Yellow
