<#
.SYNOPSIS
    Applies selected registry settings from XML by ID with backup & verification.

.PARAMETER XmlPath
    Path to the XML configuration file.

.PARAMETER IDs
    Comma-separated list of Entry IDs to apply (e.g., "1,3,5"). Use "all" for all entries.

.PARAMETER Rollback
    Rollback the last applied change (uses latest backup).

.PARAMETER VerifyOnly
    Verify only the selected entries match expected values.

.NOTES
    Requires Administrator. Backs up per-run with timestamp.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$XmlPath,

    [string]$IDs = "all",

    [switch]$Rollback,
    [switch]$VerifyOnly
)

# === Admin Check ===
function Test-Administrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Administrator)) {
    throw "This script must be run as Administrator."
}

# === Backup Setup ===
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir = Join-Path $ScriptDir "RegistryBackup_$Timestamp"
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}
$BackupManifest = Join-Path $BackupDir "backup_manifest.json"
$BackupLog = @()

# === Type Mapping ===
$TypeMap = @{
    "String"       = "String"
    "ExpandString" = "ExpandString"
    "DWord"        = "DWORD"
    "QWord"        = "QWORD"
    "Binary"       = "Binary"
    "MultiString"  = "MultiString"
}

# === Helper Functions ===
function Convert-Hive { param([string]$Path)
    $map = @{
        "HKLM:" = "HKEY_LOCAL_MACHINE"
        "HKCU:" = "HKEY_CURRENT_USER"
        "HKCR:" = "HKEY_CLASSES_ROOT"
        "HKU:"  = "HKEY_USERS"
        "HKCC:" = "HKEY_CURRENT_CONFIG"
    }
    foreach ($k in $map.Keys) { if ($Path -like "$k*") { return $Path -replace "^$([regex]::Escape($k))", $map[$k] } }
    return $Path
}

function Split-RegistryPath { param([string]$Path)
    $hive = $Path -replace '^([^\\]+)\\.*$', '$1'
    $subKey = $Path -replace '^[^\\]+\\', ''
    return @{ Hive = $hive; SubKey = $subKey }
}

function Get-RegistryValueSafe { param($Path, $Name)
    try {
        $item = Get-Item -Path $Path -ErrorAction SilentlyContinue
        if ($item) {
            if ($Name -eq "(Default)") {
                return $item.GetValue("", $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            } else {
                return $item.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
    } catch { }
    return $null
}

function Backup-RegistryValue { param($Path, $Name, $Value, $Type, $ID)
    $entry = @{
        ID    = $ID
        Path  = $Path
        Name  = $Name
        Value = $Value
        Type  = $Type
        Timestamp = Get-Date -Format "o"
    }
    $BackupLog += $entry

    $safeName = if ($Name -eq "(Default)") { "Default" } else { $Name -replace '[\\/:*?"<>|]', '_' }
    $fileName = "$ID`_$([Convert-Hive $Path] -replace '[:\\]', '_')_$safeName.reg"
    $backupFile = Join-Path $BackupDir $fileName

    $regLines = @("Windows Registry Editor Version 5.00", "", "[$([Convert-Hive $Path)])")

    if ($Name -eq "(Default)") {
        $valStr = if ($null -eq $Value) { '@=""' } else { "@=`"$Value`"" }
        $regLines += $valStr
    }
    elseif ($Type -eq "DWORD") {
        $hex = "dword:{0:x8}" -f $Value
        $regLines += "`"$Name`"=$hex"
    }
    elseif ($Type -eq "QWORD") {
        $bytes = [BitConverter]::GetBytes([uint64]$Value)
        $hex = "hex(b):" + ($bytes | ForEach-Object { $_.ToString("x2") } -join ',')
        $regLines += "`"$Name`"=$hex"
    }
    elseif ($Type -eq "Binary") {
        $hex = "hex:" + ($Value | ForEach-Object { $_.ToString("x2") } -join ',')
        $regLines += "`"$Name`"=$hex"
    }
    elseif ($Type -eq "MultiString") {
        $escaped = ($Value -join "`0") -replace '\\', '\\'
        $regLines += "`"$Name`"=hex(7):" + [BitConverter]::ToString([Text.Encoding]::Unicode.GetBytes($escaped + "`0`0")) -replace '-',''
    }
    else {
        $regLines += "`"$Name`"=`"$Value`""
    }

    $regLines | Out-File -FilePath $backupFile -Encoding ASCII
}

function Restore-FromBackup {
    if (-not (Test-Path $BackupManifest)) {
        throw "No backup manifest found in $BackupDir"
    }
    $manifest = Get-Content $BackupManifest -Raw | ConvertFrom-Json
    Write-Host "Rolling back $($manifest.Count) entries..." -ForegroundColor Yellow
    foreach ($e in $manifest) {
        try {
            $path = "$($e.Path)"
            if ($null -eq $e.Value -and $e.Name -ne "(Default)") {
                Remove-ItemProperty -Path $path -Name $e.Name -ErrorAction SilentlyContinue
            } else {
                Set-ItemProperty -Path $path -Name $e.Name -Value $e.Value -Type $e.Type -Force -ErrorAction Stop
            }
            Write-Host "  [ID:$($e.ID)] Restored: $path\$($e.Name)" -ForegroundColor Green
        } catch {
            Write-Warning "  [ID:$($e.ID)] Failed restore: $_"
        }
    }
}

# === Main Logic ===
try {
    if (-not (Test-Path $XmlPath)) { throw "XML file not found: $XmlPath" }
    [xml]$xml = Get-Content $XmlPath
    $allEntries = $xml.RegistrySettings.Entry

    if ($allEntries.Count -eq 0) { throw "No entries found in XML." }

    # Parse IDs
    $selectedIDs = if ($IDs -eq "all") {
        $allEntries | ForEach-Object { $_.ID }
    } else {
        $IDs -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    $entries = $allEntries | Where-Object { $_.ID -in $selectedIDs }

    if ($entries.Count -eq 0) {
        throw "No entries found matching IDs: $IDs"
    }

    Write-Host "Selected $($entries.Count) entr$(if($entries.Count -eq 1){'y'}else{'ies'}) [IDs: $($selectedIDs -join ', ')]" -ForegroundColor Cyan

    # === Rollback Mode ===
    if ($Rollback) {
        Restore-FromBackup
        return
    }

    # === Verify Only Mode ===
    if ($VerifyOnly) {
        Write-Host "Verifying selected entries..." -ForegroundColor Cyan
        $allGood = $true
        foreach ($e in $entries) {
            $path = "$($e.Path)"
            $current = Get-RegistryValueSafe -Path $path -Name $e.Name
            $expected = $e.Value
            $type = $TypeMap[$e.Type]

            if ($type -match "DWord|QWord") { $expected = [int64]$expected }

            $match = if ($null -eq $current -and $null -eq $expected) { $true }
                     elseif ($null -eq $current -or $null -eq $expected) { $false }
                     else { $current -eq $expected }

            if (-not $match) {
                $allGood = $false
                Write-Host "  [ID:$($e.ID)] MISMATCH: $path\$($e.Name) = '$current' (expected '$expected')" -ForegroundColor Red
            } else {
                Write-Host "  [ID:$($e.ID)] OK: $path\$($e.Name)" -ForegroundColor Green
            }
        }
        if ($allGood) { Write-Host "Verification passed." -ForegroundColor Green }
        else { Write-Host "Verification failed." -ForegroundColor Red }
        return
    }

    # === Apply Mode ===
    Write-Host "Applying selected entries..." -ForegroundColor Cyan

    foreach ($e in $entries) {
        $path = "$($e.Path)"
        $name = $e.Name
        $type = $TypeMap[$e.Type]
        $value = $e.Value
        $id = $e.ID

        if (-not $type) {
            Write-Warning "Unknown type '$($e.Type)' for ID:$id - skipping"
            continue
        }

        # Convert value
        switch ($type) {
            "DWORD"  { $value = [uint32][int]$value }
            "QWORD"  { $value = [uint64][long]$value }
            "Binary" { $value = [ b ]($value -split '(?<=\G..)' | ForEach-Object { [Convert]::ToByte($_,16) }) }
            "MultiString" { $value = $value -split "`n" }
        }

        # Ensure path exists
        $fullPath = $path
        if (-not (Test-Path $fullPath)) {
            try {
                New-Item -Path $fullPath -Force | Out-Null
                Write-Host "  [ID:$id] Created path: $fullPath" -ForegroundColor Yellow
            } catch {
                Write-Error "Failed to create path: $_"
                continue
            }
        }

        # Backup current value (only once per entry per run)
        $currentVal = Get-RegistryValueSafe -Path $fullPath -Name $name
        $currentType = if ($currentVal -ne $null -and $name -ne "(Default)") {
            (Get-Item $fullPath).GetValueKind($name)
        } else { $type }

        $alreadyBacked = $BackupLog | Where-Object { $_.ID -eq $id }
        if (-not $alreadyBacked) {
            Backup-RegistryValue -Path $fullPath -Name $name -Value $currentVal -Type $currentType -ID $id
        }

        # Apply value
        try {
            if ($name -eq "(Default)") {
                Set-Item -Path $fullPath -Value $value -Force
            } else {
                Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
            }
            Write-Host "  [ID:$id] Set: $fullPath\$name = $value" -ForegroundColor Green
        } catch {
            Write-Error "Failed to set [ID:$id]: $_"
        }
    }

    # Save manifest
    $BackupLog | ConvertTo-Json -Depth 10 | Out-File $BackupManifest -Encoding UTF8
    Write-Host "`nBackup saved: $BackupDir" -ForegroundColor Magenta
    Write-Host "Apply only IDs: $($MyInvocation.MyCommand.Path) -XmlPath `"$XmlPath`" -IDs `"1,3`"" -ForegroundColor Yellow
    Write-Host "Verify:         -VerifyOnly -IDs `"2,4`"" -ForegroundColor Yellow
    Write-Host "Rollback last:  -Rollback" -ForegroundColor Yellow

} catch {
    Write-Error "Script error: $_"
    exit 1
}
