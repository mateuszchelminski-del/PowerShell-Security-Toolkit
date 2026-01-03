<#
.SYNOPSIS
  Local Software Inventory (2 CSVs): AppX + Non-Microsoft (Win32)

.DESCRIPTION
  Exports:
   1) All AppX packages (UWP/Store apps) to CSV
   2) All NON-MICROSOFT installed software (classic/Win32) to CSV

  Uses registry uninstall keys (HKLM + WOW6432Node + HKCU) to collect Win32 apps.
  Filters Microsoft items using publisher/name heuristics (customizable).

.NOTES
  Run in PowerShell 5.1+ or PowerShell 7+ on Windows.
#>

# ==========================
# CONFIGURATION (EDIT HERE)
# ==========================
$Config = [ordered]@{
  OutputFolder              = "C:\Inventory"
  BaseFileName              = "SoftwareInventory"
  CsvDelimiter              = ","
  VerboseOutput             = $true

  # AppX scope:
  AppxAllUsers              = $false   # $true requires admin; otherwise current user only

  # Non-Microsoft filtering (tune to your environment)
  ExcludePublishersContains  = @(
    "Microsoft", "Microsoft Corporation", "Microsoft Windows", "Windows", "Microsoft Edge",
    "Teams Machine-Wide Installer" # optional, keep/remove
  )
  ExcludeNamesContains       = @(
    "Microsoft", "Windows", "Edge", "Visual C++", "VC++", ".NET", "Update for", "Hotfix",
    "Security Update", "Cumulative Update", "KB", "Windows SDK"
  )

  # Optional: keep entries with blank publisher?
  KeepBlankPublisher         = $true

  # Optional: de-duplicate results
  Deduplicate                = $true
}

# =================
# HELPER FUNCTIONS
# =================
function Write-Log {
  param([string]$Message)
  if ($Config.VerboseOutput) { Write-Host "[*] $Message" -ForegroundColor Cyan }
}

function Ensure-Folder {
  param([string]$Path)
  if (-not (Test-Path -Path $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Write-Log "Created folder: $Path"
  }
}

function Test-ContainsAny {
  param(
    [Parameter(Mandatory)] [string]$Value,
    [Parameter(Mandatory)] [string[]]$Needles
  )
  foreach ($n in $Needles) {
    if ($Value -like "*$n*") { return $true }
  }
  return $false
}

function Get-PSProp {
  <#
    Safe property fetch that won't throw if the property doesn't exist
    (important when PowerShell is in strict property access mode).
  #>
  param(
    [Parameter(Mandatory)] [object]$Obj,
    [Parameter(Mandatory)] [string]$Name
  )
  $p = $Obj.PSObject.Properties[$Name]
  if ($null -ne $p) { return $p.Value }
  return $null
}

# ==========================
# INVENTORY FUNCTIONS
# ==========================
function Get-AppxInventory {
  $computer = $env:COMPUTERNAME
  if ($Config.AppxAllUsers) {
    Write-Log "Collecting AppX packages (All Users)..."
    $pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
  } else {
    Write-Log "Collecting AppX packages (Current User)..."
    $pkgs = Get-AppxPackage -ErrorAction SilentlyContinue
  }

  $pkgs | ForEach-Object {
    [pscustomobject]@{
      ComputerName      = $computer
      Name              = $_.Name
      PackageFullName   = $_.PackageFullName
      Publisher         = $_.Publisher
      Version           = $_.Version.ToString()
      InstallLocation   = $_.InstallLocation
      Architecture      = $_.Architecture
      IsFramework       = $_.IsFramework
      IsResourcePackage = $_.IsResourcePackage
    }
  } | Sort-Object Name, Version
}

function Get-Win32InstalledSoftware {
  # Reads classic installed apps from Uninstall registry keys
  $computer = $env:COMPUTERNAME
  $paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  Write-Log "Collecting Win32 installed software from registry (HKLM/HKCU)..."

  $raw = foreach ($p in $paths) {
    $scope = if ($p -like "HKLM:*") { "Machine" } else { "User" }

    Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
      Where-Object {
        $dn = [string](Get-PSProp -Obj $_ -Name "DisplayName")
        -not [string]::IsNullOrWhiteSpace($dn)
      } |
      ForEach-Object {
        [pscustomobject]@{
          ComputerName     = $computer
          Name             = [string](Get-PSProp -Obj $_ -Name "DisplayName")
          Version          = [string](Get-PSProp -Obj $_ -Name "DisplayVersion")
          Publisher        = [string](Get-PSProp -Obj $_ -Name "Publisher")
          InstallDate      = [string](Get-PSProp -Obj $_ -Name "InstallDate")
          InstallLocation  = [string](Get-PSProp -Obj $_ -Name "InstallLocation")
          UninstallString  = [string](Get-PSProp -Obj $_ -Name "UninstallString")
          Scope            = $scope
          RegistryPath     = $p.Replace("*","")
        }
      }
  }

  # Filter to NON-Microsoft (heuristics you can tune)
  $filtered = $raw | Where-Object {
    $name = [string]$_.Name
    $pub  = [string]$_.Publisher

    if (-not $Config.KeepBlankPublisher -and [string]::IsNullOrWhiteSpace($pub)) { return $false }

    # Exclude if publisher looks like Microsoft
    if (-not [string]::IsNullOrWhiteSpace($pub) -and (Test-ContainsAny -Value $pub -Needles $Config.ExcludePublishersContains)) {
      return $false
    }

    # Exclude if name looks Microsoft/system component
    if (Test-ContainsAny -Value $name -Needles $Config.ExcludeNamesContains) {
      return $false
    }

    return $true
  }

  if ($Config.Deduplicate) {
    # Deduplicate by Name + Version + Scope (common duplicates across keys)
    $filtered = $filtered | Sort-Object Name, Version, Scope -Unique
  }

  $filtered | Sort-Object Name, Version
}

# =================
# MAIN
# =================
Ensure-Folder -Path $Config.OutputFolder

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computer  = $env:COMPUTERNAME
$base      = "$($Config.BaseFileName)_$computer`_$timestamp"

$appxCsv   = Join-Path $Config.OutputFolder "$base`_AppX.csv"
$nonMsCsv  = Join-Path $Config.OutputFolder "$base`_NonMicrosoft_Win32.csv"

# --- Collect + Export AppX ---
$appx = Get-AppxInventory
$appx | Export-Csv -Path $appxCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter
Write-Log "Wrote AppX CSV: $appxCsv"

# --- Collect + Export Non-Microsoft Win32 ---
$nonMs = Get-Win32InstalledSoftware
$nonMs | Export-Csv -Path $nonMsCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter
Write-Log "Wrote Non-Microsoft Win32 CSV: $nonMsCsv"

#==========================
#CONSOLE SUMMARY
#==========================
Write-Host "`n================ SOFTWARE INVENTORY SUMMARY ================" -ForegroundColor Green
Write-Host "Computer: $computer"
Write-Host "AppX packages exported: $($appx.Count)  -> $appxCsv"
Write-Host "Non-Microsoft Win32 apps exported: $($nonMs.Count) -> $nonMsCsv"

Write-Host "`nTop Non-Microsoft (first 15):" -ForegroundColor Yellow
$nonMs | Select-Object -First 15 Name, Version, Publisher, Scope | Format-Table -AutoSize

Write-Host "===========================================================" -ForegroundColor Green
