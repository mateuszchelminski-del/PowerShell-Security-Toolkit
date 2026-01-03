<#
.SYNOPSIS
  Credential Hygiene Scanner (Read-Only) -> CSV + Console Report

.DESCRIPTION
  Read-only endpoint hygiene checks focused on credential exposure risks:
    1) Cached credentials (Credential Manager targets only; NO secrets)
    2) Plaintext credential "smells" in files (regex-based; DOES NOT print values)
    3) Browser password store presence (file presence only; DOES NOT read contents)
    4) VPN profile/config presence (presence + last modified; DOES NOT extract secrets)

  Exports findings to a single CSV for review.
  change line 23 if neceesary   OutputFolder        = "C:\Inventory"

.NOTES
  PowerShell 5.1+ recommended.
#>

# ==========================
# CONFIGURATION (EDIT HERE)
# ==========================
$Config = [ordered]@{
  OutputFolder        = "C:\Inventory"
  BaseFileName        = "CredentialHygiene"
  CsvDelimiter        = ","
  VerboseOutput       = $true

  #File scanning scope
  ScanRoots           = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads"
  )

  #Exclusions (folders)
  ExcludeDirsContains = @(
    "\node_modules\", "\.git\", "\venv\", "\.venv\", "\__pycache__\",
    "\AppData\Local\Packages\", "\AppData\Local\Temp\", "\AppData\Roaming\Code\Cache\"
  )

  #File filters
  IncludeExtensions   = @(".txt",".log",".ini",".conf",".cfg",".env",".yml",".yaml",".json",".xml",".ps1",".psm1",".py",".js",".ts",".java",".cs",".php",".rb",".go",".sql",".md")
  MaxFileSizeMB       = 5
  MaxFilesToScan      = 2000   #safety cap to avoid scanning forever

  #Cached creds output safety
  RedactUsernames     = $true  #keeps only domain/user initial, not full username

  #If you want a stricter "non-sensitive" mode, set this $true
  DoNotReportLineNums = $false #if $true, we won't store line numbers
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

function Should-ExcludePath {
  param([string]$FullPath)
  foreach ($needle in $Config.ExcludeDirsContains) {
    if ($FullPath -like "*$needle*") { return $true }
  }
  return $false
}

function Redact-Username {
  param([string]$User)
  if (-not $Config.RedactUsernames) { return $User }
  if ([string]::IsNullOrWhiteSpace($User)) { return $User }

  #Examples:
  #DOMAIN\jdoe -> DOMAIN\j***
  #jdoe@domain.com -> j***@domain.com
  if ($User -match "^(?<dom>[^\\]+)\\(?<u>.+)$") {
    $dom = $Matches.dom
    $u   = $Matches.u
    $first = $u.Substring(0,1)
    return "$dom\$first***"
  }
  if ($User -match "^(?<u>[^@]+)@(?<d>.+)$") {
    $u = $Matches.u
    $d = $Matches.d
    $first = $u.Substring(0,1)
    return "$first***@$d"
  }
  return ($User.Substring(0,1) + "***")
}

# ==========================
# PATTERNS (NO VALUE OUTPUT)
# ==========================
#We deliberately do NOT capture/print the actual secret values.
$Patterns = @(
  @{ Name="password_assignment"; Regex="(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*.+$" }
  @{ Name="api_key_assignment";  Regex="(?i)\b(api[_-]?key|apikey|token|secret|client[_-]?secret)\b\s*[:=]\s*.+$" }
  @{ Name="aws_access_key";      Regex="AKIA[0-9A-Z]{16}" }
  @{ Name="private_key_block";   Regex="-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----" }
  @{ Name="basic_auth_url";      Regex="(?i)https?:\/\/[^\/\s]+:[^\/\s]+@[^\/\s]+" }
  @{ Name="connection_string";   Regex="(?i)\b(Server|Data Source)\s*=\s*[^;]+;.*\b(Password|Pwd)\s*=\s*[^;]+;" }
)

#==========================
#CHECK 1: CACHED CREDS (targets only)
#==========================
function Get-CachedCredentialTargets {
  $computer = $env:COMPUTERNAME
  $findings = New-Object System.Collections.Generic.List[object]

  Write-Log "Checking cached credentials (Credential Manager targets only)..."

  try {
    $out = cmdkey /list 2>$null
    if (-not $out) { return $findings }

    $currentTarget = $null
    $currentUser   = $null

    foreach ($line in $out) {
      if ($line -match "^\s*Target:\s*(.+)\s*$") {
        #commit previous
        if ($currentTarget) {
          $findings.Add([pscustomobject]@{
            ComputerName = $computer
            FindingType  = "CachedCredential"
            Name         = "CredentialManagerTarget"
            Detail       = $currentTarget
            Location     = "cmdkey"
            Line         = $null
            Risk         = "Medium"
            Notes        = ("User=" + (Redact-Username $currentUser))
          })
        }
        $currentTarget = $Matches[1].Trim()
        $currentUser   = $null
        continue
      }
      if ($line -match "^\s*User:\s*(.+)\s*$") {
        $currentUser = $Matches[1].Trim()
        continue
      }
    }

    #commit last
    if ($currentTarget) {
      $findings.Add([pscustomobject]@{
        ComputerName = $computer
        FindingType  = "CachedCredential"
        Name         = "CredentialManagerTarget"
        Detail       = $currentTarget
        Location     = "cmdkey"
        Line         = $null
        Risk         = "Medium"
        Notes        = ("User=" + (Redact-Username $currentUser))
      })
    }
  } catch {
    $findings.Add([pscustomobject]@{
      ComputerName = $env:COMPUTERNAME
      FindingType  = "Error"
      Name         = "CachedCredentialCheckFailed"
      Detail       = $_.Exception.Message
      Location     = "cmdkey"
      Line         = $null
      Risk         = "Info"
      Notes        = "Could not query cached credentials."
    })
  }

  return $findings
}

#==========================
#CHECK 2: PLAINTEXT "SMELLS" IN FILES (no values)
#==========================
function Find-PlaintextCredentialSmells {
  $computer = $env:COMPUTERNAME
  $findings = New-Object System.Collections.Generic.List[object]

  Write-Log "Scanning files for plaintext credential patterns (no value output)..."
  $scanned = 0

  foreach ($root in $Config.ScanRoots) {
    if (-not (Test-Path $root)) { continue }

    #Enumerate candidate files
    $files = Get-ChildItem -Path $root -File -Recurse -ErrorAction SilentlyContinue |
      Where-Object {
        -not (Should-ExcludePath $_.FullName) -and
        ($Config.IncludeExtensions -contains $_.Extension.ToLower()) -and
        ($_.Length -le ($Config.MaxFileSizeMB * 1MB))
      }

    foreach ($f in $files) {
      if ($scanned -ge $Config.MaxFilesToScan) { break }
      $scanned++

      foreach ($p in $Patterns) {
        try {
          $hits = Select-String -Path $f.FullName -Pattern $p.Regex -AllMatches -ErrorAction SilentlyContinue
          if ($hits) {
            foreach ($h in $hits) {
              $findings.Add([pscustomobject]@{
                ComputerName = $computer
                FindingType  = "PlaintextSmell"
                Name         = $p.Name
                Detail       = "Pattern match (value redacted)"
                Location     = $f.FullName
                Line         = $(if ($Config.DoNotReportLineNums) { $null } else { $h.LineNumber })
                Risk         = "High"
                Notes        = "Review file; do not store secrets in plaintext."
              })
            }
          }
        } catch {
          #ignore per-file errors
        }
      }
    }

    if ($scanned -ge $Config.MaxFilesToScan) { break }
  }

  Write-Log "File scan complete. Files scanned: $scanned (cap: $($Config.MaxFilesToScan))"
  return $findings
}

#==========================
#CHECK 3: BROWSER PASSWORD STORE PRESENCE (no reading)
#==========================
function Get-BrowserPasswordStorePresence {
  $computer = $env:COMPUTERNAME
  $findings = New-Object System.Collections.Generic.List[object]

  Write-Log "Checking browser password store presence (file existence only)..."

  $pathsToCheck = @(
    @{ Name="Chrome Login Data"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" }
    @{ Name="Edge Login Data";   Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" }
    @{ Name="Brave Login Data";  Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data" }
    @{ Name="Firefox logins.json"; Path="$env:APPDATA\Mozilla\Firefox\Profiles" } # we’ll detect profiles below
  )

  foreach ($item in $pathsToCheck) {
    if ($item.Name -eq "Firefox logins.json") {
      if (Test-Path $item.Path) {
        Get-ChildItem $item.Path -Directory -ErrorAction SilentlyContinue | ForEach-Object {
          $fx = Join-Path $_.FullName "logins.json"
          if (Test-Path $fx) {
            $findings.Add([pscustomobject]@{
              ComputerName = $computer
              FindingType  = "BrowserStorePresence"
              Name         = "Firefox logins.json"
              Detail       = "Password store file present (not read)"
              Location     = $fx
              Line         = $null
              Risk         = "Low"
              Notes        = "Consider master password / OS account protections."
            })
          }
        }
      }
      continue
    }

    if (Test-Path $item.Path) {
      $findings.Add([pscustomobject]@{
        ComputerName = $computer
        FindingType  = "BrowserStorePresence"
        Name         = $item.Name
        Detail       = "Password store DB present (not read)"
        Location     = $item.Path
        Line         = $null
        Risk         = "Low"
        Notes        = "Presence only; script does not access contents."
      })
    }
  }

  return $findings
}

#==========================
#CHECK 4: VPN PROFILES / CONFIG PRESENCE (no extraction)
#==========================
function Get-VpnProfilePresence {
  $computer = $env:COMPUTERNAME
  $findings = New-Object System.Collections.Generic.List[object]

  Write-Log "Checking VPN profile/config presence (file presence only)..."

  $vpnItems = @(
    @{ Name="Windows RAS phonebook (User)"; Path="$env:APPDATA\Microsoft\Network\Connections\Pbk\rasphone.pbk" }
    @{ Name="Windows RAS phonebook (Machine)"; Path="$env:ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk" }
    @{ Name="OpenVPN configs (common)"; Path="$env:ProgramFiles\OpenVPN\config" }
    @{ Name="WireGuard configs (common)"; Path="$env:ProgramFiles\WireGuard\Data\Configurations" }
    @{ Name="Cisco AnyConnect profiles (common)"; Path="$env:ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile" }
  )

  foreach ($v in $vpnItems) {
    if (Test-Path $v.Path) {
      $lastWrite = $null
      try { $lastWrite = (Get-Item $v.Path -ErrorAction SilentlyContinue).LastWriteTime } catch {}

      $findings.Add([pscustomobject]@{
        ComputerName = $computer
        FindingType  = "VpnProfilePresence"
        Name         = $v.Name
        Detail       = "Config/profile present (not read)"
        Location     = $v.Path
        Line         = $null
        Risk         = "Info"
        Notes        = ("LastWrite=" + $lastWrite)
      })
    }
  }

  return $findings
}

#=================
#MAIN
#=================
Ensure-Folder -Path $Config.OutputFolder
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computer  = $env:COMPUTERNAME
$outCsv    = Join-Path $Config.OutputFolder "$($Config.BaseFileName)_$computer`_$timestamp`_Findings.csv"

Write-Log "Starting credential hygiene scan (read-only)..."
Write-Log "Output CSV: $outCsv"

$allFindings = New-Object System.Collections.Generic.List[object]
(Get-CachedCredentialTargets)            | ForEach-Object { $allFindings.Add($_) }
(Find-PlaintextCredentialSmells)         | ForEach-Object { $allFindings.Add($_) }
(Get-BrowserPasswordStorePresence)       | ForEach-Object { $allFindings.Add($_) }
(Get-VpnProfilePresence)                | ForEach-Object { $allFindings.Add($_) }

#Export
$allFindings |
  Sort-Object FindingType, Name, Location |
  Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter

#==========================
#CONSOLE REPORT
#==========================
Write-Host "`n================ CREDENTIAL HYGIENE REPORT ================" -ForegroundColor Green
Write-Host "Computer: $computer"
Write-Host "Findings exported to: $outCsv"
Write-Host "Scan roots: $($Config.ScanRoots -join ', ')"
Write-Host "----------------------------------------------------------"

$grouped = $allFindings | Group-Object FindingType | Sort-Object Name
foreach ($g in $grouped) {
  Write-Host ("{0,-22} : {1}" -f $g.Name, $g.Count) -ForegroundColor Yellow
}

Write-Host "`nTop findings (first 20):" -ForegroundColor Cyan
$allFindings |
  Select-Object -First 20 FindingType, Name, Risk, Location, Line |
  Format-Table -AutoSize

Write-Host "==========================================================" -ForegroundColor Green
Write-Log "Done."
