<#
.SYNOPSIS
  USB + Device Connection History (Read-Only) -> CSV + HTML + Console (PS 5.1)

.DESCRIPTION
  Collects USB device history with timestamps (best-effort):
    - SetupAPI device install sections (first-seen/install timestamps)
    - Event Logs (Kernel-PnP / DeviceSetupManager / DriverFrameworks) for connect-ish timestamps (when available)
    - Registry USBSTOR + USB keys for last-write (often approximates "last seen")

  Outputs:
    1) RawFindings CSV/HTML
    2) Summary CSV/HTML (deduped per device key, with FirstSeen/LastSeen)

.NOTES
  "ConnectedTime" timestamps depend on event log availability on the host.
#>

# ==========================
# CONFIGURATION (EDIT HERE)
# ==========================
$Config = [ordered]@{
  OutputFolder          = "C:\Inventory"
  BaseFileName          = "UsbHistory"
  CsvDelimiter          = ","
  VerboseOutput         = $true

  # SetupAPI log parsing (first-seen/install timestamps)
  ParseSetupApiLogs     = $true
  SetupApiLogPaths      = @(
    "$env:WINDIR\inf\setupapi.dev.log",
    "$env:WINDIR\setupapi.log"
  )

  # Event logs for connect-ish timestamps (best-effort)
  ParseUsbEventLogs     = $true
  EventLogLookbackDays  = 90
  MaxEventsPerLog       = 4000

  # Registry sources (last-write timestamps)
  ParseUsbStorRegistry  = $true
  ParseUsbRegistry      = $true

  # MountedDevices mapping is optional/noisy
  ParseMountedDevices   = $false

  # HTML report
  GenerateHtmlReport    = $true
  HtmlTitleRaw          = "USB History - Raw Findings"
  HtmlTitleSummary      = "USB History - Summary"

  ConsoleTopRaw         = 20
  ConsoleTopSummary     = 25
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

function ConvertTo-HtmlSafe {
  param([string]$Text)
  if ($null -eq $Text) { return "" }
  $t = [string]$Text
  $t = $t.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;").Replace("'","&#39;")
  return $t
}

function Coalesce-String {
  param([object]$Value, [string]$Fallback = "")
  if ($null -eq $Value) { return $Fallback }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Fallback }
  return $s
}

function Get-VidPidFromText {
  param([string]$Text)
  if (-not $Text) { return "" }
  $m = [regex]::Match($Text, "VID_([0-9A-Fa-f]{4}).*PID_([0-9A-Fa-f]{4})")
  if ($m.Success) { return ("VID_{0}&PID_{1}" -f $m.Groups[1].Value.ToUpper(), $m.Groups[2].Value.ToUpper()) }
  return ""
}

function Get-InstanceFromText {
  param([string]$Text)
  # Attempts to pull "USB\VID_xxxx&PID_yyyy\INSTANCE" style instance segments
  if (-not $Text) { return "" }
  $m = [regex]::Match($Text, "(USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}\\[^ \]\r\n]+)")
  if ($m.Success) { return $m.Groups[1].Value }
  return ""
}

function New-Finding {
  param(
    [string]$Source,
    [string]$FindingType,
    [string]$Device,
    [string]$VidPid,
    [string]$SerialOrInstance,
    $ConnectedTime,
    $LastWriteTime,
    [string]$Detail
  )
  [pscustomobject]@{
    ComputerName     = $env:COMPUTERNAME
    Source           = $Source
    FindingType      = $FindingType
    Device           = $Device
    VidPid           = $VidPid
    SerialOrInstance = $SerialOrInstance
    ConnectedTime    = $ConnectedTime
    LastWriteTime    = $LastWriteTime
    Detail           = $Detail
  }
}

function Get-DeviceKey {
  param([string]$VidPid, [string]$SerialOrInstance, [string]$Device)
  $vp = Coalesce-String $VidPid ""
  $si = Coalesce-String $SerialOrInstance ""
  $dv = Coalesce-String $Device ""
  if ($vp -or $si) { return ($vp + "|" + $si) }
  return ("DEVICE|" + $dv)
}

# ==========================
# 1) SETUPAPI LOG PARSER
# ==========================
function Parse-SetupApiUsbEvents {
  $out = New-Object System.Collections.Generic.List[object]
  if (-not $Config.ParseSetupApiLogs) { return $out }

  foreach ($path in $Config.SetupApiLogPaths) {
    if (-not (Test-Path $path)) { continue }

    Write-Log "Parsing SetupAPI log: $path"

    try {
      $lines = Get-Content -Path $path -ErrorAction Stop

      $currentInstance = $null
      $currentTime     = $null

      foreach ($line in $lines) {
        if ($line -match "^\s*>>>\s+\[Device Install.*-\s+(.+?)\]\s*$") {
          $currentInstance = $Matches[1].Trim()
          $currentTime = $null
          continue
        }

        if ($currentInstance -and $line -match "^\s*>>>\s+Section start\s+(\d{4}\/\d{2}\/\d{2})\s+(\d{2}:\d{2}:\d{2})") {
          $dtText = "$($Matches[1]) $($Matches[2])"
          try { $currentTime = [datetime]::ParseExact($dtText, "yyyy/MM/dd HH:mm:ss", $null) } catch { $currentTime = $null }
          continue
        }

        if ($currentInstance -and $line -match "^\s*<<<\s+\[Exit status") {
          $vidpid = Get-VidPidFromText -Text $currentInstance
          if ($vidpid) {
            $dev = ($currentInstance.Split('\')[0])
            $serial = ($currentInstance -split "\\", 3 | Select-Object -Last 1)
            $detail = "SetupAPI device install section: $currentInstance (Log=$path)"
            $out.Add( (New-Finding -Source "SetupAPI" -FindingType "DeviceInstall" -Device $dev -VidPid $vidpid -SerialOrInstance $serial -ConnectedTime $currentTime -LastWriteTime $null -Detail $detail) )
          }
          $currentInstance = $null
          $currentTime = $null
          continue
        }
      }
    } catch {
      $out.Add( (New-Finding -Source "SetupAPI" -FindingType "Error" -Device "" -VidPid "" -SerialOrInstance "" -ConnectedTime $null -LastWriteTime $null -Detail $_.Exception.Message) )
    }
  }

  return $out
}

# ==========================
# 2) EVENT LOGS (CONNECTED TIMESTAMPS)
# ==========================
function Get-UsbConnectionEvents {
  $out = New-Object System.Collections.Generic.List[object]
  if (-not $Config.ParseUsbEventLogs) { return $out }

  $since = (Get-Date).AddDays(-1 * [int]$Config.EventLogLookbackDays)
  Write-Log ("Parsing USB-related event logs (lookback {0} days)..." -f $Config.EventLogLookbackDays)

  # These logs/providers vary by Windows version; we try several and gracefully skip failures.
  $targets = @(
    @{ Kind="WinEvent"; Log="Microsoft-Windows-Kernel-PnP/Configuration";            Name="KernelPnP-Config" },
    @{ Kind="WinEvent"; Log="Microsoft-Windows-UserPnp/DeviceInstall";              Name="UserPnp-Install" },
    @{ Kind="WinEvent"; Log="Microsoft-Windows-DeviceSetupManager/Admin";           Name="DeviceSetup-Admin" },
    @{ Kind="WinEvent"; Log="Microsoft-Windows-DriverFrameworks-UserMode/Operational"; Name="WDFUM-Operational" }
  )

  foreach ($t in $targets) {
    $logName = $t.Log
    try {
      Write-Log "Reading log: $logName"
      $events = Get-WinEvent -FilterHashtable @{ LogName=$logName; StartTime=$since } -MaxEvents $Config.MaxEventsPerLog -ErrorAction Stop

      foreach ($e in $events) {
        $msg = Coalesce-String $e.Message ""
        # Look for USB instance references, VID/PID markers, or "USBSTOR"
        if ($msg -notmatch "VID_" -and $msg -notmatch "USBSTOR" -and $msg -notmatch "USB\\") { continue }

        $vidpid = Get-VidPidFromText -Text $msg
        $instFull = Get-InstanceFromText -Text $msg
        $inst = $instFull
        if (-not $inst) { $inst = "" }

        $detail = "Log=$logName EventID=$($e.Id) Provider=$($e.ProviderName)"
        $device = "USB event"

        $out.Add( (New-Finding -Source "EventLog" -FindingType "ConnectedEvent" -Device $device -VidPid $vidpid -SerialOrInstance $inst -ConnectedTime $e.TimeCreated -LastWriteTime $null -Detail $detail) )
      }
    } catch {
      # silently skip missing/disabled logs
      continue
    }
  }

  return $out
}

# ==========================
# 3) REGISTRY: USBSTOR
# ==========================
function Get-UsbStorRegistry {
  $out = New-Object System.Collections.Generic.List[object]
  if (-not $Config.ParseUsbStorRegistry) { return $out }

  $base = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
  if (-not (Test-Path $base)) { return $out }

  Write-Log "Reading registry: $base"

  try {
    Get-ChildItem -Path $base -ErrorAction Stop | ForEach-Object {
      $deviceName = Split-Path -Leaf $_.Name

      Get-ChildItem -Path $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
        $instKeyPath = $_.PSPath
        $instName = Split-Path -Leaf $_.Name

        $friendly = ""
        $mfg = ""
        $lw = $null

        try {
          $p = Get-ItemProperty -Path $instKeyPath -ErrorAction SilentlyContinue
          $friendly = Coalesce-String $p.FriendlyName ""
          $mfg      = Coalesce-String $p.Mfg ""
        } catch { }

        try { $lw = (Get-Item -Path $instKeyPath -ErrorAction Stop).LastWriteTime } catch { }

        $deviceDisplay = Coalesce-String $friendly $deviceName
        $detail = "USBSTOR Device=$deviceName Instance=$instName FriendlyName=$friendly Mfg=$mfg"
        $out.Add( (New-Finding -Source "Registry" -FindingType "USBStorageKey" -Device $deviceDisplay -VidPid "" -SerialOrInstance $instName -ConnectedTime $null -LastWriteTime $lw -Detail $detail) )
      }
    }
  } catch {
    $out.Add( (New-Finding -Source "Registry" -FindingType "Error" -Device "" -VidPid "" -SerialOrInstance "" -ConnectedTime $null -LastWriteTime $null -Detail $_.Exception.Message) )
  }

  return $out
}

# ==========================
# 4) REGISTRY: USB (VID/PID)
# ==========================
function Get-UsbRegistryVidPid {
  $out = New-Object System.Collections.Generic.List[object]
  if (-not $Config.ParseUsbRegistry) { return $out }

  $base = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
  if (-not (Test-Path $base)) { return $out }

  Write-Log "Reading registry: $base"

  try {
    Get-ChildItem -Path $base -ErrorAction Stop | ForEach-Object {
      $devNode = Split-Path -Leaf $_.Name
      $vidpid = Get-VidPidFromText -Text $devNode
      if (-not $vidpid) { return }

      Get-ChildItem -Path $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
        $instKeyPath = $_.PSPath
        $instName = Split-Path -Leaf $_.Name

        $friendly = ""
        $mfg = ""
        $lw = $null

        try {
          $p = Get-ItemProperty -Path $instKeyPath -ErrorAction SilentlyContinue
          $friendly = Coalesce-String $p.FriendlyName ""
          $mfg      = Coalesce-String $p.Mfg ""
        } catch { }

        try { $lw = (Get-Item -Path $instKeyPath -ErrorAction Stop).LastWriteTime } catch { }

        $deviceDisplay = Coalesce-String $friendly $devNode
        $detail = "USB VID/PID Node=$devNode Instance=$instName FriendlyName=$friendly Mfg=$mfg"
        $out.Add( (New-Finding -Source "Registry" -FindingType "USBKey" -Device $deviceDisplay -VidPid $vidpid -SerialOrInstance $instName -ConnectedTime $null -LastWriteTime $lw -Detail $detail) )
      }
    }
  } catch {
    $out.Add( (New-Finding -Source "Registry" -FindingType "Error" -Device "" -VidPid "" -SerialOrInstance "" -ConnectedTime $null -LastWriteTime $null -Detail $_.Exception.Message) )
  }

  return $out
}

# ==========================
# 5) SUMMARY (DEDUP + FIRST/LAST)
# ==========================
function Build-UsbSummary {
  param([Parameter(Mandatory)]$Findings)

  $groups = $Findings | Where-Object {
    $_.FindingType -ne "Error"
  } | Group-Object -Property @{
    Expression = {
      Get-DeviceKey -VidPid $_.VidPid -SerialOrInstance $_.SerialOrInstance -Device $_.Device
    }
  }

  $summary = foreach ($g in $groups) {
    $items = $g.Group

    $vidpid = ( $items | Where-Object { $_.VidPid } | Select-Object -ExpandProperty VidPid -First 1 )
    $ser   = ( $items | Where-Object { $_.SerialOrInstance } | Select-Object -ExpandProperty SerialOrInstance -First 1 )
    $dev   = ( $items | Where-Object { $_.Device } | Select-Object -ExpandProperty Device -First 1 )

    $times = @()
    $times += ($items | Where-Object { $_.ConnectedTime } | Select-Object -ExpandProperty ConnectedTime)
    $times += ($items | Where-Object { $_.LastWriteTime } | Select-Object -ExpandProperty LastWriteTime)

    $first = $null
    $last  = $null
    if ($times.Count -gt 0) {
      $first = ($times | Sort-Object | Select-Object -First 1)
      $last  = ($times | Sort-Object | Select-Object -Last 1)
    }

    $sources = ($items | Select-Object -ExpandProperty Source -Unique) -join ", "
    $types   = ($items | Select-Object -ExpandProperty FindingType -Unique) -join ", "

    [pscustomobject]@{
      ComputerName      = $env:COMPUTERNAME
      DeviceKey         = $g.Name
      Device            = $dev
      VidPid            = $vidpid
      SerialOrInstance  = $ser
      FirstSeenBest     = $first
      LastSeenBest      = $last
      Sources           = $sources
      EvidenceTypes     = $types
      EvidenceCount     = $items.Count
    }
  }

  return ($summary | Sort-Object LastSeenBest -Descending)
}

# ==========================
# HTML REPORT
# ==========================
function Export-HtmlTable {
  param(
    [Parameter(Mandatory)]$Rows,
    [Parameter(Mandatory)][string]$HtmlPath,
    [Parameter(Mandatory)][string]$Title
  )

  $titleEsc = ConvertTo-HtmlSafe $Title
  $genTime  = ConvertTo-HtmlSafe (Get-Date).ToString()
  $count    = ($Rows | Measure-Object).Count

  # Build header dynamically from properties
  $props = @()
  if ($count -gt 0) { $props = $Rows[0].PSObject.Properties.Name } else { $props = @("NoData") }

  $th = ($props | ForEach-Object { "<th onclick=""sortTable('$($_)')"">$($_)</th>" }) -join "`n        "

  $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>$titleEsc</title>
<style>
 body { font-family: Arial, sans-serif; margin: 20px; }
 h1 { margin-bottom: 6px; }
 .meta { color: #555; margin-bottom: 16px; }
 input { padding: 8px; width: 560px; max-width: 100%; margin: 10px 0 16px 0; }
 table { border-collapse: collapse; width: 100%; }
 th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
 th { cursor: pointer; background: #f5f5f5; position: sticky; top: 0; }
 tr:nth-child(even) { background: #fafafa; }
 code { white-space: pre-wrap; }
 .small { font-size: 12px; color: #666; }
</style>
</head>
<body>
<h1>$titleEsc</h1>
<div class="meta">Generated: $genTime<br>Rows: $count</div>
<input id="search" placeholder="Search…" onkeyup="filterTable()">
<table id="tbl">
<thead>
<tr>
        $th
</tr>
</thead>
<tbody>
"@

  foreach ($r in $Rows) {
    $cells = foreach ($p in $props) {
      $val = ""
      try { $val = $r.$p } catch { $val = "" }
      $valEsc = ConvertTo-HtmlSafe ([string]$val)
      "<td class='small'>$valEsc</td>"
    }
    $html += "<tr>`n" + ($cells -join "`n") + "`n</tr>`n"
  }

  $html += @"
</tbody>
</table>

<script>
function filterTable() {
  const input = document.getElementById("search").value.toLowerCase();
  const rows = document.querySelectorAll("#tbl tbody tr");
  rows.forEach(r => {
    const txt = r.innerText.toLowerCase();
    r.style.display = txt.includes(input) ? "" : "none";
  });
}

let sortState = {};
function sortTable(colName) {
  const table = document.getElementById("tbl");
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const idx = Array.from(table.tHead.rows[0].cells).findIndex(c => c.innerText === colName);
  const asc = !(sortState[colName] === "asc");
  sortState = {}; sortState[colName] = asc ? "asc" : "desc";

  rows.sort((a,b) => {
    const A = a.cells[idx].innerText.toLowerCase();
    const B = b.cells[idx].innerText.toLowerCase();
    if (A < B) return asc ? -1 : 1;
    if (A > B) return asc ? 1 : -1;
    return 0;
  });

  rows.forEach(r => tbody.appendChild(r));
}
</script>
</body>
</html>
"@

  Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}

# =================
# MAIN
# =================
Ensure-Folder -Path $Config.OutputFolder

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computer  = $env:COMPUTERNAME
$base      = "$($Config.BaseFileName)_$computer`_$timestamp"

$outRawCsv   = Join-Path $Config.OutputFolder "$base`_RawFindings.csv"
$outRawHtml  = Join-Path $Config.OutputFolder "$base`_RawReport.html"
$outSumCsv   = Join-Path $Config.OutputFolder "$base`_Summary.csv"
$outSumHtml  = Join-Path $Config.OutputFolder "$base`_Summary.html"

Write-Log "Starting USB history collection (read-only)..."
Write-Log "RAW CSV : $outRawCsv"
Write-Log "SUM CSV : $outSumCsv"
if ($Config.GenerateHtmlReport) {
  Write-Log "RAW HTML: $outRawHtml"
  Write-Log "SUM HTML: $outSumHtml"
}

$all = New-Object System.Collections.Generic.List[object]

(Parse-SetupApiUsbEvents) | ForEach-Object { $all.Add($_) }
(Get-UsbConnectionEvents) | ForEach-Object { $all.Add($_) }
(Get-UsbStorRegistry)     | ForEach-Object { $all.Add($_) }
(Get-UsbRegistryVidPid)   | ForEach-Object { $all.Add($_) }

$all | Sort-Object Source, FindingType, Device |
  Export-Csv -Path $outRawCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter

$summary = Build-UsbSummary -Findings $all
$summary | Export-Csv -Path $outSumCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter

if ($Config.GenerateHtmlReport) {
  Export-HtmlTable -Rows $all -HtmlPath $outRawHtml -Title $Config.HtmlTitleRaw
  Export-HtmlTable -Rows $summary -HtmlPath $outSumHtml -Title $Config.HtmlTitleSummary
}

Write-Host "`n================ USB HISTORY SUMMARY ================" -ForegroundColor Green
Write-Host "Computer: $computer"
Write-Host "Raw findings : $($all.Count)"
Write-Host "Devices (dedup): $($summary.Count)"
Write-Host "RAW CSV : $outRawCsv"
Write-Host "SUM CSV : $outSumCsv"
if ($Config.GenerateHtmlReport) { Write-Host "RAW HTML: $outRawHtml`nSUM HTML: $outSumHtml" }
Write-Host "----------------------------------------------------"

Write-Host "`nTop $($Config.ConsoleTopSummary) devices (best-effort First/Last seen):" -ForegroundColor Cyan
$summary |
  Select-Object -First $Config.ConsoleTopSummary Device, VidPid, SerialOrInstance, FirstSeenBest, LastSeenBest, Sources, EvidenceCount |
  Format-Table -AutoSize

Write-Host "`nTop $($Config.ConsoleTopRaw) raw entries:" -ForegroundColor Cyan
$all |
  Select-Object -First $Config.ConsoleTopRaw Source, FindingType, VidPid, SerialOrInstance, ConnectedTime, LastWriteTime |
  Format-Table -AutoSize

Write-Host "====================================================" -ForegroundColor Green
Write-Log "Done."
