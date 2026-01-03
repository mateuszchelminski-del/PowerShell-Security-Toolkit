<#
.SYNOPSIS
  Attack Surface Mapper (Read-Only) -> CSV + HTML + Console
.Prerequisites
  Have C:\Inventory or change OutputFolder = value
.DESCRIPTION
  Maps common local endpoint exposure points:
    - Listening TCP ports + owning process/service (best-effort)
    - Public firewall "Allow" rules
    - SMB shares (non-default highlighted)
    - RDP enabled status
    - WinRM enabled status
#>

# ==========================
# CONFIGURATION (EDIT HERE)
# ==========================
$Config = [ordered]@{
  OutputFolder       = "C:\Inventory"
  BaseFileName       = "AttackSurface"
  CsvDelimiter       = ","
  VerboseOutput      = $true

  # Listening ports
  IncludeUdp         = $false     # TCP is the key exposure signal; UDP optional
  IncludeLoopback    = $false     # if $false, filters 127.0.0.1/::1 listeners
  IncludeIPv6        = $true

  # Firewall rules
  OnlyPublicProfile  = $true      # only show Public profile rules
  OnlyAllowRules     = $true      # only Allow rules

  # SMB shares
  HideDefaultShares  = $true      # hides ADMIN$, C$, IPC$ by default

  # HTML
  GenerateHtmlReport = $true
  HtmlTitle          = "Attack Surface Mapper Report"
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

function BoolText($b) {
  if ($b -eq $true) { return "Yes" }
  if ($b -eq $false) { return "No" }
  return ""
}

function New-Finding {
  param(
    [string]$FindingType,
    [string]$Name,
    [string]$Risk,
    [string]$Detail,
    [string]$Location,
    [string]$Notes = ""
  )
  [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    FindingType  = $FindingType
    Name         = $Name
    Risk         = $Risk
    Detail       = $Detail
    Location     = $Location
    Notes        = $Notes
  }
}

# ==========================
# 1) LISTENING PORTS
# ==========================
function Get-ListeningPorts {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Collecting listening ports (TCP$(if($Config.IncludeUdp){'+UDP'}else{''}))..."

  #TCP listeners
  $tcp = @()
  try {
    $tcp = Get-NetTCPConnection -State Listen -ErrorAction Stop
  } catch {
    $findings.Add((New-Finding -FindingType "Error" -Name "Get-NetTCPConnectionFailed" -Risk "Info" -Detail $_.Exception.Message -Location "Get-NetTCPConnection"))
    return $findings
  }

  foreach ($c in $tcp) {
    $addr = $c.LocalAddress

    if (-not $Config.IncludeLoopback) {
      if ($addr -eq "127.0.0.1" -or $addr -eq "::1") { continue }
    }
    if (-not $Config.IncludeIPv6) {
      if ($addr -like "*:*") { continue }
    }

    $OwningPid = $c.OwningProcess
    $pname = "Unknown"
    $svcNames = ""

    try { $pname = (Get-Process -Id $OwningPid -ErrorAction Stop).ProcessName } catch { }

    #Best effort PID to service(s)
    try {
      $svcs = Get-CimInstance Win32_Service -Filter "ProcessId=$OwningPid" -ErrorAction SilentlyContinue
      if ($svcs) { $svcNames = ($svcs.Name -join ";") }
    } catch { }

    $detail = "TCP $($c.LocalAddress):$($c.LocalPort)  PID=$OwningPid  Proc=$pname" +
              $(if ($svcNames) { "  Svc=$svcNames" } else { "" })

    $risk = if ($c.LocalPort -in 22,23,80,135,139,443,445,3389,5985,5986) { "High" } else { "Medium" }

    $findings.Add((New-Finding -FindingType "ListeningPort" -Name "TCP Listener" -Risk $risk -Detail $detail -Location "Get-NetTCPConnection"))
  }

  #Optional UDP endpoints
  if ($Config.IncludeUdp) {
    try {
      $udp = Get-NetUDPEndpoint -ErrorAction Stop
      foreach ($u in $udp) {
        $addr = $u.LocalAddress

        if (-not $Config.IncludeLoopback) {
          if ($addr -eq "127.0.0.1" -or $addr -eq "::1") { continue }
        }
        if (-not $Config.IncludeIPv6) {
          if ($addr -like "*:*") { continue }
        }

        $OwningPid = $u.OwningProcess
        $pname = "Unknown"
        try { $pname = (Get-Process -Id $OwningPid -ErrorAction Stop).ProcessName } catch { }

        $detail = "UDP $($u.LocalAddress):$($u.LocalPort)  PID=$OwningPid  Proc=$pname"
        $findings.Add((New-Finding -FindingType "ListeningPort" -Name "UDP Endpoint" -Risk "Info" -Detail $detail -Location "Get-NetUDPEndpoint"))
      }
    } catch { }
  }

  return $findings
}

# ==========================
# 2) PUBLIC FIREWALL ALLOW RULES
# ==========================
function Get-PublicFirewallAllowRules {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Collecting firewall rules (Public Allow rules)..."

  try {
    $rules = Get-NetFirewallRule -Enabled True -ErrorAction Stop

    if ($Config.OnlyAllowRules) { $rules = $rules | Where-Object { $_.Action -eq "Allow" } }
    if ($Config.OnlyPublicProfile) { $rules = $rules | Where-Object { $_.Profile -match "Public" } }

    foreach ($r in $rules) {
      $ports = ""
      $prog  = ""

      try {
        $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        if ($pf) { $ports = ($pf | ForEach-Object { "$($_.Protocol):$($_.LocalPort)" }) -join ";" }
      } catch { }

      try {
        $af = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        if ($af) { $prog = ($af.Program -join ";") }
      } catch { }

      $detail = "$($r.DisplayName) | Dir=$($r.Direction) | Profile=$($r.Profile) | Ports=$ports | Program=$prog"
      $risk = if ($r.Direction -eq "Inbound") { "High" } else { "Medium" }

      $findings.Add((New-Finding -FindingType "FirewallRule" -Name "Public Allow Rule" -Risk $risk -Detail $detail -Location "Get-NetFirewallRule"))
    }
  } catch {
    $findings.Add((New-Finding -FindingType "Error" -Name "FirewallRuleQueryFailed" -Risk "Info" -Detail $_.Exception.Message -Location "Get-NetFirewallRule"))
  }

  return $findings
}

# ==========================
# 3) SMB SHARES
# ==========================
function Get-SmbSharesInfo {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Collecting SMB shares..."

  $default = @("ADMIN$","C$","D$","E$","IPC$","print$")

  try {
    $shares = Get-SmbShare -ErrorAction Stop
    foreach ($s in $shares) {
      if ($Config.HideDefaultShares -and ($default -contains $s.Name)) { continue }
      $detail = "Share=$($s.Name) Path=$($s.Path) Desc=$($s.Description)"
      $risk = if ($s.Name -match "\$$") { "Medium" } else { "High" }
      $findings.Add((New-Finding -FindingType "SMBShare" -Name "SMB Share" -Risk $risk -Detail $detail -Location "Get-SmbShare"))
    }
    if (($shares | Measure-Object).Count -eq 0) {
      $findings.Add((New-Finding -FindingType "SMBShare" -Name "SMB Share" -Risk "Info" -Detail "No SMB shares found." -Location "Get-SmbShare"))
    }
  } catch {
    try {
      $wmiShares = Get-CimInstance Win32_Share -ErrorAction Stop
      foreach ($ws in $wmiShares) {
        if ($Config.HideDefaultShares -and ($default -contains $ws.Name)) { continue }
        $detail = "Share=$($ws.Name) Path=$($ws.Path) Desc=$($ws.Description)"
        $risk = if ($ws.Name -match "\$$") { "Medium" } else { "High" }
        $findings.Add((New-Finding -FindingType "SMBShare" -Name "SMB Share" -Risk $risk -Detail $detail -Location "Win32_Share"))
      }
    } catch {
      $findings.Add((New-Finding -FindingType "Error" -Name "SMBShareQueryFailed" -Risk "Info" -Detail $_.Exception.Message -Location "Get-SmbShare/Win32_Share"))
    }
  }

  return $findings
}

# ==========================
# 4) RDP STATUS
# ==========================
function Get-RdpStatus {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Checking RDP enabled status..."

  $enabled = $null
  try {
    $v = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
    $enabled = ($v.fDenyTSConnections -eq 0)
  } catch { }

  $detail = if ($null -eq $enabled) { "Unable to determine RDP status." } else { "RDP Enabled: $(BoolText $enabled)" }
  $risk = if ($enabled -eq $true) { "High" } elseif ($enabled -eq $false) { "Low" } else { "Info" }

  $findings.Add((New-Finding -FindingType "RDP" -Name "RDP Enabled" -Risk $risk -Detail $detail -Location "HKLM:\...\Terminal Server"))
  return $findings
}

# ==========================
# 5) WINRM STATUS
# ==========================
function Get-WinRmStatus {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Checking WinRM status..."

  $svc = $null
  try { $svc = Get-Service -Name WinRM -ErrorAction Stop } catch { }

  if (-not $svc) {
    $findings.Add((New-Finding -FindingType "WinRM" -Name "WinRM Service" -Risk "Info" -Detail "WinRM service not found." -Location "Get-Service WinRM"))
    return $findings
  }

  $running = ($svc.Status -eq "Running")
  $startup = $svc.StartType

  $risk = if ($running) { "Medium" } else { "Low" }
  $detail = "WinRM Running: $(BoolText $running) | Startup: $startup"

  $listeners = ""
  try {
    $l = & winrm enumerate winrm/config/listener 2>$null
    if ($l) {
      $listeners = ($l | Select-String -Pattern "Transport|Port|Address" | ForEach-Object { $_.Line.Trim() }) -join " | "
    }
  } catch { }

  if ($listeners) { $detail += " | Listeners: $listeners" }

  $findings.Add((New-Finding -FindingType "WinRM" -Name "WinRM Service" -Risk $risk -Detail $detail -Location "Get-Service WinRM / winrm"))
  return $findings
}

# ==========================
# HTML REPORT
# ==========================
function Export-HtmlReport {
  param(
    [Parameter(Mandatory)]$Findings,
    [Parameter(Mandatory)][string]$HtmlPath,
    [Parameter(Mandatory)][string]$Title
  )

  $titleEsc = ConvertTo-HtmlSafe $Title
  $genTime  = ConvertTo-HtmlSafe (Get-Date).ToString()
  $count    = ($Findings | Measure-Object).Count

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
    input { padding: 8px; width: 520px; max-width: 100%; margin: 10px 0 16px 0; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
    th { cursor: pointer; background: #f5f5f5; position: sticky; top: 0; }
    tr:nth-child(even) { background: #fafafa; }
    .risk-High { font-weight: bold; color: #b00020; }
    .risk-Medium { font-weight: bold; color: #b26a00; }
    .risk-Low { color: #1b5e20; }
    .risk-Info { color: #1565c0; }
    code { white-space: pre-wrap; }
    .small { font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <h1>$titleEsc</h1>
  <div class="meta">
    Generated: $genTime<br>
    Findings: $count
  </div>

  <input id="search" placeholder="Search findings…" onkeyup="filterTable()">

  <table id="tbl">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Type</th>
        <th onclick="sortTable(1)">Name</th>
        <th onclick="sortTable(2)">Risk</th>
        <th onclick="sortTable(3)">Detail</th>
        <th onclick="sortTable(4)">Location</th>
        <th onclick="sortTable(5)">Notes</th>
      </tr>
    </thead>
    <tbody>
"@

  foreach ($f in $Findings) {
    $type = ConvertTo-HtmlSafe ([string]$f.FindingType)
    $name = ConvertTo-HtmlSafe ([string]$f.Name)
    $risk = ConvertTo-HtmlSafe ([string]$f.Risk)
    $det  = ConvertTo-HtmlSafe ([string]$f.Detail)
    $loc  = ConvertTo-HtmlSafe ([string]$f.Location)
    $note = ConvertTo-HtmlSafe ([string]$f.Notes)

    $riskClass = "risk-$($f.Risk)"
    $html += "      <tr><td>$type</td><td>$name</td><td class='$riskClass'>$risk</td><td><code>$det</code></td><td class='small'>$loc</td><td class='small'>$note</td></tr>`n"
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
function sortTable(col) {
  const table = document.getElementById("tbl");
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.rows);
  const asc = table.getAttribute("data-sort-col") != col || table.getAttribute("data-sort-dir") != "asc";
  rows.sort((a,b) => {
    const A = a.cells[col].innerText.toLowerCase();
    const B = b.cells[col].innerText.toLowerCase();
    if (A < B) return asc ? -1 : 1;
    if (A > B) return asc ? 1 : -1;
    return 0;
  });
  rows.forEach(r => tbody.appendChild(r));
  table.setAttribute("data-sort-col", col);
  table.setAttribute("data-sort-dir", asc ? "asc" : "desc");
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

$outCsv  = Join-Path $Config.OutputFolder "$base`_Findings.csv"
$outHtml = Join-Path $Config.OutputFolder "$base`_Report.html"

Write-Log "Starting Attack Surface Mapper (read-only)..."
Write-Log "CSV : $outCsv"
if ($Config.GenerateHtmlReport) { Write-Log "HTML: $outHtml" }

$all = New-Object System.Collections.Generic.List[object]

(Get-ListeningPorts)           | ForEach-Object { $all.Add($_) }
(Get-PublicFirewallAllowRules) | ForEach-Object { $all.Add($_) }
(Get-SmbSharesInfo)            | ForEach-Object { $all.Add($_) }
(Get-RdpStatus)                | ForEach-Object { $all.Add($_) }
(Get-WinRmStatus)              | ForEach-Object { $all.Add($_) }

$all | Sort-Object FindingType, Risk, Name |
  Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter

if ($Config.GenerateHtmlReport) {
  Export-HtmlReport -Findings $all -HtmlPath $outHtml -Title $Config.HtmlTitle
}

Write-Host "`n================ ATTACK SURFACE SUMMARY ================" -ForegroundColor Green
Write-Host "Computer: $computer"
Write-Host "Findings: $($all.Count)"
Write-Host "CSV:  $outCsv"
if ($Config.GenerateHtmlReport) { Write-Host "HTML: $outHtml" }
Write-Host "--------------------------------------------------------"

($all | Group-Object FindingType | Sort-Object Name) | ForEach-Object {
  Write-Host ("{0,-14} : {1}" -f $_.Name, $_.Count) -ForegroundColor Yellow
}

Write-Host "`nTop findings (first 25):" -ForegroundColor Cyan
$all |
  Select-Object -First 25 FindingType, Risk, Name, Detail |
  Format-Table -AutoSize

Write-Host "========================================================" -ForegroundColor Green
Write-Log "Done."
