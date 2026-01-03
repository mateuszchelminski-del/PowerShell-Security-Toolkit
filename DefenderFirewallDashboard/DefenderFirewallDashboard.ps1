<#
.SYNOPSIS
  Defender / Firewall Posture Dashboard (Read-only) - CSV + HTML + Console (PowerShell 5.1 compatible)
#>

#==========================
#CONFIGURATION (EDIT HERE)
#==========================
$Config = [ordered]@{
  OutputFolder           = "C:\Inventory"
  BaseFileName           = "DefenderFirewallDashboard"
  CsvDelimiter           = ","
  VerboseOutput          = $true

  ConsoleTopRules        = 20
  HtmlTopRules           = 50
  IncludeDisabledRules   = $false

  GenerateHtmlReport     = $true
  AutoOpenHtmlReport     = $true   # NEW
  HtmlTitle              = "Defender + Firewall Posture Dashboard"
}

#=================
#HELPER FUNCTIONS
#=================
function Write-Log {
  param([string]$Message)
  if ($Config.VerboseOutput) { Write-Host "[*] $Message" -ForegroundColor Cyan }
}
function Write-Warn {
  param([string]$Message)
  Write-Host "[! ] $Message" -ForegroundColor Yellow
}
function Write-Err {
  param([string]$Message)
  Write-Host "[X ] $Message" -ForegroundColor Red
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

function Try-Get {
  param([scriptblock]$Script, [object]$Fallback = $null)
  try { return & $Script } catch { return $Fallback }
}

function To-BoolText {
  param($val)
  if ($null -eq $val) { return "" }
  if ($val -is [bool]) { return ($(if($val){"True"}else{"False"})) }
  return [string]$val
}

function Days-Old {
  param([datetime]$dt)
  if ($null -eq $dt) { return $null }
  return [math]::Floor(((Get-Date) - $dt).TotalDays)
}

function Score-AllowRule {
  param(
    [string]$LocalPort,
    [string]$RemoteAddress,
    [string]$Program,
    [string]$Service
  )

  $score = 0

  if (-not $LocalPort -or $LocalPort -eq "Any") { $score += 30 }
  elseif ($LocalPort -match ",") { $score += 15 }
  elseif ($LocalPort -match "-") { $score += 18 }
  else { $score += 5 }

  if (-not $RemoteAddress -or $RemoteAddress -eq "Any" -or $RemoteAddress -match "0\.0\.0\.0/0|::/0") { $score += 30 }
  elseif ($RemoteAddress -match "LocalSubnet") { $score += 10 }
  else { $score += 5 }

  if (-not $Program -or $Program -eq "Any") { $score += 15 } else { $score += 5 }
  if (-not $Service -or $Service -eq "") { $score += 10 } else { $score += 3 }

  return $score
}

#==========================
#DATA COLLECTION
#==========================
function Get-DefenderStatus {
  Write-Log "Collecting Microsoft Defender status..."
  $mp = Try-Get { Get-MpComputerStatus } $null

  if (-not $mp) {
    return [pscustomobject]@{
      Available                   = $false
      RealTimeProtectionEnabled   = ""
      AntivirusEnabled            = ""
      BehaviorMonitorEnabled      = ""
      IOAVProtectionEnabled       = ""
      NISProtectionEnabled        = ""
      AntispywareEnabled          = ""
      TamperProtection            = ""
      SigLastUpdated              = ""
      SigAgeDays                  = ""
      AntivirusSigVersion         = ""
      EngineVersion               = ""
      PlatformVersion             = ""
      Notes                       = "Get-MpComputerStatus unavailable (Defender module missing or blocked)."
    }
  }

  $sigLast = $mp.AntivirusSignatureLastUpdated
  $sigAge  = Days-Old $sigLast

  $tp = Try-Get { (Get-MpComputerStatus).IsTamperProtected } $null
  $tpText = ""
  if ($null -ne $tp) { $tpText = To-BoolText $tp }

  return [pscustomobject]@{
    Available                   = $true
    RealTimeProtectionEnabled   = To-BoolText $mp.RealTimeProtectionEnabled
    AntivirusEnabled            = To-BoolText $mp.AntivirusEnabled
    BehaviorMonitorEnabled      = To-BoolText $mp.BehaviorMonitorEnabled
    IOAVProtectionEnabled       = To-BoolText $mp.IOAVProtectionEnabled
    NISProtectionEnabled        = To-BoolText $mp.NISEnabled
    AntispywareEnabled          = To-BoolText $mp.AntispywareEnabled
    TamperProtection            = $tpText
    SigLastUpdated              = $sigLast
    SigAgeDays                  = $sigAge
    AntivirusSigVersion         = Coalesce-String $mp.AntivirusSignatureVersion ""
    EngineVersion               = Coalesce-String $mp.AMEngineVersion ""
    PlatformVersion             = Coalesce-String $mp.AMProductVersion ""
    Notes                       = ""
  }
}

function Get-FirewallProfiles {
  Write-Log "Collecting Windows Firewall profile states..."
  $profiles = Try-Get { Get-NetFirewallProfile } @()
  if (-not $profiles) { return @() }

  $profiles | ForEach-Object {
    [pscustomobject]@{
      Name                    = $_.Name
      Enabled                 = $_.Enabled
      DefaultInboundAction    = $_.DefaultInboundAction
      DefaultOutboundAction   = $_.DefaultOutboundAction
      AllowInboundRules       = $_.AllowInboundRules
      AllowLocalFirewallRules = $_.AllowLocalFirewallRules
      NotifyOnListen          = $_.NotifyOnListen
      LogFileName             = $_.LogFileName
      LogAllowed              = $_.LogAllowed
      LogBlocked              = $_.LogBlocked
    }
  }
}

function Get-InboundAllowRules {
  Write-Log "Collecting inbound firewall allow rules..."
  $rules = Try-Get { Get-NetFirewallRule -Direction Inbound -Action Allow } @()
  if (-not $rules) { return @() }

  $rows = foreach ($r in $rules) {
    if (-not $Config.IncludeDisabledRules -and $r.Enabled -ne "True") { continue }

    $port  = Try-Get { (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1).LocalPort } ""
    $proto = Try-Get { (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1).Protocol } ""
    $addr  = Try-Get { (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1).RemoteAddress } ""
    $app   = Try-Get { (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1).Program } ""
    $svc   = Try-Get { (Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $r -ErrorAction Stop | Select-Object -First 1).Service } ""

    $score = Score-AllowRule `
      -LocalPort (Coalesce-String $port "Any") `
      -RemoteAddress (Coalesce-String $addr "Any") `
      -Program (Coalesce-String $app "Any") `
      -Service (Coalesce-String $svc "")

    [pscustomobject]@{
      Name           = $r.DisplayName
      Group          = Coalesce-String $r.DisplayGroup ""
      Enabled        = $r.Enabled
      Profile        = $r.Profile
      LocalPort      = Coalesce-String $port ""
      Protocol       = Coalesce-String $proto ""
      RemoteAddress  = Coalesce-String $addr ""
      Program        = Coalesce-String $app ""
      Service        = Coalesce-String $svc ""
      EdgeTraversal  = $r.EdgeTraversalPolicy
      RuleScore      = $score
    }
  }

  return ($rows | Sort-Object `
    @{ Expression = 'RuleScore'; Descending = $true },
    @{ Expression = 'Name'; Descending = $false }
  )
}

function Get-ASRRules {
  Write-Log "Collecting Defender ASR rules (if available)..."
  $pref = Try-Get { Get-MpPreference } $null
  if (-not $pref) { return @() }

  $ids  = $pref.AttackSurfaceReductionRules_Ids
  $acts = $pref.AttackSurfaceReductionRules_Actions
  if (-not $ids -or $ids.Count -eq 0) { return @() }

  $mapAction = @{ 0="Disabled"; 1="Block"; 2="Audit"; 6="Warn" }

  $rows = @()
  for ($i=0; $i -lt $ids.Count; $i++) {
    $id = [string]$ids[$i]
    $a  = $acts[$i]
    $action = (if ($mapAction.ContainsKey([int]$a)) { $mapAction[[int]$a] } else { [string]$a })

    $rows += [pscustomobject]@{ RuleId=$id; Action=$action }
  }
  return $rows
}

#==========================
#HTML BUILD
#==========================
function Export-HtmlDashboard {
  param(
    [Parameter(Mandatory)]$SummaryRow,
    [Parameter(Mandatory)]$Profiles,
    [Parameter(Mandatory)]$InboundRules,
    [Parameter(Mandatory)]$AsrRules,
    [Parameter(Mandatory)][string]$HtmlPath,
    [Parameter(Mandatory)][string]$Title
  )

  $titleEsc = ConvertTo-HtmlSafe $Title
  $genTime  = ConvertTo-HtmlSafe (Get-Date).ToString()

  function Badge($label, $value) {
    $v = ConvertTo-HtmlSafe ([string]$value)
    $l = ConvertTo-HtmlSafe ([string]$label)
    $cls = "warn"
    if ($v -match "True|Enabled|Block|Audit|Warn") { $cls = "ok" }
    if ($v -match "False|Disabled") { $cls = "bad" }
    return "<div class='card'><div class='k'>$l</div><div class='v $cls'>$v</div></div>"
  }

  $profileRows = ""
  foreach ($p in $Profiles) {
    $profileRows += "<tr>" +
      "<td>$(ConvertTo-HtmlSafe $p.Name)</td>" +
      "<td>$(ConvertTo-HtmlSafe ([string]$p.Enabled))</td>" +
      "<td>$(ConvertTo-HtmlSafe $p.DefaultInboundAction)</td>" +
      "<td>$(ConvertTo-HtmlSafe $p.DefaultOutboundAction)</td>" +
      "<td>$(ConvertTo-HtmlSafe $p.LogFileName)</td>" +
      "<td>Allowed: $(ConvertTo-HtmlSafe ([string]$p.LogAllowed)) / Blocked: $(ConvertTo-HtmlSafe ([string]$p.LogBlocked))</td>" +
    "</tr>`n"
  }

  $topRules = $InboundRules | Select-Object -First $Config.HtmlTopRules
  $ruleRows = ""
  foreach ($r in $topRules) {
    $ruleRows += "<tr>" +
      "<td>$(ConvertTo-HtmlSafe $r.Name)</td>" +
      "<td>$(ConvertTo-HtmlSafe $r.Profile)</td>" +
      "<td>$(ConvertTo-HtmlSafe ([string]$r.Enabled))</td>" +
      "<td>$(ConvertTo-HtmlSafe $r.Protocol)</td>" +
      "<td>$(ConvertTo-HtmlSafe $r.LocalPort)</td>" +
      "<td>$(ConvertTo-HtmlSafe $r.RemoteAddress)</td>" +
      "<td>$(ConvertTo-HtmlSafe $r.Program)</td>" +
      "<td>$(ConvertTo-HtmlSafe $r.Service)</td>" +
      "<td>$(ConvertTo-HtmlSafe ([string]$r.RuleScore))</td>" +
    "</tr>`n"
  }

  $asrRows = ""
  foreach ($a in $AsrRules) {
    $asrRows += "<tr><td>$(ConvertTo-HtmlSafe $a.RuleId)</td><td>$(ConvertTo-HtmlSafe $a.Action)</td></tr>`n"
  }

  $asrNote = ""
  if (-not $AsrRules -or $AsrRules.Count -eq 0) {
    $asrNote = "<div class='note'>ASR rules not configured or not available on this system.</div>"
  }

  $sigAge = [string]$SummaryRow.SigAgeDays
  $sigBadgeClass = "ok"
  try {
    if ($sigAge -ne "" -and [int]$sigAge -ge 7)  { $sigBadgeClass = "warn" }
    if ($sigAge -ne "" -and [int]$sigAge -ge 14) { $sigBadgeClass = "bad" }
  } catch { }

  $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>$titleEsc</title>
<style>
  body { font-family: Arial, sans-serif; margin: 20px; }
  h1 { margin: 0 0 6px 0; }
  .meta { color: #555; margin-bottom: 16px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 14px 0 20px 0; }
  .card { border: 1px solid #ddd; border-radius: 10px; padding: 12px; background: #fafafa; }
  .k { font-size: 12px; color: #666; margin-bottom: 6px; }
  .v { font-size: 18px; font-weight: bold; }
  .ok { color: #1b5e20; }
  .warn { color: #b26a00; }
  .bad { color: #b00020; }
  .note { margin: 10px 0; padding: 10px; background: #fff3cd; border: 1px solid #ffeeba; border-radius: 8px; color: #6b4f00; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0 22px 0; }
  th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
  th { background: #f5f5f5; position: sticky; top: 0; }
  tr:nth-child(even) { background: #fafafa; }
  .small { font-size: 12px; color: #666; }
  input { padding: 8px; width: 560px; max-width: 100%; margin: 8px 0 12px 0; }
</style>
</head>
<body>
<h1>$titleEsc</h1>
<div class="meta">
  Computer: $(ConvertTo-HtmlSafe $SummaryRow.ComputerName)<br>
  Generated: $genTime
</div>

<h2>Defender Snapshot</h2>
<div class="grid">
  $(Badge "Defender Available" $SummaryRow.DefenderAvailable)
  $(Badge "Real-time Protection" $SummaryRow.RealTimeProtectionEnabled)
  $(Badge "Antivirus Enabled" $SummaryRow.AntivirusEnabled)
  $(Badge "Behavior Monitor" $SummaryRow.BehaviorMonitorEnabled)
  $(Badge "IOAV Protection" $SummaryRow.IOAVProtectionEnabled)
  $(Badge "NIS Protection" $SummaryRow.NISProtectionEnabled)
  $(Badge "Tamper Protection" $SummaryRow.TamperProtection)
  <div class='card'>
    <div class='k'>Signature Age (days)</div>
    <div class='v $sigBadgeClass'>$(ConvertTo-HtmlSafe ([string]$SummaryRow.SigAgeDays))</div>
    <div class='small'>Last Updated: $(ConvertTo-HtmlSafe ([string]$SummaryRow.SigLastUpdated))</div>
  </div>
</div>

<div class="small">
  Sig Version: $(ConvertTo-HtmlSafe $SummaryRow.AntivirusSigVersion) |
  Engine: $(ConvertTo-HtmlSafe $SummaryRow.EngineVersion) |
  Platform: $(ConvertTo-HtmlSafe $SummaryRow.PlatformVersion)
</div>

<h2>Firewall Profiles</h2>
<table>
  <thead><tr><th>Profile</th><th>Enabled</th><th>Default Inbound</th><th>Default Outbound</th><th>Log File</th><th>Logging</th></tr></thead>
  <tbody>$profileRows</tbody>
</table>

<h2>Inbound Allow Rules (Top $($Config.HtmlTopRules) broadest)</h2>
<input id="search" placeholder="Search rules..." onkeyup="filterRules()">
<table id="rules">
  <thead><tr><th>Name</th><th>Profile</th><th>Enabled</th><th>Proto</th><th>LocalPort</th><th>RemoteAddress</th><th>Program</th><th>Service</th><th>Score</th></tr></thead>
  <tbody>$ruleRows</tbody>
</table>

<h2>ASR Rules</h2>
$asrNote
<table>
  <thead><tr><th>RuleId</th><th>Action</th></tr></thead>
  <tbody>$asrRows</tbody>
</table>

<script>
function filterRules() {
  const input = document.getElementById("search").value.toLowerCase();
  const rows = document.querySelectorAll("#rules tbody tr");
  rows.forEach(r => {
    const txt = r.innerText.toLowerCase();
    r.style.display = txt.includes(input) ? "" : "none";
  });
}
</script>
</body>
</html>
"@

  try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($HtmlPath, $html, $utf8NoBom)
  } catch {
    throw "Failed to write HTML to '$HtmlPath'. Error: $($_.Exception.Message)"
  }
}

#=================
#MAIN
#=================
Ensure-Folder -Path $Config.OutputFolder

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computer  = $env:COMPUTERNAME
$base      = "$($Config.BaseFileName)_$computer`_$timestamp"

$outSummaryCsv = Join-Path $Config.OutputFolder "$base`_Summary.csv"
$outRulesCsv   = Join-Path $Config.OutputFolder "$base`_InboundAllowRules.csv"
$outAsrCsv     = Join-Path $Config.OutputFolder "$base`_ASR.csv"
$outHtml       = Join-Path $Config.OutputFolder "$base`_Report.html"

Write-Log "Starting Defender/Firewall posture collection (read-only)..."
Write-Log "Summary CSV: $outSummaryCsv"
Write-Log "Rules CSV  : $outRulesCsv"
Write-Log "ASR CSV    : $outAsrCsv"
if ($Config.GenerateHtmlReport) { Write-Log "HTML       : $outHtml" }

$def      = Get-DefenderStatus
$profiles = Get-FirewallProfiles
$rules    = Get-InboundAllowRules
$asr      = Get-ASRRules

$summary = [pscustomobject]@{
  ComputerName                = $computer
  DefenderAvailable           = $def.Available
  RealTimeProtectionEnabled   = $def.RealTimeProtectionEnabled
  AntivirusEnabled            = $def.AntivirusEnabled
  BehaviorMonitorEnabled      = $def.BehaviorMonitorEnabled
  IOAVProtectionEnabled       = $def.IOAVProtectionEnabled
  NISProtectionEnabled        = $def.NISProtectionEnabled
  TamperProtection            = $def.TamperProtection
  SigLastUpdated              = $def.SigLastUpdated
  SigAgeDays                  = $def.SigAgeDays
  AntivirusSigVersion         = $def.AntivirusSigVersion
  EngineVersion               = $def.EngineVersion
  PlatformVersion             = $def.PlatformVersion
  FirewallProfiles            = ($profiles | Select-Object -ExpandProperty Name) -join ", "
  FirewallProfilesEnabled     = ($profiles | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Name) -join ", "
  InboundAllowRuleCount       = ($rules | Measure-Object).Count
  AsrRuleCount                = ($asr | Measure-Object).Count
  Notes                       = Coalesce-String $def.Notes ""
}

$summary | Export-Csv -Path $outSummaryCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter
$rules   | Export-Csv -Path $outRulesCsv   -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter

if ($asr -and $asr.Count -gt 0) {
  $asr | Export-Csv -Path $outAsrCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter
} else {
  "" | Select-Object @{Name="RuleId";Expression={""}}, @{Name="Action";Expression={""}} |
    Export-Csv -Path $outAsrCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter
}

if ($Config.GenerateHtmlReport) {
  try {
    Export-HtmlDashboard -SummaryRow $summary -Profiles $profiles -InboundRules $rules -AsrRules $asr -HtmlPath $outHtml -Title $Config.HtmlTitle

    if (Test-Path $outHtml) {
      Write-Log "HTML report created: $outHtml"
      if ($Config.AutoOpenHtmlReport) { Start-Process $outHtml }
    } else {
      Write-Warn "HTML report was attempted but file not found at: $outHtml"
    }
  } catch {
    Write-Err "HTML report generation failed: $($_.Exception.Message)"
  }
}

Write-Host "`n================ DEFENDER + FIREWALL DASHBOARD ================" -ForegroundColor Green
Write-Host "Computer: $computer"
Write-Host "Generated: $(Get-Date)"
Write-Host "==============================================================" -ForegroundColor Green

Write-Host "`nOutputs:" -ForegroundColor Yellow
Write-Host "  Summary CSV: $outSummaryCsv"
Write-Host "  Rules CSV  : $outRulesCsv"
Write-Host "  ASR CSV    : $outAsrCsv"
if ($Config.GenerateHtmlReport) { Write-Host "  HTML       : $outHtml" }

Write-Log "Done."
