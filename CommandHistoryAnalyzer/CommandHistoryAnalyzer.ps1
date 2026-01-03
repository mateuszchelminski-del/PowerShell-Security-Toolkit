<#
.SYNOPSIS
  Command-Line History Analyzer (Read-Only) -> CSV + HTML + Console

.Prerequisites
  Have C:\Inventory or change OutputFolder = value

.DESCRIPTION
  Read-only analysis of local command history sources:
    - PowerShell PSReadLine history (ConsoleHost_history.txt)
    - Optional CMD history files (if present)
    - Optional WSL bash history (if present)

  Flags patterns for:
    - Credential usage (redacted)
    - Network enumeration / recon
    - LOLBins / suspicious built-ins

  Outputs:
    - Findings CSV
    - Findings HTML report (search + sortable)
    - Console summary

.NOTES
  Safe-by-design: does not dump secrets. Redacts common secret patterns.
  PowerShell 5.1+ / 7+ compatible (no System.Web dependency).
#>

#==========================
#CONFIGURATION (EDIT HERE)
#==========================
$Config = [ordered]@{
  OutputFolder         = "C:\Inventory"
  BaseFileName         = "CommandHistory"
  CsvDelimiter         = ","
  VerboseOutput        = $true

  #Output safety
  MaxSnippetLength     = 180
  RedactSecrets        = $true

  #How many lines to process from each file (0 = all)
  MaxLinesPerFile      = 8000

  #Sources
  IncludeWSL           = $true
  IncludeCmdCandidates = $true

  #HTML report
  GenerateHtmlReport   = $true
  HtmlTitle            = "Command History Analyzer Report"
}

#=================
#HELPER FUNCTIONS
#=================
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

function Truncate {
  param([string]$Text, [int]$Max)
  if ([string]::IsNullOrEmpty($Text)) { return $Text }
  if ($Text.Length -le $Max) { return $Text }
  return $Text.Substring(0, $Max) + "…"
}

function Redact-Line {
  param([string]$Line)
  if (-not $Config.RedactSecrets -or [string]::IsNullOrWhiteSpace($Line)) { return $Line }

  $x = $Line

  #password=..., pwd:..., pass: ...
  $x = [regex]::Replace($x, '(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*([^\s;]+)', '$1=<REDACTED>')

  #token/apiKey/secret assignments
  $x = [regex]::Replace($x, '(?i)\b(token|api[_-]?key|apikey|secret|client[_-]?secret)\b\s*[:=]\s*([^\s;]+)', '$1=<REDACTED>')

  #Basic auth URLs: https://user:pass@host
  $x = [regex]::Replace($x, '(?i)(https?:\/\/)([^\/\s:]+):([^\/\s@]+)@', '$1<REDACTED>:<REDACTED>@')

  #Bearer token
  $x = [regex]::Replace($x, '(?i)\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*', 'Bearer <REDACTED>')

  #AWS Access Key ID-like
  $x = [regex]::Replace($x, '\bAKIA[0-9A-Z]{16}\b', 'AKIA<REDACTED>')

  return $x
}

function ConvertTo-HtmlSafe {
  param([string]$Text)
  if ($null -eq $Text) { return "" }
  $t = [string]$Text
  $t = $t.Replace("&","&amp;")
  $t = $t.Replace("<","&lt;")
  $t = $t.Replace(">","&gt;")
  $t = $t.Replace('"',"&quot;")
  $t = $t.Replace("'","&#39;")
  return $t
}

#==========================
#PATTERNS (FLAGS)
#==========================
$Rules = @(
  # ---- Credential-ish ----
  @{ Category="Credential";   Name="net_use_user";          Regex='(?i)\bnet\s+use\b.*\b/user:';                              Risk="High" }
  @{ Category="Credential";   Name="runas";                 Regex='(?i)\brunas\b';                                            Risk="Medium" }
  @{ Category="Credential";   Name="curl_user";             Regex='(?i)\bcurl\b.*\s(-u|--user)\s+\S+';                         Risk="High" }
  @{ Category="Credential";   Name="openssl_pass";          Regex='(?i)\bopenssl\b.*\b(pass|passwd|password)\b';               Risk="High" }
  @{ Category="Credential";   Name="secret_assignment";     Regex='(?i)\b(pass(word)?|pwd|token|api[_-]?key|secret)\b\s*[:=]'; Risk="High" }
  @{ Category="Credential";   Name="get_credential";        Regex='(?i)\b(Get-Credential|ConvertTo-SecureString)\b';            Risk="Low" }

  # ---- Network / Recon ----
  @{ Category="NetworkRecon"; Name="ipconfig_ifconfig";     Regex='(?i)\b(ipconfig|ifconfig)\b';                               Risk="Low" }
  @{ Category="NetworkRecon"; Name="whoami_hostname";       Regex='(?i)\b(whoami|hostname)\b';                                 Risk="Low" }
  @{ Category="NetworkRecon"; Name="arp_route_netstat";     Regex='(?i)\b(arp|route|netstat)\b';                                Risk="Low" }
  @{ Category="NetworkRecon"; Name="nslookup_dig";          Regex='(?i)\b(nslookup|dig)\b';                                    Risk="Low" }
  @{ Category="NetworkRecon"; Name="ping_tracert";          Regex='(?i)\b(ping|tracert|traceroute)\b';                          Risk="Low" }
  @{ Category="NetworkRecon"; Name="nmap_masscan";          Regex='(?i)\b(nmap|masscan)\b';                                    Risk="High" }
  @{ Category="NetworkRecon"; Name="net_user_group";        Regex='(?i)\bnet\s+(view|user|group|localgroup)\b';                 Risk="Medium" }
  @{ Category="NetworkRecon"; Name="nltest_dsquery";        Regex='(?i)\b(nltest|dsquery|dsget)\b';                             Risk="Medium" }
  @{ Category="NetworkRecon"; Name="testnetconn_dns";       Regex='(?i)\b(Test-NetConnection|Resolve-DnsName)\b';               Risk="Low" }

  #---- LOLBins / Suspicious ----
  @{ Category="LOLBins";      Name="certutil";              Regex='(?i)\bcertutil\b';                                          Risk="High" }
  @{ Category="LOLBins";      Name="bitsadmin";             Regex='(?i)\bbitsadmin\b';                                         Risk="High" }
  @{ Category="LOLBins";      Name="mshta";                 Regex='(?i)\bmshta\b';                                             Risk="High" }
  @{ Category="LOLBins";      Name="rundll32_regsvr32";     Regex='(?i)\b(rundll32|regsvr32)\b';                               Risk="High" }
  @{ Category="LOLBins";      Name="wmic";                  Regex='(?i)\bwmic\b';                                              Risk="Medium" }
  @{ Category="LOLBins";      Name="powershell_encoded";    Regex='(?i)\bpowershell(\.exe)?\b.*\s(-enc|-encodedcommand)\s+';    Risk="High" }
  @{ Category="LOLBins";      Name="schtasks_create";       Regex='(?i)\bschtasks\b.*\b/create\b';                             Risk="High" }
  @{ Category="LOLBins";      Name="wevtutil_clear";        Regex='(?i)\bwevtutil\b.*\bcl\b';                                  Risk="High" }
  @{ Category="LOLBins";      Name="vssadmin_delete";       Regex='(?i)\bvssadmin\b.*\bdelete\b';                              Risk="High" }
  @{ Category="LOLBins";      Name="bcdedit";               Regex='(?i)\bbcdedit\b';                                           Risk="Medium" }
)

# ==========================
# HISTORY SOURCES
# ==========================
function Get-HistorySources {
  $sources = New-Object System.Collections.Generic.List[object]

  $psCandidates = @(
    (Join-Path $env:APPDATA      "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
    (Join-Path $env:APPDATA      "Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"),
    (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
  )

  foreach ($p in $psCandidates) {
    if (Test-Path $p) { $sources.Add([pscustomobject]@{ Source="PowerShell"; Path=$p }) }
  }

  if ($Config.IncludeCmdCandidates) {
    $cmdCandidates = @(
      (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\CMD\cmd_history.txt"),
      (Join-Path $env:APPDATA      "Microsoft\Windows\CMD\cmd_history.txt")
    )
    foreach ($c in $cmdCandidates) {
      if (Test-Path $c) { $sources.Add([pscustomobject]@{ Source="CMD"; Path=$c }) }
    }
  }

  if ($Config.IncludeWSL) {
    $wsl = Join-Path $env:USERPROFILE ".bash_history"
    if (Test-Path $wsl) { $sources.Add([pscustomobject]@{ Source="WSL"; Path=$wsl }) }
  }

  return ($sources | Sort-Object Path -Unique)
}

#==========================
#ANALYZE FILE
#==========================
function Analyze-HistoryFile {
  param(
    [Parameter(Mandatory)][string]$SourceName,
    [Parameter(Mandatory)][string]$Path
  )

  $computer = $env:COMPUTERNAME
  $findings = New-Object System.Collections.Generic.List[object]

  $lines = @()
  try {
    $lines = Get-Content -Path $Path -ErrorAction Stop
  } catch {
    $findings.Add([pscustomobject]@{
      ComputerName = $computer
      Source       = $SourceName
      FindingType  = "Error"
      Rule         = "ReadFailed"
      Risk         = "Info"
      LineNumber   = $null
      Snippet      = $null
      Path         = $Path
      Notes        = $_.Exception.Message
    })
    return $findings
  }

  if ($Config.MaxLinesPerFile -gt 0 -and $lines.Count -gt $Config.MaxLinesPerFile) {
    $lines = $lines[-$Config.MaxLinesPerFile..-1]
  }

  $lineNum = 0
  foreach ($line in $lines) {
    $lineNum++
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    foreach ($r in $Rules) {
      if ($line -match $r.Regex) {
        $safe = Truncate (Redact-Line $line) $Config.MaxSnippetLength

        $findings.Add([pscustomobject]@{
          ComputerName = $computer
          Source       = $SourceName
          FindingType  = $r.Category
          Rule         = $r.Name
          Risk         = $r.Risk
          LineNumber   = $lineNum
          Snippet      = $safe
          Path         = $Path
          Notes        = "Pattern match; secrets redacted."
        })
      }
    }
  }

  return $findings
}

#==========================
#HTML REPORT
#==========================
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
    input { padding: 8px; width: 460px; max-width: 100%; margin: 10px 0 16px 0; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
    th { cursor: pointer; background: #f5f5f5; position: sticky; top: 0; }
    tr:nth-child(even) { background: #fafafa; }
    .risk-High { font-weight: bold; color: #b00020; }
    .risk-Medium { font-weight: bold; color: #b26a00; }
    .risk-Low { color: #1b5e20; }
    .risk-Info { color: #1565c0; }
    .small { font-size: 12px; color: #666; }
    code { white-space: pre-wrap; }
  </style>
</head>
<body>
  <h1>$titleEsc</h1>
  <div class="meta">
    Generated: $genTime<br>
    Findings: $count
  </div>

  <input id="search" placeholder="Search findings (type to filter)…" onkeyup="filterTable()">

  <table id="tbl">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Source</th>
        <th onclick="sortTable(1)">Type</th>
        <th onclick="sortTable(2)">Risk</th>
        <th onclick="sortTable(3)">Rule</th>
        <th onclick="sortTable(4)">Line</th>
        <th onclick="sortTable(5)">Snippet</th>
        <th onclick="sortTable(6)">Path</th>
      </tr>
    </thead>
    <tbody>
"@

  foreach ($f in $Findings) {
    $riskClass = "risk-$($f.Risk)"
    $src  = ConvertTo-HtmlSafe ([string]$f.Source)
    $type = ConvertTo-HtmlSafe ([string]$f.FindingType)
    $risk = ConvertTo-HtmlSafe ([string]$f.Risk)
    $rule = ConvertTo-HtmlSafe ([string]$f.Rule)
    $line = ConvertTo-HtmlSafe ([string]$f.LineNumber)
    $snip = ConvertTo-HtmlSafe ([string]$f.Snippet)
    $path = ConvertTo-HtmlSafe ([string]$f.Path)

    $html += "      <tr><td>$src</td><td>$type</td><td class='$riskClass'>$risk</td><td>$rule</td><td>$line</td><td><code>$snip</code></td><td class='small'>$path</td></tr>`n"
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

#=================
#    MAIN
#=================
Ensure-Folder -Path $Config.OutputFolder

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$computer  = $env:COMPUTERNAME
$base      = "$($Config.BaseFileName)_$computer`_$timestamp"

$outCsv  = Join-Path $Config.OutputFolder "$base`_Findings.csv"
$outHtml = Join-Path $Config.OutputFolder "$base`_Report.html"

Write-Log "Starting command-history analysis (read-only)..."
Write-Log "CSV : $outCsv"
if ($Config.GenerateHtmlReport) { Write-Log "HTML: $outHtml" }

$sources = Get-HistorySources
if (-not $sources -or $sources.Count -eq 0) {
  Write-Host "`nNo history files found to analyze (PSReadLine/CMD/WSL)." -ForegroundColor Yellow
  return
}

$all = New-Object System.Collections.Generic.List[object]
foreach ($s in $sources) {
  Write-Log "Analyzing source: $($s.Source) -> $($s.Path)"
  (Analyze-HistoryFile -SourceName $s.Source -Path $s.Path) | ForEach-Object { $all.Add($_) }
}

#Export CSV
$all |
  Sort-Object Source, FindingType, Risk, Rule, Path, LineNumber |
  Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter

#Export HTML
if ($Config.GenerateHtmlReport) {
  Export-HtmlReport -Findings $all -HtmlPath $outHtml -Title $Config.HtmlTitle
}

#Console summary
Write-Host "`n================ COMMAND HISTORY ANALYSIS ================" -ForegroundColor Green
Write-Host "Computer: $computer"
Write-Host "Sources analyzed: $($sources.Count)"
Write-Host "Findings: $($all.Count)"
Write-Host "CSV:  $outCsv"
if ($Config.GenerateHtmlReport) { Write-Host "HTML: $outHtml" }
Write-Host "----------------------------------------------------------"

($all | Group-Object FindingType | Sort-Object Name) | ForEach-Object {
  Write-Host ("{0,-16} : {1}" -f $_.Name, $_.Count) -ForegroundColor Yellow
}

Write-Host "`nTop findings (first 25):" -ForegroundColor Cyan
$all |
  Select-Object -First 25 Source, FindingType, Risk, Rule, LineNumber, Snippet |
  Format-Table -AutoSize

Write-Host "==========================================================" -ForegroundColor Green
Write-Log "Done."
