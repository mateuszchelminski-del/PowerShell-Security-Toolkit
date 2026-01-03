<#
.SYNOPSIS
  Persistence Hunter (Read-Only) -> CSV + HTML + Console

.DESCRIPTION
  Enumerates common Windows persistence mechanisms (read-only):
    - Registry Run / RunOnce (HKCU + HKLM + Wow6432Node)
    - Startup folders (User + All Users)
    - Scheduled tasks (including hidden) + key flags
    - Services set to Auto (and key suspicious indicators)
    - Optional: WMI event subscriptions (Filter/Consumer/Binding)

  Outputs:
    - Findings CSV
    - Findings HTML report (search + sort + High-risk highlights)
    - Console summary

.NOTES
  Safe for portfolio use: reads system configuration only.
  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>

# ==========================
# CONFIGURATION (EDIT HERE)
# ==========================
$Config = [ordered]@{
  OutputFolder          = "C:\Inventory"
  BaseFileName          = "PersistenceHunter"
  CsvDelimiter          = ","
  VerboseOutput         = $true

  IncludeWmiPersistence = $true   # Optional - may require admin to see full results

  # Noise control
  IncludeMicrosoftTasks = $false  # If $false, filters tasks under \Microsoft\
  IncludeMicrosoftSvcs  = $false  # If $false, filters services with CompanyName containing Microsoft (best-effort)

  # Scoring / highlighting
  EnableRiskScoring     = $true
  HighRiskOnlyConsole   = $false  # If $true, console table shows only High risk

  # HTML report
  GenerateHtmlReport    = $true
  HtmlTitle             = "Persistence Hunter Report"
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

function New-Finding {
  param(
    [string]$FindingType,
    [string]$Name,
    [string]$Risk,
    [string]$Detail,
    [string]$Location,
    [string]$PathOrId = "",
    [string]$Notes = ""
  )
  [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    FindingType  = $FindingType
    Name         = $Name
    Risk         = $Risk
    Detail       = $Detail
    Location     = $Location
    PathOrId     = $PathOrId
    Notes        = $Notes
  }
}

function Get-RiskFromIndicators {
  param(
    [string]$CommandLine,
    [string]$PathText,
    [string]$Context = ""
  )

  if (-not $Config.EnableRiskScoring) { return "Info" }

  $txt = ("$CommandLine $PathText $Context").ToLowerInvariant()

  $high = @(
    "\appdata\", "\temp\", "\programdata\", "\users\public\", "\windows\temp\",
    "powershell", "pwsh", "-enc", "-encodedcommand", "iex", "invoke-expression",
    "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic", "wscript", "cscript",
    "http://", "https://", ".ps1", ".vbs", ".js", ".hta", ".dll"
  )

  $med = @(
    "\startup\", "\runonce", "\run\", "\tasks\", "schtasks", "sc.exe", "service",
    "cmd.exe", "conhost", "python", "curl", "wget"
  )

  foreach ($h in $high) { if ($txt -like "*$h*") { return "High" } }
  foreach ($m in $med)  { if ($txt -like "*$m*") { return "Medium" } }
  return "Low"
}

# ==========================
# 1) REGISTRY RUN / RUNONCE
# ==========================
function Get-RunKeys {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Scanning registry Run/RunOnce keys..."

  $keys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
  )

  foreach ($k in $keys) {
    if (-not (Test-Path $k)) { continue }

    try {
      $item = Get-ItemProperty -Path $k -ErrorAction Stop
      $props = $item.PSObject.Properties |
        Where-Object { $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") }

      foreach ($p in $props) {
        $name = $p.Name
        $val  = [string]$p.Value
        if ([string]::IsNullOrWhiteSpace($val)) { continue }

        $risk = Get-RiskFromIndicators -CommandLine $val -PathText "" -Context $k
        $findings.Add( (New-Finding -FindingType "RegistryRun" -Name $name -Risk $risk -Detail $val -Location $k -PathOrId $k -Notes "Autorun registry value") )
      }
    } catch {
      $findings.Add( (New-Finding -FindingType "Error" -Name "RunKeyReadFailed" -Risk "Info" -Detail $_.Exception.Message -Location $k -PathOrId $k ) )
    }
  }

  return $findings
}

# ==========================
# 2) STARTUP FOLDERS
# ==========================
function Get-StartupFolderItems {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Scanning Startup folders..."

  $userStartup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
  $allStartup  = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup"

  $folders = @(
    [pscustomobject]@{ Scope="CurrentUser"; Path=$userStartup },
    [pscustomobject]@{ Scope="AllUsers";    Path=$allStartup  }
  )

  foreach ($f in $folders) {
    if (-not (Test-Path $f.Path)) { continue }

    try {
      Get-ChildItem -Path $f.Path -Force -ErrorAction Stop | ForEach-Object {
        $full = $_.FullName
        $detail = "$($_.Name) | Type=$($_.Extension) | Modified=$($_.LastWriteTime)"
        $risk = Get-RiskFromIndicators -CommandLine "" -PathText $full -Context "StartupFolder"
        $findings.Add( (New-Finding -FindingType "StartupFolder" -Name $_.Name -Risk $risk -Detail $detail -Location $f.Scope -PathOrId $full -Notes "Startup folder item") )
      }
    } catch {
      $findings.Add( (New-Finding -FindingType "Error" -Name "StartupFolderReadFailed" -Risk "Info" -Detail $_.Exception.Message -Location $f.Scope -PathOrId $f.Path ) )
    }
  }

  return $findings
}

# ==========================
# 3) SCHEDULED TASKS
# ==========================
function Get-ScheduledTasksFindings {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Scanning scheduled tasks (including hidden)..."

  try {
    $tasks = Get-ScheduledTask -ErrorAction Stop
  } catch {
    $findings.Add( (New-Finding -FindingType "Error" -Name "GetScheduledTaskFailed" -Risk "Info" -Detail $_.Exception.Message -Location "Get-ScheduledTask") )
    return $findings
  }

  foreach ($t in $tasks) {
    $taskPathId = "$($t.TaskPath)$($t.TaskName)"

    if (-not $Config.IncludeMicrosoftTasks) {
      if ($t.TaskPath -like "\Microsoft\*") { continue }
    }

    $actions = @()
    try { $actions = $t.Actions } catch { $actions = @() }

    $actionText = ($actions | ForEach-Object {
      if ($_.Execute) {
        $args = if ($_.Arguments) { " $($_.Arguments)" } else { "" }
        "$($_.Execute)$args"
      } else { "$($_)" }
    }) -join " | "

    $hidden = $false
    try { $hidden = [bool]$t.Settings.Hidden } catch { }

    $runAs = ""
    try {
      $runAs = $t.Principal.UserId
      if (-not $runAs) { $runAs = $t.Principal.GroupId }
    } catch { }

    $risk = Get-RiskFromIndicators -CommandLine $actionText -PathText "" -Context "ScheduledTask"
    if ($hidden -and $risk -ne "High") { $risk = "Medium" }

    $detail = "Action=$actionText | Hidden=$hidden | RunAs=$runAs | State=$($t.State)"
    $notes  = if ($hidden) { "Hidden task" } else { "" }

    $findings.Add( (New-Finding -FindingType "ScheduledTask" -Name $t.TaskName -Risk $risk -Detail $detail -Location $t.TaskPath -PathOrId $taskPathId -Notes $notes) )
  }

  return $findings
}

# ==========================
# 4) SERVICES (AUTO)
# ==========================
function Get-AutoServicesFindings {
  $findings = New-Object System.Collections.Generic.List[object]
  Write-Log "Scanning services set to Automatic..."

  $services = @()
  try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq "Auto" }
  } catch {
    $findings.Add( (New-Finding -FindingType "Error" -Name "ServiceQueryFailed" -Risk "Info" -Detail $_.Exception.Message -Location "Win32_Service") )
    return $findings
  }

  foreach ($s in $services) {
    $path = [string]$s.PathName
    $name = [string]$s.Name
    $disp = [string]$s.DisplayName

    if (-not $Config.IncludeMicrosoftSvcs) {
      try {
        $exe = $null
        if ($path) {
          $first = $path.Trim()
          if ($first.StartsWith('"')) { $exe = ($first -split '"')[1] }
          else { $exe = ($first -split '\s+')[0] }

          if ($exe -and (Test-Path $exe)) {
            $company = (Get-Item $exe -ErrorAction SilentlyContinue).VersionInfo.CompanyName
            if ($company -and $company -match "Microsoft") { continue }
          }
        }
      } catch { }
    }

    $risk = Get-RiskFromIndicators -CommandLine $path -PathText $path -Context "ServiceAuto"
    $detail = "DisplayName=$disp | State=$($s.State) | StartMode=$($s.StartMode) | Path=$path"
    $findings.Add( (New-Finding -FindingType "ServiceAuto" -Name $name -Risk $risk -Detail $detail -Location "Win32_Service" -PathOrId $path -Notes "Auto-start service") )
  }

  return $findings
}

# ==========================
# 5) WMI EVENT SUBSCRIPTIONS (OPTIONAL)
# ==========================
function Get-WmiPersistenceFindings {
  $findings = New-Object System.Collections.Generic.List[object]
  if (-not $Config.IncludeWmiPersistence) { return $findings }

  Write-Log "Scanning WMI event subscriptions (optional)..."

  try {
    $filters   = Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction Stop
    $consumers = Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
    $bindings  = Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

    foreach ($f in $filters) {
      $detail = "Name=$($f.Name) | Query=$($f.Query)"
      $risk = Get-RiskFromIndicators -CommandLine $f.Query -PathText "" -Context "WMIEventFilter"
      $findings.Add( (New-Finding -FindingType "WMI" -Name "__EventFilter" -Risk $risk -Detail $detail -Location "root\subscription" -PathOrId $f.__Path -Notes "WMI event filter") )
    }

    foreach ($c in $consumers) {
      $cmd = [string]$c.CommandLineTemplate
      $detail = "Name=$($c.Name) | CommandLineTemplate=$cmd"
      $risk = Get-RiskFromIndicators -CommandLine $cmd -PathText "" -Context "CommandLineEventConsumer"
      if ($risk -ne "High") { $risk = "High" }
      $findings.Add( (New-Finding -FindingType "WMI" -Name "CommandLineEventConsumer" -Risk $risk -Detail $detail -Location "root\subscription" -PathOrId $c.__Path -Notes "WMI consumer executes commands") )
    }

    foreach ($b in $bindings) {
      $detail = "Filter=$($b.Filter) | Consumer=$($b.Consumer)"
      $findings.Add( (New-Finding -FindingType "WMI" -Name "__FilterToConsumerBinding" -Risk "Medium" -Detail $detail -Location "root\subscription" -PathOrId $b.__Path -Notes "WMI binding") )
    }
  } catch {
    $findings.Add( (New-Finding -FindingType "Error" -Name "WmiSubscriptionQueryFailed" -Risk "Info" -Detail $_.Exception.Message -Location "root\subscription") )
  }

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
    input { padding: 8px; width: 560px; max-width: 100%; margin: 10px 0 16px 0; }
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
        <th onclick="sortTable(5)">Path/Id</th>
        <th onclick="sortTable(6)">Notes</th>
      </tr>
    </thead>
    <tbody>
"@

  foreach ($f in $Findings) {
    $typeEsc     = ConvertTo-HtmlSafe ([string]$f.FindingType)
    $nameEsc     = ConvertTo-HtmlSafe ([string]$f.Name)
    $riskEsc     = ConvertTo-HtmlSafe ([string]$f.Risk)
    $detailEsc   = ConvertTo-HtmlSafe ([string]$f.Detail)
    $locEsc      = ConvertTo-HtmlSafe ([string]$f.Location)
    $pathIdEsc   = ConvertTo-HtmlSafe ([string]$f.PathOrId)   # <-- FIX: do NOT use $pid / $PID
    $notesEsc    = ConvertTo-HtmlSafe ([string]$f.Notes)

    $riskClass = "risk-$($f.Risk)"
    $html += "      <tr><td>$typeEsc</td><td>$nameEsc</td><td class='$riskClass'>$riskEsc</td><td><code>$detailEsc</code></td><td class='small'>$locEsc</td><td class='small'>$pathIdEsc</td><td class='small'>$notesEsc</td></tr>`n"
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

Write-Log "Starting Persistence Hunter (read-only)..."
Write-Log "CSV : $outCsv"
if ($Config.GenerateHtmlReport) { Write-Log "HTML: $outHtml" }

$all = New-Object System.Collections.Generic.List[object]

(Get-RunKeys)                | ForEach-Object { $all.Add($_) }
(Get-StartupFolderItems)     | ForEach-Object { $all.Add($_) }
(Get-ScheduledTasksFindings) | ForEach-Object { $all.Add($_) }
(Get-AutoServicesFindings)   | ForEach-Object { $all.Add($_) }
(Get-WmiPersistenceFindings) | ForEach-Object { $all.Add($_) }

$all |
  Sort-Object FindingType, Risk, Name |
  Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8 -Delimiter $Config.CsvDelimiter

if ($Config.GenerateHtmlReport) {
  Export-HtmlReport -Findings $all -HtmlPath $outHtml -Title $Config.HtmlTitle
}

Write-Host "`n================ PERSISTENCE HUNTER SUMMARY ================" -ForegroundColor Green
Write-Host "Computer: $computer"
Write-Host "Findings: $($all.Count)"
Write-Host "CSV:  $outCsv"
if ($Config.GenerateHtmlReport) { Write-Host "HTML: $outHtml" }
Write-Host "-----------------------------------------------------------"

($all | Group-Object FindingType | Sort-Object Name) | ForEach-Object {
  Write-Host ("{0,-16} : {1}" -f $_.Name, $_.Count) -ForegroundColor Yellow
}

$high = $all | Where-Object { $_.Risk -eq "High" }
Write-Host "`nHigh-risk items: $($high.Count)" -ForegroundColor Cyan

Write-Host "`nConsole preview (first 25):" -ForegroundColor Cyan
$preview = if ($Config.HighRiskOnlyConsole) { $high } else { $all }
$preview |
  Select-Object -First 25 FindingType, Risk, Name, Location, PathOrId, Detail |
  Format-Table -AutoSize

Write-Host "===========================================================" -ForegroundColor Green
Write-Log "Done."
