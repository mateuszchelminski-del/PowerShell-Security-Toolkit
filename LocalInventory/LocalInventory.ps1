<#
.SYNOPSIS
  Local Windows Inventory (Single CSV)

.DESCRIPTION
  Collects hardware, OS, disk, volume, and network information
  from the local machine and exports EVERYTHING into ONE CSV row.
  Also presents a clean, readable summary in the console.
#>

#==========================
#CONFIGURATION (EDIT HERE)
#==========================
$Config = @{
    OutputFolder  = "C:\Inventory"
    BaseFileName  = "LocalInventory"
    CsvDelimiter  = ","
    VerboseOutput = $true
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

function Get-UptimeSafe {
    try {
        $bootEvent = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=6005 } -MaxEvents 1 -ErrorAction Stop
        $lastBoot  = $bootEvent.TimeCreated
        $uptime    = (Get-Date) - $lastBoot

        return [pscustomobject]@{
            LastBootTime = $lastBoot
            UptimeDays   = [math]::Floor($uptime.TotalDays)
            UptimeHours  = [math]::Floor($uptime.TotalHours)
            Source       = "EventLog:System/6005"
        }
    } catch {
        return [pscustomobject]@{
            LastBootTime = "Unavailable"
            UptimeDays   = "Unavailable"
            UptimeHours  = "Unavailable"
            Source       = "Unavailable"
        }
    }
}

#=================
#INITIAL SETUP
#=================
Ensure-Folder -Path $Config.OutputFolder

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Computer  = $env:COMPUTERNAME
$CsvPath   = Join-Path $Config.OutputFolder "$($Config.BaseFileName)_$Computer`_$Timestamp.csv"

#=====================
#COLLECT SYSTEM INFO
#=====================
Write-Log "Collecting system information..."

$CS   = Get-CimInstance Win32_ComputerSystem
$OS   = Get-CimInstance Win32_OperatingSystem
$BIOS = Get-CimInstance Win32_BIOS
$CPU  = Get-CimInstance Win32_Processor | Select-Object -First 1
$Up   = Get-UptimeSafe

#==========
#DISKS
#==========
$DiskSummary = (
    Get-CimInstance Win32_DiskDrive | ForEach-Object {
        "$($_.Model) [$([math]::Round($_.Size / 1GB, 2)) GB]"
    }
) -join " | "

#==========
#VOLUMES
#==========
$VolumeSummary = (
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        "$($_.DeviceID): $([math]::Round($_.FreeSpace/1GB,1)) GB free / $([math]::Round($_.Size/1GB,1)) GB"
    }
) -join " | "

#==========
#NETWORK
#==========
$NetworkSummary = (
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object {
        $ip = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -and $_.IPAddress -ne "0.0.0.0" } |
              Select-Object -ExpandProperty IPAddress -First 1

        if (-not $ip) { $ip = "No IPv4" }

        "$($_.Name): $ip"
    }
) -join " | "

#========================
#FINAL INVENTORY OBJECT
#========================
$Inventory = [pscustomobject]@{
    ComputerName      = $Computer
    Manufacturer      = $CS.Manufacturer
    Model             = $CS.Model
    SerialNumber      = $BIOS.SerialNumber
    BIOSVersion       = $BIOS.SMBIOSBIOSVersion
    CPU               = $CPU.Name
    Cores             = $CPU.NumberOfCores
    LogicalProcessors = $CPU.NumberOfLogicalProcessors
    TotalRAM_GB       = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
    OSName            = $OS.Caption
    OSVersion         = $OS.Version
    BuildNumber       = $OS.BuildNumber
    OSArchitecture    = $OS.OSArchitecture

    LastBootTime      = $Up.LastBootTime
    UptimeDays        = $Up.UptimeDays
    UptimeHours       = $Up.UptimeHours
    UptimeSource      = $Up.Source

    Disks             = $DiskSummary
    Volumes           = $VolumeSummary
    NetworkAdapters   = $NetworkSummary
}

#========
#EXPORT
#========
$Inventory | Export-Csv -Path $CsvPath -NoTypeInformation -Delimiter $Config.CsvDelimiter -Encoding UTF8
Write-Log "Inventory exported to $CsvPath"

#==========================
#CONSOLE PRESENTATION
#==========================
Write-Host "`n==================== SYSTEM INVENTORY ====================" -ForegroundColor Green

Write-Host "`n[System]" -ForegroundColor Yellow
$Inventory | Select-Object ComputerName, Manufacturer, Model, SerialNumber |
    Format-List

Write-Host "[OS]" -ForegroundColor Yellow
$Inventory | Select-Object OSName, OSVersion, BuildNumber, OSArchitecture |
    Format-List

Write-Host "[Uptime]" -ForegroundColor Yellow
$Inventory | Select-Object LastBootTime, UptimeDays, UptimeHours, UptimeSource |
    Format-List

Write-Host "[Hardware]" -ForegroundColor Yellow
$Inventory | Select-Object CPU, Cores, LogicalProcessors, TotalRAM_GB |
    Format-List

Write-Host "[Storage]" -ForegroundColor Yellow
Write-Host "Disks   : $($Inventory.Disks)"
Write-Host "Volumes : $($Inventory.Volumes)"

Write-Host "`n[Network]" -ForegroundColor Yellow
Write-Host $Inventory.NetworkAdapters

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Log "Inventory completed successfully"
