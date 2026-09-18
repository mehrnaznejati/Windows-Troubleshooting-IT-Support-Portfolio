<#
.SYNOPSIS
    Analyse Resource-Exhaustion-Detector Event 2004 and the page file / commit configuration.

.DESCRIPTION
    Event 2004 fires when Windows detects a low-virtual-memory condition. Its XML payload records
    the system commit charge and commit limit at that instant, and the message names the three
    processes holding the most commit. This script:
        1. Shows page file configuration (the commit limit = RAM + page file).
        2. Lists every 2004 with commit charge vs limit and % used.
        3. Aggregates the named top consumers across all events.
        4. Shows the current top commit consumers.

.PARAMETER Days
    How far back to look. Default 30.
#>
param([int]$Days = 30)

$since = (Get-Date).AddDays(-$Days)

Write-Host '=== Page file configuration ==='
Get-CimInstance Win32_ComputerSystem | Select-Object AutomaticManagedPagefile, @{ n = 'PhysicalRAM_GB'; e = { [math]::Round($_.TotalPhysicalMemory / 1GB, 1) } } | Format-List
$pf = Get-CimInstance Win32_PageFileUsage
if ($pf) { $pf | Format-Table Name, AllocatedBaseSize, CurrentUsage, PeakUsage -AutoSize }
else     { Write-Host '  *** NO PAGE FILE CONFIGURED - commit limit equals physical RAM ***' -ForegroundColor Red }
$reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
'  PagingFiles registry value: [{0}]' -f ($reg.PagingFiles -join ', ')

$os = Get-CimInstance Win32_OperatingSystem
'  Commit limit now : {0:N0} MB' -f ($os.TotalVirtualMemorySize / 1KB)
'  Commit charge now: {0:N0} MB' -f (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1KB)

Write-Host "`n=== Low-memory events (2004), last $Days days ==="
$events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $since } -ErrorAction SilentlyContinue
'  Count: {0}' -f $events.Count

$events | Sort-Object TimeCreated | ForEach-Object {
    $x   = [xml]$_.ToXml()
    $sys = $x.Event.UserData.MemoryExhaustionInfo.SystemInfo
    $charge = [int64]$sys.SystemCommitCharge / 1MB
    $limit  = [int64]$sys.SystemCommitLimit  / 1MB
    '  {0:yyyy-MM-dd HH:mm}  commit {1,7:N0} MB / {2,7:N0} MB  ({3,5:P1})' -f $_.TimeCreated, $charge, $limit, ($charge / $limit)
}

Write-Host "`n=== Top consumers named across all 2004 events ==="
$events | ForEach-Object {
    [regex]::Matches($_.Message, '([A-Za-z0-9_.\-]+\.exe|vmmem\w*) \(\d+\) consumed (\d+) bytes') | ForEach-Object {
        [pscustomobject]@{ Process = $_.Groups[1].Value; MB = [int64]$_.Groups[2].Value / 1MB }
    }
} | Group-Object Process |
    Select-Object Count, Name,
        @{ n = 'AvgMB'; e = { [math]::Round(($_.Group | Measure-Object MB -Average).Average) } },
        @{ n = 'MaxMB'; e = { [math]::Round(($_.Group | Measure-Object MB -Maximum).Maximum) } } |
    Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host '=== Top commit consumers right now ==='
Get-Process | Sort-Object PagedMemorySize64 -Descending | Select-Object -First 15 Name,
    @{ n = 'CommitMB'; e = { [math]::Round($_.PagedMemorySize64 / 1MB) } },
    @{ n = 'WorkingSetMB'; e = { [math]::Round($_.WorkingSet64 / 1MB) } } | Format-Table -AutoSize

Write-Host '=== Crash-dump initialisation failures (volmgr 46) - a symptom of no page file on the boot volume ==='
$v46 = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'volmgr'; Id = 46; StartTime = $since } -ErrorAction SilentlyContinue
'  Count: {0}   Most recent: {1}' -f $v46.Count, ($v46 | Select-Object -First 1).TimeCreated
