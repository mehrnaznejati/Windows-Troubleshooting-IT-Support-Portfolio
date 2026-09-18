<#
.SYNOPSIS
    Post-fix verification and ongoing monitor.

.DESCRIPTION
    Run after the reboot that follows 05-apply-fix.ps1, then weekly.
        - Confirms the page file exists and the commit limit exceeds physical RAM
        - Confirms crash-dump initialisation no longer fails at boot (volmgr 46)
        - Confirms lid / button actions are set to Hibernate (read from the power scheme registry,
          because these are hidden attributes and don't appear in 'powercfg /q')
        - Counts dirty shutdowns (41) and low-memory warnings (2004) in the window, and shows the
          most recent of each so you can tell pre-fix history from new occurrences

.PARAMETER Days
    Monitoring window. Default 7.
#>
param([int]$Days = 7)

$since = (Get-Date).AddDays(-$Days)
$os    = Get-CimInstance Win32_OperatingSystem
$boot  = $os.LastBootUpTime

Write-Host '=== Page file / commit ==='
$pf = Get-CimInstance Win32_PageFileUsage
if ($pf) { $pf | Format-Table Name, AllocatedBaseSize, CurrentUsage, PeakUsage -AutoSize } else { Write-Host '  *** still no page file ***' -ForegroundColor Red }
'  Physical RAM : {0:N0} MB' -f ($os.TotalVisibleMemorySize / 1KB)
'  Commit limit : {0:N0} MB   {1}' -f ($os.TotalVirtualMemorySize / 1KB), $(if ($os.TotalVirtualMemorySize -gt $os.TotalVisibleMemorySize) { 'OK (limit > RAM)' } else { '*** limit == RAM ***' })
'  Commit charge: {0:N0} MB' -f (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1KB)

Write-Host "`n=== Crash-dump readiness ==="
$v46 = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'volmgr'; Id = 46 } -MaxEvents 1 -ErrorAction SilentlyContinue
'  Last boot          : {0}' -f $boot
'  Last volmgr 46     : {0}   {1}' -f $v46.TimeCreated, $(if ($v46 -and $v46.TimeCreated -gt $boot) { '*** fired on THIS boot - dump init still failing ***' } else { 'OK (older than this boot)' })

Write-Host "`n=== Power settings ==="
'  Fast Startup (HiberbootEnabled): {0}' -f (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled
$scheme  = (powercfg /getactivescheme) -replace '.*GUID: ([0-9a-f-]+).*', '$1'
$buttons = @{
    'Lid close'    = '5ca83367-6e45-459f-a27b-476b1d01c936'
    'Power button' = '7648efa3-dd9c-4e3e-b566-50f929386280'
    'Sleep button' = '96996bc0-ad50-47ec-923b-6f41874dd9eb'
}
foreach ($b in $buttons.GetEnumerator()) {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$scheme\4f971e89-eebd-4455-a8de-9e59040e7347\$($b.Value)"
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    '  {0,-13}: AC={1} DC={2}   (0=nothing 1=sleep 2=hibernate 3=shutdown)' -f $b.Key, $p.ACSettingIndex, $p.DCSettingIndex
}

Write-Host "`n=== Stability, last $Days days ==="
$e41   = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since } -ErrorAction SilentlyContinue
$e2004 = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $since } -ErrorAction SilentlyContinue
'  Dirty shutdowns (41)      : {0,3}   most recent: {1}' -f $e41.Count,   ($e41   | Select-Object -First 1).TimeCreated
'  Low-memory warnings (2004): {0,3}   most recent: {1}' -f $e2004.Count, ($e2004 | Select-Object -First 1).TimeCreated
'  Uptime                    : {0:d\d\ hh\:mm}' -f ((Get-Date) - $boot)

if (Test-Path "$env:SystemRoot\MEMORY.DMP") {
    $d = Get-Item "$env:SystemRoot\MEMORY.DMP"
    Write-Host ("`n  A crash dump exists ({0:N1} GB, written {1}). Analyse with WinDbg: !analyze -v" -f ($d.Length / 1GB), $d.LastWriteTime) -ForegroundColor Yellow
}
