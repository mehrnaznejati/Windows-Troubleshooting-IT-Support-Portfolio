<#
.SYNOPSIS
    Rule-out checks: storage health, hardware errors, thermal events, memory diagnostic results.

.DESCRIPTION
    Before blaming memory pressure, confirm the usual hardware suspects are quiet:
        - Physical disk health and boot-volume identification
        - Storage driver errors: disk 51/153/157, stornvme 129, Ntfs corruption
        - WHEA-Logger (machine-check / PCIe) records
        - Kernel-Power thermal events 125/126
        - Windows Memory Diagnostic results (1201/1202)
        - Crash dump configuration

.PARAMETER Days
    How far back to look. Default 30.
#>
param([int]$Days = 30)

$since = (Get-Date).AddDays(-$Days)

Write-Host '=== Physical disks ==='
Get-PhysicalDisk | Select-Object DeviceId, MediaType, BusType, HealthStatus, OperationalStatus,
    @{ n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB) } } | Format-Table -AutoSize
Get-Partition | Where-Object DriveLetter | Select-Object DiskNumber, DriveLetter, IsBoot, IsSystem,
    @{ n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB) } } | Format-Table -AutoSize

Write-Host '=== SMART / reliability counters (requires elevation) ==='
try {
    Get-PhysicalDisk | Get-StorageReliabilityCounter -ErrorAction Stop |
        Select-Object DeviceId, Temperature, Wear, ReadErrorsUncorrected, WriteErrorsUncorrected, PowerOnHours | Format-Table -AutoSize
} catch { Write-Host '  (not available - run elevated)' }

Write-Host "=== Storage / filesystem error counts, last $Days days ==="
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'disk', 'stornvme', 'storahci', 'Ntfs', 'Microsoft-Windows-Ntfs', 'volmgr', 'partmgr'; StartTime = $since } -ErrorAction SilentlyContinue |
    Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize
Write-Host '  Key IDs: disk 51 = paging I/O error, disk 153 = I/O retried, disk 157 = surprise removal, stornvme 129 = controller reset, Ntfs 55/98/140 = corruption / health'

Write-Host "=== WHEA-Logger (hardware errors), last $Days days ==="
$whea = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } -ErrorAction SilentlyContinue
if ($whea) { $whea | Group-Object Id | Select-Object Count, Name | Format-Table -AutoSize } else { '  none' }
Write-Host '  Key IDs: 17 = corrected PCIe, 18/19 = machine check, 20 = fatal; 3 = informational only'

Write-Host "=== Thermal shutdown events (Kernel-Power 125/126) ==="
$therm = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 125, 126; StartTime = $since } -ErrorAction SilentlyContinue
if ($therm) { $therm | Select-Object TimeCreated, Id | Format-Table -AutoSize } else { '  none' }

Write-Host '=== Windows Memory Diagnostic results ==='
$md = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'; StartTime = $since } -ErrorAction SilentlyContinue
if ($md) { $md | Select-Object TimeCreated, Id, Message | Format-List } else { '  no results logged in window (1201 = pass, 1202 = errors found)' }

Write-Host '=== Crash dump configuration ==='
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' |
    Select-Object CrashDumpEnabled, AutoReboot, DumpFile, DedicatedDumpFile | Format-List
Write-Host '  CrashDumpEnabled: 0 = none, 1 = complete, 2 = kernel, 3 = small, 7 = automatic'
'  MEMORY.DMP present: {0}' -f (Test-Path "$env:SystemRoot\MEMORY.DMP")
'  Minidumps present : {0}' -f ((Get-ChildItem "$env:SystemRoot\Minidump" -ErrorAction SilentlyContinue).Count)

Write-Host '=== Available sleep states ==='
powercfg /a
