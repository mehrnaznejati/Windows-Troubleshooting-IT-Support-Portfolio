<#
.SYNOPSIS
    Build a chronological timeline of every boot, orderly shutdown and dirty shutdown.

.DESCRIPTION
    Pulls the five event IDs that describe the power lifecycle of a Windows machine:
        41    Kernel-Power   rebooted without a clean shutdown (crash / hang / power loss)
        1074  User32         orderly shutdown or restart, with the initiating process
        6005  EventLog       event log service started  (= boot)
        6006  EventLog       event log service stopped  (= clean shutdown)
        6008  EventLog       previous shutdown was unexpected (includes last-known-alive time)
    Reading 6008 + the following 6005 tells you how long the machine was down.

.PARAMETER Days
    How far back to look. Default 30.

.EXAMPLE
    .\01-shutdown-timeline.ps1 -Days 14
#>
param([int]$Days = 30)

$since = (Get-Date).AddDays(-$Days)

Write-Host "=== Power lifecycle events, last $Days days ===`n"

Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 1074, 6005, 6006, 6008; StartTime = $since } -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated |
    ForEach-Object {
        $msg = ($_.Message -replace "`r`n", ' ')
        if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 140) + '...' }
        '{0:yyyy-MM-dd HH:mm:ss}  ID={1,-5} {2,-30} {3}' -f $_.TimeCreated, $_.Id, $_.ProviderName, $msg
    }

Write-Host "`n=== Summary ==="
$counts = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 1074, 6008; StartTime = $since } -ErrorAction SilentlyContinue |
    Group-Object Id | Sort-Object Name
foreach ($c in $counts) {
    $label = switch ($c.Name) { 41 { 'Dirty shutdowns (Kernel-Power 41)' } 1074 { 'Orderly shutdowns (User32 1074)' } 6008 { 'Unexpected shutdown notices (6008)' } }
    '{0,-40} {1}' -f $label, $c.Count
}
