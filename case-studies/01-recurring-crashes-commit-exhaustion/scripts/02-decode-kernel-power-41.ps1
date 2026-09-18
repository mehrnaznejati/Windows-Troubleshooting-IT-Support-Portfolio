<#
.SYNOPSIS
    Decode the XML payload of every Kernel-Power Event 41 to reveal the bugcheck code and power state.

.DESCRIPTION
    The message text of Event 41 is always the same generic sentence. The useful data lives in
    the EventData XML:
        BugcheckCode / BugcheckParameter1-4   the stop code and its parameters (0 = no bugcheck)
        SleepInProgress                       classic S3 sleep transition in progress
        ConnectedStandbyInProgress            machine was in Modern Standby (S0ix) when it died
        PowerButtonTimestamp                  non-zero = user held the power button to recover
    Grouping on these fields separates "crashed with a stop code" from "hung and was power-cycled"
    from "lost power", and shows whether crashes cluster in a particular power state.

.PARAMETER Days
    How far back to look. Default 30.

.EXAMPLE
    .\02-decode-kernel-power-41.ps1 | Format-Table -AutoSize
#>
param([int]$Days = 30)

$since = (Get-Date).AddDays(-$Days)

# Common stop codes, for readability. Full list: https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2
$stopNames = @{
    0x1E       = 'KMODE_EXCEPTION_NOT_HANDLED'
    0x3B       = 'SYSTEM_SERVICE_EXCEPTION'
    0x50       = 'PAGE_FAULT_IN_NONPAGED_AREA'
    0x51       = 'REGISTRY_ERROR'
    0x7E       = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
    0x9F       = 'DRIVER_POWER_STATE_FAILURE'
    0xEF       = 'CRITICAL_PROCESS_DIED'
    0x116      = 'VIDEO_TDR_FAILURE'
    0x124      = 'WHEA_UNCORRECTABLE_ERROR'
    0x133      = 'DPC_WATCHDOG_VIOLATION'
    0x135      = 'REGISTRY_FILTER_DRIVER_EXCEPTION'
    0x139      = 'KERNEL_SECURITY_CHECK_FAILURE'
    0x154      = 'UNEXPECTED_STORE_EXCEPTION'
    0xC000021A = 'STATUS_SYSTEM_PROCESS_TERMINATED'
}

$events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since } -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}
        $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        $code = [int64]$d.BugcheckCode

        [pscustomobject]@{
            Time             = $_.TimeCreated
            Bugcheck         = if ($code) { '0x{0:X}' -f $code } else { '-' }
            Name             = if ($code) { $stopNames[[int64]$code] } else { 'no bugcheck (hang / power loss)' }
            Param1           = if ($code) { '0x{0:X}' -f [int64]$d.BugcheckParameter1 } else { '' }
            ConnectedStandby = [bool]::Parse($d.ConnectedStandbyInProgress)
            SleepInProgress  = [int]$d.SleepInProgress
            PowerButtonUsed  = ([int64]$d.PowerButtonTimestamp) -ne 0
        }
    }

$events

Write-Host "`n=== Clusters ==="
'{0,-45} {1}' -f 'Bugchecks while in Connected Standby:',  ($events | Where-Object { $_.Bugcheck -ne '-' -and $_.ConnectedStandby }).Count
'{0,-45} {1}' -f 'Bugchecks while awake:',                 ($events | Where-Object { $_.Bugcheck -ne '-' -and -not $_.ConnectedStandby }).Count
'{0,-45} {1}' -f 'Hangs recovered with power button:',     ($events | Where-Object { $_.Bugcheck -eq '-' -and $_.PowerButtonUsed }).Count
'{0,-45} {1}' -f 'Power loss / hang without power button:' , ($events | Where-Object { $_.Bugcheck -eq '-' -and -not $_.PowerButtonUsed }).Count

Write-Host "`n=== Stop-code frequency ==="
$events | Where-Object { $_.Bugcheck -ne '-' } | Group-Object Bugcheck, Param1 | Sort-Object Count -Descending |
    ForEach-Object { '{0,3}x  {1}' -f $_.Count, $_.Name }
