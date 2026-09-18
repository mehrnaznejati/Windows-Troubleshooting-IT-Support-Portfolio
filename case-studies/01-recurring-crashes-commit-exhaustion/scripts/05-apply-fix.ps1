#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Apply the three remediation steps: page file, background-load trim, hibernate-instead-of-standby.

.DESCRIPTION
    Step 1  Re-enable a system-managed page file (restores commit headroom and crash-dump capability).
    Step 2  Set always-on lab services to Manual so they don't consume commit at every boot.
    Step 3  Disable Fast Startup and route lid/power/sleep-button and idle through Hibernate
            instead of Modern Standby.

    Does NOT reboot. Review the transcript, then restart the machine for Step 1 to take effect.

.PARAMETER ServicesToManual
    Services to set to Manual start and stop now. Adjust for the machine in question.
    Default: Splunkd (Splunk Enterprise), CmService (Windows Sandbox container manager).

.PARAMETER WslMemoryGB
    Cap for WSL 2 written to %USERPROFILE%\.wslconfig. 0 = don't touch. Default 4.

.PARAMETER HibernateIdleSeconds
    Idle time before hibernating. Default 1800 (30 min).

.EXAMPLE
    .\05-apply-fix.ps1
    .\05-apply-fix.ps1 -ServicesToManual 'Splunkd' -WslMemoryGB 8
#>
param(
    [string[]]$ServicesToManual = @('Splunkd', 'CmService'),
    [int]$WslMemoryGB = 4,
    [int]$HibernateIdleSeconds = 1800
)

$log = Join-Path $PSScriptRoot 'apply-fix.log'
Start-Transcript -Path $log -Force | Out-Null
try {
    Write-Output '== STEP 1: page file =='
    $cs = Get-CimInstance Win32_ComputerSystem
    Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $true }
    'AutomaticManagedPagefile : {0}' -f (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
    'PagingFiles (registry)   : {0}' -f ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management').PagingFiles -join ',')

    Write-Output "`n== STEP 2: trim always-on load =="
    foreach ($svc in $ServicesToManual) {
        if (Get-Service $svc -ErrorAction SilentlyContinue) {
            Set-Service $svc -StartupType Manual
            Stop-Service $svc -Force -ErrorAction Continue
        } else { "  service '$svc' not present - skipped" }
    }
    Get-Service $ServicesToManual -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize | Out-String | Write-Output

    if ($WslMemoryGB -gt 0) {
        $wslcfg = Join-Path $env:USERPROFILE '.wslconfig'
        if (-not (Test-Path $wslcfg)) {
            "[wsl2]`nmemory=${WslMemoryGB}GB`n" | Set-Content $wslcfg -Encoding ASCII
            "  wrote $wslcfg (memory=${WslMemoryGB}GB)"
        } else { "  $wslcfg already exists - not modified; add 'memory=${WslMemoryGB}GB' under [wsl2] manually" }
    }

    Write-Output "`n== STEP 3: hibernate instead of Modern Standby; Fast Startup off =="
    powercfg /h on
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value 0 -Type DWord

    # Lid close / power button / sleep button -> Hibernate (2), on AC and battery
    foreach ($a in 'LIDACTION', 'PBUTTONACTION', 'SBUTTONACTION') {
        powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS $a 2
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS $a 2
    }
    # Never enter standby on idle; hibernate after the configured idle time instead
    powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
    powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE $HibernateIdleSeconds
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE $HibernateIdleSeconds
    powercfg /setactive SCHEME_CURRENT

    'HiberbootEnabled : {0}' -f (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled
    powercfg /a | Write-Output

    Write-Output "`n== DONE - restart the machine to activate the page file =="
} catch {
    Write-Output "== ERROR: $_ =="
} finally {
    Stop-Transcript | Out-Null
}
