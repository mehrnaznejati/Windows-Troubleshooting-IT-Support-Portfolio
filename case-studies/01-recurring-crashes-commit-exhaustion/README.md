# Case Study 01 — Recurring Unexpected Shutdowns & Freezes on a Windows 11 Workstation

**Root cause:** the page file had been disabled, so the system commit limit equalled physical RAM with zero headroom. Under normal daily load the machine ran at 99.5 %+ commit, and every time it touched the ceiling a critical process failed to allocate → bugcheck or hard freeze.

| | |
|---|---|
| **Symptom** | ~1 unexpected shutdown per day for a month; mix of BSODs and hard freezes requiring a power-button reset |
| **Environment** | Windows 11 Pro laptop, 32 GB RAM, NVMe SSD, Modern Standby (S0 Low Power Idle) only, hybrid iGPU/dGPU graphics. Runs a security lab: Splunk Enterprise, Hyper-V VMs, WSL 2, Windows Sandbox |
| **Time to diagnose** | ~20 minutes using only the built-in System event log and PowerShell |
| **Fix** | Re-enable a system-managed page file, trim always-on background load, use Hibernate instead of Modern Standby, disable Fast Startup |
| **Skills shown** | Event log forensics, bugcheck decoding, Kernel-Power 41 XML parsing, memory commit analysis, elevated PowerShell remediation, post-fix verification |

---

## 1. Symptom

The user reported "periodic shutdowns." No pattern was obvious to them — sometimes a blue screen, sometimes the laptop was simply off when they returned to it, sometimes it froze and had to be held down.

Faulty RAM had been suspected earlier and Windows Memory Diagnostic had been run the day before with no result logged.

## 2. Evidence collection

All evidence came from the **System** event log. No third-party tools were needed.

### 2.1 Shutdown timeline (`scripts/01-shutdown-timeline.ps1`)

Filtering for boot/shutdown event IDs (`41, 1074, 6005, 6006, 6008`) over 30 days gave a clean timeline:

| Signal | Count / 30 days |
|---|---|
| `Kernel-Power 41` — "rebooted without cleanly shutting down" | **30** |
| `EventLog 6008` — "previous shutdown was unexpected" | 30 (one per 41) |
| `User32 1074` — orderly shutdown/restart | ~25 (user-initiated + Windows Update) |

Thirty dirty shutdowns in thirty days — roughly one a day. The `6008` message includes the *last known time the log was written*, which combined with the following `6005` boot time tells you how long the machine was down.

### 2.2 Decoding Kernel-Power 41 (`scripts/02-decode-kernel-power-41.ps1`)

**This was the pivotal step.** The Event 41 message text is generic, but its XML payload carries the bugcheck code and parameters plus power-state flags. Parsing every 41 event and tabulating the fields:

| Field | What it tells you |
|---|---|
| `BugcheckCode` | The stop code, if the crash was a bugcheck. `0` = no bugcheck (hang / power loss) |
| `BugcheckParameter1` | For exception-type bugchecks, the NTSTATUS that triggered it |
| `ConnectedStandbyInProgress` | `true` = machine was in Modern Standby when it died |
| `PowerButtonTimestamp` | Non-zero = the user held the power button to recover |

The 30 events split into **two clean clusters**:

**Cluster A — bugchecks (16), every one with `ConnectedStandbyInProgress = true`:**

| Stop code | Count | Parameter 1 | Meaning |
|---|---|---|---|
| `0x1E KMODE_EXCEPTION_NOT_HANDLED` | 7 | `0xC0000006` | STATUS_IN_PAGE_ERROR — a page-in from a mapped file failed |
| `0x135 REGISTRY_FILTER_DRIVER_EXCEPTION` | 1 | `0xC0000006` | same |
| `0xEF CRITICAL_PROCESS_DIED` | 5 | (process object) | a system-critical process (csrss/wininit/etc.) terminated |
| `0xC000021A WINLOGON/CSRSS terminated` | 2 | | same family |
| `0x51 REGISTRY_ERROR` | 1 | | hive I/O failure |
| `0x3B SYSTEM_SERVICE_EXCEPTION` | 1 | `0xC0000005` | access violation in a system call |

None of these implicate a specific driver. Every one of them is what you see when the kernel or a critical process **cannot get memory or cannot read a page back in**.

**Cluster B — no bugcheck (14):** `BugcheckCode = 0`. Nine had a non-zero `PowerButtonTimestamp` → the machine froze and the user power-cycled it. Five had none → froze and eventually died on its own (battery / thermal / watchdog).

### 2.3 Memory exhaustion (`scripts/03-memory-exhaustion-analysis.ps1`)

The `Microsoft-Windows-Resource-Exhaustion-Detector` provider logs **Event 2004** when Windows detects a low-virtual-memory condition. There were **68 in 30 days**, and the XML payload of each one records the system commit charge and limit at that instant:

```
Commit = 32,130 – 32,363 MB   of   Limit = 32,387 MB     (99.2 % – 99.9 %)
```

Every single event. The machine was living 20–250 MB from the wall.

Several of these fired **1–2 minutes before a Cluster-B freeze**:

```
15:59  Resource-Exhaustion 2004  →  16:01  system froze (power-button reset)
19:33  Resource-Exhaustion 2004  →  19:35  system froze (power-button reset)
```

The same events name the top three consumers. Aggregated across all 68:

| Process | Appearances | Avg commit | Note |
|---|---|---|---|
| `splunkd.exe` (Splunk Enterprise) | 68 / 68 | 4.5 GB | always-on indexer, autostart |
| `dwm.exe` | 54 | 1.4 GB | Desktop Window Manager — abnormally high |
| `vmmemCmZygote` | 23 | 0.9 GB | Windows Sandbox pre-warmed VM, spawned at every boot |
| `vmmemWSL` | 10 | 1.7 GB | WSL 2 VM, uncapped |
| `vmmemWindowsSandbox` | 2 | 2.6 GB | Windows Sandbox session |
| web browsers / IDE / sync clients | — | 1–2.5 GB each | normal user load |

### 2.4 The configuration defect

```powershell
Get-CimInstance Win32_ComputerSystem | Select AutomaticManagedPagefile   # False
Get-CimInstance Win32_PageFileUsage                                       # (nothing)
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management').PagingFiles   # (empty)
```

**No page file on any volume.** On Windows the *commit limit* = physical RAM + total page file size. With no page file, 32 GB of RAM is a hard 32 GB ceiling on every private allocation in the system. Windows cannot page anything out to make room, so when a critical process's next allocation fails, it dies.

A corroborating symptom: `volmgr` **Event 46 "Crash dump initialization failed!"** on every boot. A kernel memory dump is written *through the page file on the boot volume*. No page file → no dump can ever be written → `C:\Windows\MEMORY.DMP` never appeared, which is why nobody had been able to analyse these crashes.

### 2.5 Ruled out (`scripts/04-storage-hardware-checks.ps1`)

| Hypothesis | Evidence against |
|---|---|
| Faulty RAM | Stop codes are allocation/in-page failures, not the `0x124 / 0x1A / 0x50` corruption signatures; Memory Diagnostic produced no errors |
| SSD failure | Both NVMe disks `HealthStatus = Healthy`; zero `stornvme 129` resets, zero `disk 153` retries on the boot disk in 30 days |
| Display driver | Zero `0x9F / 0x116 / 0x117` in 30 days (an earlier, separate `0x9F` issue on this machine had been fixed by a driver update — a machine can have more than one problem) |
| Hardware error | `WHEA-Logger` had only 3 informational (ID 3) records, no corrected/uncorrected errors |
| Thermal | No `Kernel-Power 125/126` thermal events |

### 2.6 Why "during Modern Standby"?

Every bugcheck had `ConnectedStandbyInProgress = true`. Modern Standby is not "off" — Windows runs maintenance (Defender scans, update servicing, app background tasks, and in this case Splunk kept indexing) while the display is off. With zero commit headroom, that background activity is exactly when the next allocation fails. The `STATUS_IN_PAGE_ERROR` variants fit the same story: with no page file, Windows is forced to discard file-backed code pages aggressively and re-read them from disk; when that re-read cannot be serviced, the faulting process takes `0xC0000006`.

## 3. Root cause statement

> The system page file had been disabled. The commit limit therefore equalled physical RAM (32 GB) with zero headroom. Always-on background load (a SIEM indexer, a pre-warmed Sandbox VM, an uncapped WSL 2 VM, and normal desktop use) held commit at 99.5 %+ continuously. Each time commit reached the limit, a critical system process failed to allocate, producing `CRITICAL_PROCESS_DIED` / `IN_PAGE_ERROR` bugchecks or a complete freeze. Because a page file is also required for kernel crash dumps, no dump was ever written, which had prevented earlier diagnosis.

## 4. Resolution — step by step

All steps are in `scripts/05-apply-fix.ps1` (run elevated). Manual equivalents below.

### Step 1 — Re-enable the page file (the fix)

```powershell
# Elevated PowerShell — system-managed page file on the boot volume
$cs = Get-CimInstance Win32_ComputerSystem
Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $true }
Restart-Computer
```

GUI: `Win+R` → `SystemPropertiesAdvanced` → Performance **Settings** → Advanced → Virtual memory **Change** → tick *Automatically manage paging file size for all drives* → OK → reboot.

The page file **must be on the boot volume** for crash dumps to work.

### Step 2 — Reduce always-on load

Enabling the page file stops the crashes; this stops the machine from living at the ceiling.

```powershell
# SIEM indexer: start on demand, not at boot
Set-Service Splunkd -StartupType Manual; Stop-Service Splunkd

# Windows Sandbox pre-warms a VM at every boot (vmmemCmZygote)
Set-Service CmService -StartupType Manual; Stop-Service CmService
```

Cap WSL 2 — create `%USERPROFILE%\.wslconfig`:
```ini
[wsl2]
memory=4GB
```

Remove a second hypervisor if one is installed alongside Hyper-V (here VMware Workstation's `vmware-authd` had crashed hundreds of times competing with Hyper-V).

### Step 3 — Avoid Modern Standby until stable

Every bugcheck occurred in Connected Standby, so route sleep through Hibernate instead — it writes RAM to disk and fully powers off, with no background activity window.

```powershell
powercfg /h on
# Fast Startup off (it is a partial hibernate and skips a clean kernel init)
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' HiberbootEnabled 0

# Lid close, power button, sleep button → Hibernate (2), on AC and DC
foreach ($a in 'LIDACTION','PBUTTONACTION','SBUTTONACTION') {
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS $a 2
    powercfg /setdcvalueindex SCHEME_CURRENT SUB_BUTTONS $a 2
}
# Never idle into standby; hibernate after 30 min idle instead
powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE 1800
powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE 1800
powercfg /setactive SCHEME_CURRENT
```

### Step 4 — Verify (`scripts/06-verify-and-monitor.ps1`)

After the reboot:

```powershell
Get-CimInstance Win32_PageFileUsage | Format-Table Name, AllocatedBaseSize   # pagefile.sys present
(Get-CimInstance Win32_OperatingSystem).TotalVirtualMemorySize / 1KB          # commit limit > physical RAM
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='volmgr'; Id=46} -MaxEvents 1   # should be older than this boot
```

Observed post-fix: `pagefile.sys` 4.75 GB system-managed; commit limit rose 32,387 → 37,251 MB; steady-state commit fell from ~24 GB to ~19 GB after Step 2.

> Note: `volmgr 46` fired once more on the *first* boot after the change, at boot + 4 s — before `smss.exe` had created the new page file. It should not appear on subsequent boots. If it does, dump initialisation is failing for another reason (page file too small for the dump type, or a storage driver that doesn't support dump mode).

### Step 5 — Monitor for 7 days

```powershell
$s = (Get-Date).AddDays(-7)
(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41;   StartTime=$s} -ea 0).Count   # dirty shutdowns
(Get-WinEvent -FilterHashtable @{LogName='System'; Id=2004; StartTime=$s} -ea 0).Count   # low-memory warnings
```

Both should trend to **0**. For the first week the numbers still include the pre-fix days — check the `TimeCreated` of the most recent event rather than the raw count.

### Step 6 — Only if a crash recurs

`C:\Windows\MEMORY.DMP` will now actually exist. Open it in WinDbg (`!analyze -v`) and read `FAILURE_BUCKET_ID` and the stack. If `0xC0000006` still appears specifically during standby, the next suspect is the NVMe drive entering a deep idle power state — check SSD firmware / BIOS updates, or set *Primary NVMe Idle Timeout* to 0 in the active power plan. Do not pursue this without a dump to justify it.

## 5. Lessons

1. **Read the Event 41 XML, not the message.** `BugcheckCode`, `ConnectedStandbyInProgress` and `PowerButtonTimestamp` turned 30 identical-looking events into two distinct, explainable clusters.
2. **`CRITICAL_PROCESS_DIED` + `IN_PAGE_ERROR` + no dump file = check the page file first.** All three are direct consequences of the same setting.
3. **Resource-Exhaustion 2004 is a gift.** It records the commit charge, the limit and the top three consumers at the moment of pressure. Parse the XML and aggregate.
4. **"Disable the page file for performance" is a myth that still circulates.** On a machine with 32 GB it removed all headroom and all crash-dump capability.
5. **A machine can have two unrelated faults.** An earlier driver-related `0x9F` had genuinely been fixed; the remaining crashes were a different problem and were nearly dismissed as "the driver again."
6. **Verify with the same instrument you diagnosed with.** The exit criterion is the event log going quiet, not the user saying "it seems better."
