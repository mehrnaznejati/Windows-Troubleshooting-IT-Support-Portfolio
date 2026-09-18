# Windows Troubleshooting & IT Support Portfolio

Hands-on Windows infrastructure and support work by **Mehrnaz Nejati** — SOC analyst
(3+ years) with CISSP, Security+ and FCP (Fortinet), building toward a secure
cloud/network engineering role. Every case is a real incident on real hardware, written up as a root-cause
analysis with the PowerShell used to diagnose, fix and verify it.

## Projects

| Project | What it is | Stack |
|---------|------------|-------|
| [Case Studies](case-studies/) | Real-world Windows troubleshooting incidents written up as root-cause analyses, with the PowerShell used to diagnose, fix and verify each one. | PowerShell · Event log forensics · Bugcheck analysis · `powercfg` · WinDbg |

### Case Studies

Every case follows the same structure: **symptom → evidence → hypotheses ruled out → root
cause → step-by-step resolution → verification → lessons**. Scripts are parameterised and
safe to run on any Windows 10/11 machine; diagnostic scripts are read-only, remediation
scripts are clearly marked and require elevation. Machine identifiers, usernames and
personal data have been removed.

| # | Title | Root cause | Key techniques |
|---|---|---|---|
| [01](case-studies/01-recurring-crashes-commit-exhaustion/) | Recurring unexpected shutdowns & freezes on a Windows 11 workstation | Page file disabled → commit limit = RAM → critical-process allocation failures | Kernel-Power 41 XML decoding, Resource-Exhaustion 2004 parsing, commit analysis, `powercfg`, Hibernate vs Modern Standby |

Script conventions: `01`–`04` diagnostic (read-only) · `05` remediation (`#Requires -RunAsAdministrator`,
writes a transcript, never reboots on its own) · `06` verification / weekly monitor.

## License

MIT — see [LICENSE](LICENSE).
