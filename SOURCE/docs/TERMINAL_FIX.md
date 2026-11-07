# Piped sudo terminal fix — 1.3.1

## Demonstrated cause

One guided 1.3.0 reproduction on a freshly installed Ubuntu 26.04 DE host reached the menu and stopped before processing the echoed selection. Before attaching a tracer, the package Bash was already `T+ / do_signal_stop`, while its bootstrap Bash parent remained in `wait`. A signal trace recorded `stopped by SIGTTIN`. Only after saving process/TTY/signal evidence was SIGCONT sent; package checks and installation immediately progressed. This reproduced a terminal stop, not a slow checksum, disk-space or network issue. The original removed OS cannot supply its past signal record; the reproduced mechanism matches its reported symptom. No claim is made that an unavailable historical signal was directly observed.

With sudo `use_pty`, a piped command can initially lack foreground access to the controlling terminal. The bootstrap previously launched another Bash to read `/dev/tty`. When that nested process stopped on SIGTTIN, the direct command monitored by sudo kept waiting instead of stopping, so foreground handoff did not resume the reader. A tiny real-sudo PTY fixture independently failed with the same `T+` state before the fix and passed after it. The nested menu reader stopped before asynchronous payload stages were entered; `run_stage` was not the cause of this particular reproduced menu failure.

## Targeted changes

The bootstrap now execs the verified entrypoint and resets inherited terminal signal dispositions. The terminal reader stays sudo's direct command through the package/all-in-one exec chain. Package and all-in-one EXIT handlers remove only the bootstrap's owned, private, narrowly named staging directory. Checksums and trust boundaries are unchanged.

Stage messages precede package checks, preflight, payload/core verification and guided OS/setup work. Manager package progress and prompts remain visible. Noninteractive payload stages explicitly disable inherited monitor mode. The manager retains its dedicated cancellation group, with asynchronous INT/QUIT dispositions reset. Ctrl+Z forwards suspension to that group; SIGCONT resumes it. Interrupted waits retain child ownership and wait again, preventing live files from being removed on resume. INT/TERM/HUP cancels the child tree and permits existing transaction rollback/recovery. SIGKILL and power loss remain journal-based recovery cases.

## Focused verification

`tests/test_sudo_terminal.py` uses real sudo plus a tiny package fixture, no network or product installation. `tests/test_job_control.py` checks inherited monitor mode, INT/HUP/TERM cancellation, stopped-child cancellation and real Ctrl+Z/fg resume. Public bootstrap cases cover checksum/download/platform/permission failures and guided/unattended input. The owner report retains before/after trace and process evidence, the one DE public guided installation, five authenticated protocol smokes, negative credentials, accounting, doctor and strict HTTPS checks. Previous functional campaigns are historical evidence for unchanged runtime components, not newly repeated tests.
