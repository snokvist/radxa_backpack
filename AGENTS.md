# Repository Guidelines

## Project Structure & Module Organization
All runtime logic lives in `radxa_linkd.c`, which implements the `radxa_linkd` bridge between a USB CDC serial device, a localhost HTTP proxy, and a CRSF-over-UDP forwarder. Expect the binary (`radxa_linkd` or the default `a.out`) to be produced in the repo root. No nested modules or subdirectories are present; add new support code as additional translation units in the root and update the build command accordingly to keep the layout predictable.

## Build, Test, and Development Commands
Use `gcc -O2 -Wall -Wextra -o radxa_linkd radxa_linkd.c` for local builds; add `-fsanitize=address` when chasing memory bugs. Run the daemon with `./radxa_linkd` while the USB device is attached at `/dev/ttyACM0`. Interactive debugging is easiest with `strace ./radxa_linkd` or by piping canned frames into the serial device using `socat - FILE:/dev/ttyACM0,raw,echo=0`.

## Coding Style & Naming Conventions
Stick to ISO C99, 4-space indentation, and brace-on-same-line as seen in the existing file. Use `static` for translation-unit helpers and prefix shared structs with concise nouns (`app_ctx`, `rx_ctx`). Add small block comments only when behavior is non-obvious. Prefer descriptive flag macros (`LINK_FLAG_*`) and uppercase constants for tunables (ports, buffer sizes). Before sending patches, run `clang-format -style=LLVM radxa_linkd.c` if you edited substantial sections.

## Testing Guidelines
There is no automated harness, so rely on manual integration checks. Verify serial framing by replaying captures into `/dev/ttyACM0` and watching UDP egress on port 14450 with `tcpdump -n -vvv udp port 14450`. Exercise the HTTP bridge by curling `http://127.0.0.1:55667` through the ESP host to ensure START and END flags bracket payloads correctly.

## Commit & Pull Request Guidelines
Commits should be focused and describe the observable change in the imperative mood (e.g., "Add retry on CRSF send failures"). Reference hardware tickets or GitHub issues directly in the body and mention any manual test matrices you ran. PRs must include a short problem statement, screenshots or logs of serial output when applicable, and reproduction steps so reviewers can validate on their own hardware.

## Live Documentation Expectations
Keep **both this `AGENTS.md` and the repo `README.md` current** as functionality evolves. When code, build steps, or operational behavior changes:

- Update the relevant sections here so the next agent has accurate constraints and conventions.
- Mirror user-facing progress, new workflows, and testing instructions in `README.md`, removing stale details instead of letting them drift.
- Call out any new troubleshooting commands or logging cues you introduce (e.g., ESP monitor strings, host proxy logs) so future work continues from an informed baseline.
- Current state (Mar 2025): the ESP stub is a transparent HTTP proxy (no local assets), CRSF telemetry is emitted once per second, and `radxa_linkd` now drives HTTP responses with a stop-and-wait ACK (`LINK_FLAG_ACK`) so large transfers survive noisy links (200 ms timeout, up to eight retries per chunk plus a 24 ms post-ACK throttle so we don’t overwhelm the UART). The ESP firmware mirrors each response `seq` back in an ACK frame and sets `LINK_FLAG_ERROR` on the ACK to demand an immediate retransmit if a chunk cannot be queued. If you change the framing again, document the expected ACK/NAK vocabulary here and in the README.
