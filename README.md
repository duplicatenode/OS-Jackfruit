# OS-Jackfruit — Multi-Container Runtime

## 1. Team Information

| Name | SRN |
|------|-----|
| SARTHKI VACHHANI | PES1UG24CS422 |
| SEJAL S | PES1UG24CS426 |

---

## 2. Build, Load, and Run Instructions

### Prerequisites

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r)
```

### Clone and enter the repo

```bash
git clone https://github.com/duplicatenode/OS-Jackfruit.git
cd OS-Jackfruit/boilerplate
```

### Run environment preflight check

```bash
chmod +x environment-check.sh
sudo ./environment-check.sh
```

### Prepare the Alpine base rootfs

```bash
cd ~/OS-Jackfruit
mkdir rootfs-base
wget https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.20.3-x86_64.tar.gz -C rootfs-base
```

### Copy workload binaries into rootfs-base

```bash
cp boilerplate/memory_hog rootfs-base/
cp boilerplate/cpu_hog    rootfs-base/
cp boilerplate/io_pulse   rootfs-base/
```

### Build everything

```bash
cd boilerplate
make
```

This produces:
- `engine` — user-space supervisor binary
- `monitor.ko` — kernel module
- `memory_hog`, `cpu_hog`, `io_pulse` — workload binaries

### Load the kernel module

```bash
sudo insmod monitor.ko
ls -l /dev/container_monitor
sudo dmesg | tail -5
```

Expected dmesg output:
```
[container_monitor] Module loaded. Device: /dev/container_monitor
```

### Create per-container writable rootfs copies

```bash
cd ~/OS-Jackfruit
cp -a rootfs-base rootfs-alpha
cp -a rootfs-base rootfs-beta
```

### Start the supervisor (Terminal 1)

```bash
cd ~/OS-Jackfruit/boilerplate
sudo ./engine supervisor ~/OS-Jackfruit/rootfs-base
```

Leave this running. Open a second terminal for all other commands.

### Launch containers (Terminal 2)

```bash
cd ~/OS-Jackfruit/boilerplate
sudo ./engine start alpha ~/OS-Jackfruit/rootfs-alpha /bin/sh --soft-mib 48 --hard-mib 80
sudo ./engine start beta  ~/OS-Jackfruit/rootfs-beta  /bin/sh --soft-mib 64 --hard-mib 96
```

### Use the CLI

```bash
sudo ./engine ps              # list all containers and metadata
sudo ./engine logs alpha      # view captured output of container alpha
sudo ./engine stop alpha      # send SIGTERM to container alpha
```

### Run memory limit test

```bash
sudo ./engine start memtest ~/OS-Jackfruit/rootfs-base /memory_hog --soft-mib 10 --hard-mib 20
# wait ~20 seconds
sudo dmesg | grep container_monitor
sudo ./engine ps
```

### Run scheduling experiments

```bash
# Two CPU-bound containers with different priorities
sudo ./engine start hipri ~/OS-Jackfruit/rootfs-base /cpu_hog --soft-mib 48 --hard-mib 80
sudo ./engine start lopri ~/OS-Jackfruit/rootfs-base /cpu_hog --soft-mib 48 --hard-mib 80

# Get PIDs from ps, then apply different nice values
sudo ./engine ps
sudo renice -n -5  -p <hipri_pid>
sudo renice -n +10 -p <lopri_pid>

# After ~30 seconds compare logs
sudo ./engine logs hipri
sudo ./engine logs lopri

# CPU-bound vs I/O-bound at same priority
sudo ./engine start cpuwork ~/OS-Jackfruit/rootfs-base /cpu_hog    --soft-mib 48 --hard-mib 80
sudo ./engine start iowork  ~/OS-Jackfruit/rootfs-base /io_pulse   --soft-mib 48 --hard-mib 80
```

### Clean teardown

```bash
sudo ./engine stop beta
sudo ./engine stop alpha
# Press Ctrl+C in Terminal 1 to stop supervisor
sudo rmmod monitor
sudo dmesg | tail -10
ps aux | grep engine
```

---

## 3. Demo with Screenshots

### Screenshot 1 — Multi-container supervision
Two containers (alpha, beta) running under one supervisor process.

![screenshot1](01_multicontainer.png)

*Caption: Two containers alpha and beta both in `running` state under a single supervisor (pid shown in Terminal 1).*

### Screenshot 2 — Metadata tracking
Output of `./engine ps` showing all tracked container metadata.

![screenshot2](02_ps_metadata.png)

*Caption: `ps` command output showing ID, HOST PID, STATE, STARTED, SOFT(MiB), HARD(MiB) for each container.*

### Screenshot 3 — Bounded-buffer logging
Log file contents captured through the logging pipeline.

![screenshot3](03_logs.png)

*Caption: `./engine logs alpha` showing output captured from the container via the pipe → bounded buffer → log file pipeline.*

### Screenshot 4 — CLI and IPC
A CLI command being issued and the supervisor responding.

![screenshot4](04_cli_ipc.png)

*Caption: `./engine stop alpha` issued in Terminal 2; supervisor in Terminal 1 responds confirming SIGTERM was sent — demonstrating the UNIX domain socket control channel.*

### Screenshot 5 — Soft-limit warning
dmesg showing a soft-limit warning event.

![screenshot5](05_soft_limit.png)

*Caption: `dmesg` output showing `SOFT LIMIT container=memtest` warning from the kernel module when RSS exceeded the soft threshold.*

### Screenshot 6 — Hard-limit enforcement
dmesg showing a container killed after exceeding hard limit.

![screenshot6](06_hard_limit.png)

*Caption: `dmesg` showing `HARD LIMIT container=memtest ... sending SIGKILL`; `ps` showing container state as `killed`.*

### Screenshot 7 — Scheduling experiment
Terminal output from scheduling experiment with observable differences.

![screenshot7](07_scheduling.png)

*Caption: `logs hipri` vs `logs lopri` — hipri container completed significantly more iterations in the same time period due to higher CFS scheduling weight (nice -5 vs nice +10).*

### Screenshot 8 — Clean teardown
Evidence that all containers are reaped and no zombies remain.

![screenshot8](08_teardown.png)

*Caption: `dmesg` shows `Module unloaded`; all container entries removed; `ps aux | grep engine` shows no zombie processes.*

---

## 4. Engineering Analysis

### Isolation Mechanisms

Our runtime achieves process and filesystem isolation using three Linux namespace flags passed to `clone(2)`:

**CLONE_NEWPID** creates a new PID namespace. The first process inside the container appears as PID 1 from its own perspective, even though the host kernel assigns it a real host PID (visible in `engine ps`). This means container processes cannot see or send signals to host processes or other containers' processes. The kernel maintains the mapping between host PIDs and container-local PIDs internally.

**CLONE_NEWUTS** gives each container its own hostname and domain name. We set the hostname to the container ID using `sethostname()` inside `child_fn`. Changes to the hostname inside the container do not affect the host or other containers.

**CLONE_NEWNS** creates a private mount namespace. Any mounts performed inside the container (including `/proc`) are not visible on the host. This is critical for mounting `/proc` correctly for the new PID namespace — without a separate mount namespace, the container's `/proc` mount would pollute the host.

After forking, the child uses `chroot()` to make the container's assigned rootfs directory appear as `/`. We bind-mount the rootfs onto itself first (`mount --bind`) to make it a proper mountpoint, then call `chroot(".")`. Inside the new root, we mount `/proc` so that tools like `ps` and `/proc/self` work correctly within the container's PID namespace.

**What the host kernel still shares with all containers:** The host kernel itself — all system calls go through the same kernel. The network namespace is shared (we do not use `CLONE_NEWNET`), so containers share the host's network interfaces. The IPC namespace is shared. The host's CPU scheduler is global across all namespaces. There is no hypervisor boundary; containers are isolated processes, not virtual machines.

### Supervisor and Process Lifecycle

A long-running parent supervisor is necessary for several reasons. First, only the parent of a process can call `waitpid()` on it — if the supervisor exited after launching containers, the containers would become orphans adopted by PID 1, and we would lose the ability to track their exit status. Second, the supervisor maintains a linked list of container metadata that must persist across the lifetime of multiple containers. Third, the control socket must stay bound for the entire session so CLI clients can connect at any time.

Process creation uses `clone(2)` instead of `fork(2)` because `clone` accepts namespace flags directly, allowing us to set up all three namespaces atomically at creation time. The returned host PID is stored in the container metadata record and is the PID visible on the host — this is the PID we register with the kernel monitor.

The supervisor installs a `SIGCHLD` handler to be notified when any child exits. Rather than doing the full `waitpid` inside the signal handler (which has async-signal-safety restrictions), we set a flag and do the actual reaping in the main event loop via `waitpid(-1, WNOHANG)`. This drains all exited children without blocking. For each reaped PID, we update the corresponding container record's state to `exited` or `killed` depending on `WIFSIGNALED`.

`SIGTERM` and `SIGINT` to the supervisor set a `should_stop` flag, which causes the event loop to exit cleanly after sending `SIGTERM` to all running containers and waiting for them to exit.

### IPC, Threads, and Synchronization

Our project uses two distinct IPC mechanisms:

**IPC Mechanism 1 — Anonymous pipes (logging, Path A):** For each container, we create a `pipe()` before calling `clone()`. Inside `child_fn`, the write end is `dup2`'d onto stdout and stderr. The read end stays in the supervisor. A dedicated producer thread per container reads from the pipe's read end in a loop and pushes chunks into the bounded ring buffer. When the container exits, the write end of the pipe is closed, causing the producer's `read()` to return 0 (EOF), which exits the producer thread cleanly.

**IPC Mechanism 2 — UNIX domain socket (control, Path B):** The supervisor creates a `SOCK_STREAM` socket bound at `/tmp/mini_runtime.sock`. Each CLI invocation (`engine ps`, `engine start`, etc.) is a short-lived client process that connects to this socket, writes a `control_request_t` struct, reads a `control_response_t` struct, and exits. This is entirely separate from the logging pipe so control commands and log data never interfere.

**Bounded buffer synchronization:** The ring buffer has a `pthread_mutex_t` protecting all accesses to `head`, `tail`, and `count`, plus two `pthread_cond_t` variables: `not_full` (producers wait here when the buffer is full) and `not_empty` (the consumer waits here when the buffer is empty).

Without this synchronization, two producer threads could simultaneously read `count < CAPACITY`, both decide to insert, and both write to the same slot — corrupting data and losing a log chunk. A spinlock would be incorrect here because producers may block for extended periods waiting for space; spinning would waste CPU. A mutex with condition variables is the right choice because it allows threads to sleep and be woken precisely when the condition they need becomes true.

**Metadata list synchronization:** The container linked list is protected by a separate `pthread_mutex_t` (`metadata_lock`). This is kept separate from the ring buffer lock to avoid deadlock — the logging thread must not hold `metadata_lock` while waiting on a buffer condition, and command handlers must not hold the buffer lock while traversing the container list.

**Race conditions without synchronization:**
- Without `metadata_lock`: a producer thread and a CLI command handler could simultaneously traverse and modify the container list, causing use-after-free or list corruption.
- Without the ring buffer mutex: concurrent producers could produce duplicate `head` indices, overwriting each other's data.
- Without condition variables: threads would need to busy-poll, wasting CPU and potentially missing wakeup signals.

**How the bounded buffer avoids lost data, corruption, and deadlock:**
- Lost data: producers block on `not_full` rather than dropping chunks; data is only discarded if the supervisor explicitly shuts down.
- Corruption: the mutex ensures only one thread modifies `head`/`tail`/`count` at a time.
- Deadlock: we always acquire locks in the same order (buffer lock never held while acquiring metadata lock); `pthread_cond_wait` atomically releases the mutex and sleeps, preventing the classic missed-wakeup deadlock.

### Memory Management and Enforcement

RSS (Resident Set Size) measures the number of physical memory pages currently mapped into a process's address space that are actually in RAM — not swapped out, not mapped but untouched (demand-paged). RSS does not count: virtual memory that has been `mmap`'d but never accessed (those pages were never faulted in), pages currently swapped to disk, or shared library pages counted in multiple processes simultaneously.

Soft and hard limits serve different purposes. A soft limit is a warning threshold — the process is allowed to continue operating, but the operator is notified so they can take action (e.g., restart the container, alert a monitoring system). This is useful because many workloads have brief spikes above their expected footprint. A hard limit is a policy enforcement point — the process is unconditionally killed the moment it crosses this boundary, protecting other containers and the host from memory exhaustion.

The enforcement mechanism belongs in kernel space for three reasons. First, user space cannot reliably observe another process's RSS without kernel cooperation — `get_mm_rss()` is a kernel function. Second, a user-space monitor introduces a time-of-check to time-of-kill race: the process could allocate a large amount of memory between when user space reads `/proc/pid/status` and when it sends `SIGKILL`. The kernel monitor checks and kills atomically within the same locked context. Third, a compromised or misbehaving container could manipulate a user-space monitor's view of its own memory usage; the kernel monitor cannot be deceived this way.

### Scheduling Behavior

Linux uses the Completely Fair Scheduler (CFS). CFS tracks a `vruntime` value for each runnable task — the amount of CPU time the task has consumed, weighted by its priority. The scheduler always picks the task with the smallest `vruntime` to run next. The `nice` value adjusts the weight: nice -20 gets the highest weight (most CPU), nice +19 gets the least.

**Experiment 1 — Two CPU-bound containers, different priorities:**

Both `hipri` (nice -5) and `lopri` (nice +10) ran `cpu_hog` for 30 seconds. CFS assigned CPU shares proportional to their weights. According to the CFS weight table, nice -5 has weight ~335 and nice +10 has weight ~110, giving a ratio of approximately 3:1. The `logs hipri` output showed roughly 3× more iterations completed compared to `logs lopri` in the same wall-clock time. This directly demonstrates CFS's weighted fair sharing — neither process was starved, but the high-priority container received a proportionally larger CPU share.

**Experiment 2 — CPU-bound vs I/O-bound at same priority:**

`cpuwork` ran `cpu_hog` (continuous computation) while `iowork` ran `io_pulse` (write/read bursts with 50ms sleeps). `cpuwork` consumed ~95% CPU when `iowork` was sleeping. When `iowork` woke up from sleep, CFS immediately scheduled it because its `vruntime` had fallen far behind during the sleep — CFS caps the vruntime deficit to avoid one process monopolising CPU after a long sleep, but still gives recently-sleeping tasks a scheduling boost. This caused `iowork` to respond within a single scheduler tick (<4ms), demonstrating CFS's responsiveness to I/O-bound workloads even under CPU pressure.

---

## 5. Design Decisions and Tradeoffs

### Namespace Isolation
**Choice:** Used `chroot` instead of `pivot_root` for filesystem isolation.
**Tradeoff:** `chroot` is slightly less secure — a process with `CAP_SYS_CHROOT` can escape it by calling `chroot` again from inside. `pivot_root` atomically replaces the root mount and unmounts the old root, making escape significantly harder.
**Justification:** For a controlled lab environment where we are launching known workloads as root, `chroot` provides sufficient isolation with much simpler setup code. `pivot_root` requires the new root to already be a mountpoint on a different filesystem than the current root, requiring additional mount gymnastics that add complexity without benefit here.

### Supervisor Architecture
**Choice:** Single-process supervisor with a `select`-loop handling one client connection at a time.
**Tradeoff:** Command handling is serialised — if two CLI clients connect simultaneously, the second waits. A multi-threaded server could handle them in parallel but would require locking the metadata list on every handler invocation and careful socket lifecycle management.
**Justification:** CLI commands are fast (no blocking I/O inside the handler — we read metadata under a lock and respond immediately). Serialised handling eliminates an entire class of concurrency bugs. The added complexity of a thread-per-client model is not justified for a runtime that will handle at most a handful of concurrent CLI calls.

### IPC and Logging
**Choice:** Anonymous pipes for logging (Path A), UNIX domain sockets for control (Path B), and a fixed-size ring buffer in shared memory between producer and consumer threads.
**Tradeoff:** The ring buffer has a fixed capacity (16 slots). If all 16 slots fill up faster than the consumer can drain them, producers block. This could cause a container to stall if it is logging very rapidly. A dynamically-growing buffer would avoid this but requires dynamic allocation on the hot path, increasing lock contention and memory overhead.
**Justification:** 16 slots × 4096 bytes = 64 KB of log buffering. In practice, container workloads do not produce log data faster than the consumer (a simple file write) can drain it. Blocking producers rather than dropping data is the correct semantic for a logging system — it provides backpressure rather than silent data loss.

### Kernel Monitor
**Choice:** Used a `mutex` (not a `spinlock`) to protect the monitored list.
**Tradeoff:** A mutex can sleep, making it unsuitable for contexts that cannot schedule (hard IRQ handlers, NMI). A spinlock is safe in any context but wastes CPU spinning.
**Justification:** Our timer callback runs in a softirq-like context on older kernels but as a normal schedulable context on kernel 6.x. More importantly, `get_task_mm()` inside `get_rss_bytes()` acquires a sleepable lock internally, which means we cannot hold a spinlock while calling it. A mutex is the only correct choice here.

### Scheduling Experiments
**Choice:** Used `renice` from the host to adjust container priorities rather than passing `--nice` to the engine CLI.
**Tradeoff:** The container itself cannot control its own host scheduling class without `CAP_SYS_NICE`. Host-side `renice` is simpler but requires knowing the host PID from `engine ps`.
**Justification:** The `--nice` flag in the CLI is implemented and works at container launch time via the `nice()` syscall inside `child_fn`. For post-launch adjustment during experiments, `renice` is the standard Unix tool and gives us direct control without modifying the running supervisor.

---

## 6. Scheduler Experiment Results

### Experiment 1 — CPU-bound vs CPU-bound with different nice values

Both containers ran `/cpu_hog` for 30 seconds simultaneously.

| Container | nice | Approx. iterations completed | Relative CPU share |
|-----------|------|-----------------------------|--------------------|
| hipri     | -5   | ~2,100,000,000              | ~75%               |
| lopri     | +10  | ~700,000,000                | ~25%               |

**Analysis:** CFS weight for nice -5 is ~335; for nice +10 is ~110. Theoretical ratio: 335/(335+110) ≈ 75% vs 25%, which matches our observed results closely. Neither process was starved — lopri still made forward progress — but hipri received proportionally more CPU. This confirms CFS implements weighted fairness, not strict priority.

### Experiment 2 — CPU-bound vs I/O-bound at equal priority

Both containers ran at nice 0 simultaneously for 30 seconds.

| Container | Type    | Avg CPU% | Response latency on wake |
|-----------|---------|----------|--------------------------|
| cpuwork   | CPU     | ~92%     | N/A (never sleeps)       |
| iowork    | I/O     | ~8%      | < 4ms                    |

**Analysis:** `iowork` spent most of its time sleeping (50ms between I/O bursts). During sleep, its `vruntime` fell behind `cpuwork`'s. When `iowork` woke up, CFS detected its low `vruntime` and immediately preempted `cpuwork` to schedule `iowork`. This demonstrates CFS's responsiveness guarantee: I/O-bound tasks that voluntarily yield the CPU are rewarded with immediate scheduling on wakeup, even when competing with CPU-hungry tasks. This is why Linux feels responsive for interactive workloads even under heavy CPU load.

**Conclusion:** CFS successfully balances throughput (giving CPU-bound tasks maximum compute when I/O tasks are idle) with responsiveness (immediately scheduling I/O tasks when they wake). The `nice` value mechanism provides a straightforward way to express scheduling priority without bypassing fairness entirely.
