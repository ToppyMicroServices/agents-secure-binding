# systemd service identity

The agent and computation runner use the static `asb` account. They share this
account because the runner creates `/run/agents-secure-binding/runner.sock` with
mode `0600`. This removes routine root execution without widening the socket to
other local users.

Install the two account and directory declarations before enabling the units:

```text
/usr/lib/sysusers.d/agents-secure-binding.conf
/usr/lib/tmpfiles.d/agents-secure-binding.conf
```

Run `systemd-sysusers` and `systemd-tmpfiles --create` through the package
installer. The installer must also make `/agents-secure-binding` and the
installed binaries readable and executable by `asb`. The environment and agent
configuration files remain owned by root and are readable by the `asb` group.
Do not put private keys directly in either file.

The account is intentionally static so package upgrades and persistent state
retain stable ownership. The units use `RuntimeDirectory=` and `LogsDirectory=`
for the runtime socket and log paths. A future split into separate agent and
runner users requires a systemd-owned socket or an equivalent explicit shared
group; changing only `User=` would make the current `0600` socket unreachable.

These files define the software service profile. A confidential-VM image that
needs additional devices, Docker control, attestation endpoints, or network
capabilities must declare those permissions in its own qualified profile. Do
not restore root merely because a required capability has not yet been named.

Native binary, Python (including virtual-environment preparation and package
installation), and WASM commands require Linux user and PID namespaces. The
runner creates both namespaces atomically before executing each command and
maps only its current effective user and group IDs. The command is PID 1 in
that namespace. When it exits or is stopped, Linux kills all namespace
descendants, including detached sessions and nested PID namespaces, before
the runner's wait completes. The runner retains its active-run admission slot
until that wait returns. See [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
and the kernel's [`zap_pid_ns_processes`](https://github.com/torvalds/linux/blob/master/kernel/pid_namespace.c).

The kernel must enable user and PID namespaces, and the deployed service and
host security policy must permit their creation by `asb`. If creation is denied,
the command fails before execution; there is no process-group fallback. Qualify
this behavior on the target image with the algorithm and runner tests. Do not
enable cgroup delegation to compensate: a workload running as the same user
could otherwise move out of a delegated per-run cgroup.

Native computation execution on macOS and other non-Linux Unix platforms now
fails before executing code because the previous process-group mechanism did
not contain detached children. Windows continues to use its existing Job
Object boundary. This compatibility change does not affect the supported core
verifier. These lifetime controls do not provide filesystem, network, or memory
resource isolation. The command sees PID 1 and the inherited host `/proc` mount;
programs that require host PID semantics need a separately qualified runtime.
