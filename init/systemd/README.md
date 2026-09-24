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
