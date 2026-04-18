# NIC Pinning for Bonded Paths

When a bond has multiple paths, you almost always want each path to
egress a **different** physical NIC — an LTE modem, a Starlink
uplink, a fibre drop, etc. Without pinning, the kernel picks the
outbound interface from its routing table based on the **destination**
IP, so if every path terminates at the same relay or hub all paths
collapse onto the default route and the bond becomes cosmetic.

This document explains the three ways to pin a path to a NIC, which
one bilbycast-bonding uses by default, and when to reach for the
others.

## TL;DR — the nice and easy way

Add `interface` to your path config:

```json
{
  "paths": [
    { "id": 0, "name": "lte-0",
      "transport": { "type": "udp", "remote": "hub:7000", "interface": "wwan0" } },
    { "id": 1, "name": "starlink",
      "transport": { "type": "udp", "remote": "hub:7001", "interface": "wwan1" } },
    { "id": 2, "name": "fibre",
      "transport": { "type": "udp", "remote": "hub:7002", "interface": "eth0"  } }
  ]
}
```

On Linux this calls `SO_BINDTODEVICE` and **needs `CAP_NET_RAW`**
(see [capability grant](#granting-cap_net_raw) below). On macOS and
FreeBSD it calls `IP_BOUND_IF` / `IPV6_BOUND_IF` and is **fully
unprivileged**.

If you cannot or do not want to grant the capability, omit
`interface` and use [policy routing](#option-2-source-ip-binding--policy-routing)
instead — no runtime privilege needed.

## What the kernel does without pinning

With an unbound socket or a `0.0.0.0` bind, the kernel consults the
routing table at send time. Simplified: it looks up the destination
IP, finds the matching route (usually just `default via … dev
eth0`), and uses that interface. So:

- Three paths to the same relay → three copies of traffic out `eth0`,
  and the LTE / Starlink uplinks stay idle.
- Three paths to three different relays → the kernel *might* pick
  different interfaces, but only if each has its own specific route.
- Binding the socket to a non-default local IP (e.g. the LTE modem's
  address) doesn't automatically change egress: the kernel still
  consults the main routing table. You need
  [policy routing](#option-2-source-ip-binding--policy-routing) to
  make source-address steering actually work.

Pinning skips this entirely by telling the socket *which device* to
use.

## Option 1: `SO_BINDTODEVICE` / `IP_BOUND_IF` (implemented)

This is what the `interface` config field does. It is the simplest,
least-surprising way to get per-NIC egress.

| Platform | Mechanism | Privilege |
|----------|-----------|-----------|
| Linux, Android | `SO_BINDTODEVICE` | `CAP_NET_RAW` |
| macOS, iOS, tvOS, watchOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` | none |
| FreeBSD, Fuchsia | `IP_BOUND_IF` / `IPV6_BOUND_IF` | none |
| Windows, Others | not implemented | — |

### Granting `CAP_NET_RAW`

You do **not** need to run the process as root. Three options, in
order of preference:

#### 1. File capability (cleanest for bare-metal installs)

```bash
sudo setcap cap_net_raw+ep /usr/local/bin/bilbycast-bonder
sudo setcap cap_net_raw+ep /usr/local/bin/bilbycast-edge
```

The binary runs under an unprivileged user account but retains the
ability to pin sockets to interfaces. Re-run after every upgrade,
since `setcap` is stored in the file's extended attributes and is
lost when the binary is replaced. Most package tooling handles this
in a post-install hook.

#### 2. systemd ambient capability

Add to the unit file:

```ini
[Service]
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
# Still run as a non-root user:
User=bilbycast
Group=bilbycast
```

Works even if the binary isn't `setcap`'d. Recommended for deployments
already managed by systemd.

#### 3. Container (Docker / Kubernetes)

```yaml
# Docker Compose:
services:
  bilbycast-bonder:
    cap_add: [NET_RAW]

# Kubernetes pod spec:
securityContext:
  capabilities:
    add: [NET_RAW]
```

### What if I don't grant the capability?

The bind fails at startup with a clear error:

```
path 'lte-0' pin to interface 'wwan0' failed: Operation not permitted (os error 1)
```

Pick one of the other options below, or grant the capability.

## Option 2: Source-IP binding + policy routing

If elevated capabilities are off the table — audit policy, shared
hosting, strict hardening — you can get the same effect by
configuring the Linux routing subsystem once at install time. No
runtime privilege is needed after that.

Each NIC gets its own routing table and a rule that says *"if the
packet's source IP is X, consult table T"*. Binding the socket to
the NIC's IP (via `bind` in the path config) then naturally steers
egress.

```bash
# Assume: eth0 = 192.168.1.10/24 gw 192.168.1.1
#         wwan0 = 192.168.5.10/24 gw 192.168.5.1

# Per-NIC default routes in dedicated tables:
ip route add default via 192.168.1.1 dev eth0  table 101
ip route add default via 192.168.5.1 dev wwan0 table 102

# Source-based rules:
ip rule add from 192.168.1.10 lookup 101
ip rule add from 192.168.5.10 lookup 102
```

Then configure paths to bind to the source IP and leave `interface`
unset:

```json
{
  "paths": [
    { "id": 0, "name": "eth",
      "transport": { "type": "udp", "bind": "192.168.1.10:0", "remote": "hub:7000" } },
    { "id": 1, "name": "lte",
      "transport": { "type": "udp", "bind": "192.168.5.10:0", "remote": "hub:7001" } }
  ]
}
```

Persist the `ip rule` / `ip route` commands via `/etc/network/interfaces`,
NetworkManager dispatchers, or `systemd-networkd` `.network` files so
they survive reboots and interface flaps.

Downside: easy to mis-configure. Every new NIC needs a new table and
rule; an IP change on a modem (common on LTE) breaks the rule. A
single `interface: "wwan0"` in the config is always correct.

## Option 3: Network namespaces / VRFs

Heavy-duty isolation. Each uplink lives in its own netns or VRF;
the bonder runs a per-path worker inside each one.

Good when you also want to isolate DNS, routing, and local services
(e.g. the LTE uplink has its own DNS and should not leak to the
default resolver). Expensive operationally, harder to observe with
plain `ss` / `ip` / `netstat`, and `CAP_NET_ADMIN` is needed to set
them up anyway.

Not wired into bilbycast-bonding today. If you need this, run one
`bilbycast-bonder` process per namespace and aggregate externally.

## Operational notes

- **One `interface` per path**, not one per bond. Different paths in
  the same bond can use different pinning strategies (e.g. pin the
  cellular modem by name, leave the wired Ethernet to the default
  route).
- **Check the wire with `ss` after startup**: `ss -u -n | grep
  <port>` should show each socket on its expected local address.
  On Linux, `ss -e` also prints the bound device when
  `SO_BINDTODEVICE` is set.
- **Interface names must match the kernel's view** (`ip link`,
  `ifconfig`). On Linux the limit is 15 characters (`IFNAMSIZ - 1`);
  bilbycast-bonding validates this at config load.
- **IPv6 is handled transparently** — the same `interface` field
  pins both IPv4 and IPv6 UDP sockets.
- **Mobile interfaces can change index on reconnect**; the bonding
  stack re-resolves the name → index mapping at socket creation
  time, not once at process start, so `wwan0` coming back up after
  a drop works as expected. (Linux also accepts the name directly,
  which sidesteps the index entirely.)
- **This only affects UDP paths.** QUIC, RIST, and SRT paths have
  their own bind configurations; pinning for those transports is
  tracked separately.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `path pin to interface 'xxx' failed: Operation not permitted` | Linux without `CAP_NET_RAW`. | [Grant the capability](#granting-cap_net_raw) or switch to [policy routing](#option-2-source-ip-binding--policy-routing). |
| `path pin to interface 'xxx' failed: No such device` (Linux) / `… if_nametoindex returned 0` (macOS/BSD) | Interface doesn't exist or is typo'd. | Check `ip link` / `ifconfig`. Mobile interfaces may still be coming up — retry after the modem attaches. |
| `NIC pinning is not supported on this platform` | Running on Windows or another unsupported OS. | Use policy routing. Windows has `IP_UNICAST_IF` but it is not wired into bilbycast-bonding yet. |
| Traffic still all on one NIC despite `interface` set | Destination is reachable only through one gateway and the pinned NIC has no route back. | Check return path: pinned egress still needs a working reverse path to the remote. |
| Interface binds OK but no response packets | Asymmetric routing — peer replies to the "wrong" address. | Ensure the pinned NIC's IP is the one the remote sees; consider a dedicated remote port per NIC so peers don't collapse return traffic. |
