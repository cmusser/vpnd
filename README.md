# vpnd
NaCl-based VPN for UNIX systems

## Overview

`vpnd` provides an encrypted virtual connection between two hosts,
allowing the creation of secure network topologies.

`vpnd` is designed to be simple and, as a result, secure. It requires
little configuration. `vpnd` was inspired by other, similar projects,
principally QuickTUN, whose author helpfully gave some advice on
network configuration while this project was still in the planning
stage.

## Features

- Uses NaCl cryptographic primitives. provided by the `libsodium` library.

- No reduced security modes, such as unencrypted transport or unchanging nonces.

- Frequently-changing encryption keys increase the difficulty of
  decrypting recorded flows in the future, even if the initial private
  keys are compromised. This is known as "forward secrecy".

- Layer 3 transport. Saves bandwidth and prevents broadcast traffic
  from traversing the link.

- Supports two well-defined VPN use cases:

	- An individual client host needing access to a remote network,
	  and a security gateway providing access to one or more such
	  clients. This allows individual clients to access a main
	  network.

	- A pair of hosts acting as security gateways that connect two
	  internal networks together via a secure link. This connects
	  all the hosts in two sites together.

## Requirements

1. A BSD or Linux system. Development is on {DragonFly,Free,Net}BSD, and
   Arch Linux.
2. libsodium >= 1.0.7
3. The `resolvconf` utility (only needed for HOST role)

## Modes of Operation

### Network Gateway Mode

In this mode, a pair of hosts--each with an interface on an internal
network and another on the Internet--provide a communcation path for
other hosts on the internal networks. This is akin to VPN software
that connects geographically separated sites together. This is a useful
setup, but less often seen outside of large companies.

The configuration in this case is static because information about
each network can be shared in advance and does not change often.
Each gateway knows the address of its peer. The addresses of the
other peer's internal network is also known, and a route to it
via the VPN gateway can be configured in the default gateway for each
internal network. The VPN gateways, in effect become layer 3 routers,
and use the operating system's packet forwarding to move data.

### Host/Host Gateway Mode

In this mode, a client host, often operating from behind a firewall,
connects to a host that acts as a gateway to its internal
network. This mode is used more widely: this is how mobile or remote
users connect to corporate networks.

Here, the network configuration is dynamic due to the nature of mobile
hosts and NATs. `vpnd` performs the various network stack configuration
changes, making connections easy to establish. The gateway discovers
the address of the client host by passively listening until the client
actually begins communication. When the connection becomes active, the
gateway host provides the client with an address on a network dedicated
to VPN clients, the network address of the internal network and DNS
resolver information. This arrangement allows any number of clients to
access the internal network, each served by a dedicated `vpnd` process.
As in the network gateway setup, the VPN gateway becomes a layer 3 router
forwarding packets between connected clients and the internal network.
## Configuration and Startup
The configuration file (`/etc/vpnd.conf` by default) contains one parameter
per line, in the following format:

`param_name: value`

### Key Generation
1. Use the `vpnd-keygen` program (included with the distribution)
   to create a public/private keypair and give the resulting public key
   to the operator of the peer system.
2. Get the peer's public key.
3. In the configuration file, specify the following parameters:
		- `local_sk` the locally generate secret key.
		- `remote_pk` the peer's public key
		- `remote_host`: the name or IP address of the peer gateway.

### Command Line Parameters
|Option|Description|Notes|
|---|---|---|
|`-v`| verbosity level|Specify once for NOTICE level verbosity, multiple times for DEBUG|
|`-V`| display version, then exit|
|`-f`| foreground mode|Run in foreground. The default is to run as a daemon|
|`-c`| configuration file|Name of configuration file. The default is `/etc/vpnd.conf`|

### Configuration File Parameters
|Parameter Name|Description|Required?|
|---|---|---|
|role|The networking role to assume: `net-gw`, `host-gw`, or `host`. These roles are explained above|no, defaults to `net-gw`|
|device|The tunnel device name  |no, defaults to `tun0`.|
|stats_prefix|prefix to use for Graphite data  |no, defaults to value from`gethostname(3)`.|
|local_sk|The local secret key|yes, use values from `vpnd-keygen` program.|
|local_port|local UDP port to listen on|no, defaults to 4706.|
|remote_pk|The peer's public key|yes, use values from `vpnd-keygen` program|
|remote_host|hostname or IP address of remote peer.|yes, in `host` and `net-gw` role.|
|remote_network|In `net-gw` mode, the address of the remote network.|no,  defaults to unconfigured. Specified in CIDR notation, ie 192.168.1.0/24|
|local_network|The address of the local network.|yes, in `host-gw` role. Specified in CIDR notation, ie 192.168.1.0/24|
|host_addr|In `host-gw` mode, the address to assign to the client and the prefix length of the associated network|yes, in `host-gw` role. Specified in CIDR notation, ie 192.168.1.1/24|
|resolv_addr|In `host-gw` mode, the address of the DNS resolver to be used by the client|no|
|resolv_domain|In `host-gw` mode, the DNS search domain to be used by the client|no|
|resolvconf_path|In `host` mode, the path to the `resolvconf` utility|no, defaults to `/sbin/resolvconf`|
|ip_path|On Linux, the path to the `ip` utility|no, defaults to `/sbin/ip`|
|remote_port|UDP port on peer to listen on|no, defaults to 4706.|
|max_key_age|Maximum age for ephemeral key, in seconds.|no, defaults to 60 seconds. Range is 30-3,600|
|max_key_packets|Maximum number of packets that can be sent with ephemeral key|no, defaults to 100,000. Range is 5000-10,000,000|
|local_nonce_file|Name of local nonce reset point file|no, defaults to `/var/db/local_vpnd.nonce`|
|remote_nonce_file|Name of remote nonce file|no, defaults to `/var/db/remote_vpnd.nonce`|
|nonce_reset_incr|Interval for creating the reset point for the local nonce|no, defaults to 10000. Range is 16-20000|
### Configuration Examples

#### Network Gateways

In this example, internal network #1 is 172.16.0.0/16 and the VPN gateway's
address on this network is 172.16.0.2. Internal network #2 is 10.1.0.0/16
and the VPN gateway's address on this network is 10.1.0.2. We assume that
both networks have another host that acts as the default router.

##### Gateway #1 config:

```
local_sk: <local secret key>
remote_pk: <gateway #2 public key>
role: net-gw
remote_network 10.1.0.0/16
remote_host: vpn-gw.network-2.com
```
Internal network #1's default router needs to be configured with a route
to internal network #2, via its local VPN gateway:

`route add 10.1.0.0/16 172.16.0.2`

##### Gateway #2 config:

```
local_sk: <local secret key>
remote_pk: <gateway #1 public key>
role: net-gw
remote_network: 172.16.0.0/16
remote_host: vpn--gw.network-1.com
```
Similar to the above, internal network #2's default router needs to
be configured with a route to internal network #1, via its local VPN
gateway:

`route add 172.16.0.0/16 10.1.0.2`

Note that the `remote_network` parameter is optional. If you don't want
vpnd to add a route to the remote network via the tunnel, omit this
parameter and configure the networking manually as needed. This is
a sort of "raw" mode for custom network topologies.

#### Host/Host Gateway

In this example the host gateway's network is 192.168.1.0/24 and its
address is 192.168.1.2. 192.168.30.0/24 is a network block dedicated
to VPN clients. On the host gateway, the `vpnd` can be started beforehand
in the background. The client can be located on any network; it's location
need not be known beforehand.

##### Host Gateway config:

```
local_sk: <host gateway secret key>
remote_pk: <client host public key>
role: host-gw
client_addr: 192.168.30.66/24
local_network: 192.168.2.0/24
resolv_addr: 192.168.1.2
resolv_domain: my-internal-domain
```
Similar to the network gateway case, the internal network's default
router needs to route to the VPN client network via the VPN gateway:

`route add 192.168.30.0/24 192.168.1.2`

##### Host configuration

```
local_sk: <client host secret key>
remote_pk: <host gateway public key>
role: host
remote_host: vpn-host-gw.some-domain.com
resolvconf_path: /usr/local/sbin/resolvconf
```
No route establishment or interface configuration commands need to be manually
issued. `vpnd` will perform the necessary configuration. Note that the above
specifies `resolvconf_path` which is not needed on systems that install `resolvconf`
in the default place. If the system does need to have `resolvconf` installed as an
add-on feature, make sure that the resolver configuration is properly symlinked, e.g.

```
ln -s /usr/local/etc/resolvconf/run/resolv.conf /etc/resolv.conf
```

## Statistics and Diagnostics

The current state is sent to the current logging output if the process receives
the `USR1` signal or if `stats` is typed into the console in foreground
mode. Graphite plaintext formatted statistics are available by connecting to
the `/var/run/vpnd_stats.sock` UNIX domain socket. An example of doing this
on the command line is:

`nc -U /var/run/vpnd_stats.sock`

or

`socat - UNIX-CONNECT:/var/run/vpnd_stats.sock`

## Operating System Compatibility
|Operating System|Notes|
|---|---|
|DragonFlyBSD|Works in all modes.|
|FreeBSD|Works in all modes.|
|NetBSD|Works in `host-gw` and `net-gw` modes. `host` mode untested|
|Linux|Works in `host` mode. The other modes are untested, but are likely to work|
|Mac OS X|Doesn't compile currently. Needs the 3rd-party `tun(4)` KEXT.  A compatibility function is needed for `clock_gettime(2)`.|

## Protocol Details

The `vpnd` network protocol is [explained in detail here](docs/protocol.md) 

Nonces are an important part of the system, so a [discussion of how `vpnd`
handles them](docs/nonces.md) is also available.
