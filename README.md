# vpnd
tun-based VPN for DragonFlyBSD

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

- DragonFlyBSD-only at the moment. Support for the other BSDs still needs
  some minor porting work and Linux is possible as well. The status of porting
  is described below.

- Layer 3 transport. Saves bandwidth and prevents broadcast traffic
  from traversing the link.

- Supports two well-defined VPN use cases:

	- An individual client host needing access to a remote network,
	  and a security gateway providing access to one or more such
	  clients. This allows individual clients to access a main
	  network.

	- A pair of hosts acting as security gateways that connect two
	  private networks together via a secure link. This connects
	  all the hosts in two sites together.


## Requirements

1. DragonFlyBSD
2. libsodium >= 1.0.7
3. The `resolvconf` utility.

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
gateway host providess the client with an address on its local network
and becomes an ARP proxy for that address. This arrangement allows
any number of clients to participate on the remote network, each served
by a dedicated `vpnd` process. The ARP proxy technique offers a couple
of advantages. It eliminates the need to configure routes on any other
routers on the host network: remote clients simply appear to be hosts 
attached to the LAN. Because layer 2 is terminated at the VPN host,
the connection need only pass layer 3. This reduces bandwidth and
prevents broadcast traffic from traversing the link. It also simplifies
the codebase, because only one type of tunnel (the `tun(4)`) needs to 
be supported.

## Configuration and Startup
The configuration file (`vpnd.conf` in the current directory, by
default) contains one parameter per line, in the following format:

`param_name: value`

### Key Generation
1. Use the `keypair` program to create a public/private keypair and
   the resulting public key to the operator of the peer system
2. Get the peer's public key.
3. In the configuration file, specify the following parameters:
		- `local_sk` the locally generate secret key.
		- `remote_pk` the peer's public key
		- `remote_host`: the name or IP address of the peer gateway.

### Command Line Parameters
|Option|Description|Notes|
|---|---|---|
|`-v`| verbosity level|Specify once for NOTICE level verbosity, multiple times for DEBUG|
|`-f`| foreground mode|Run in foreground. The default is to run as a  daemon|
|`-c`| configuration file|Name of configuration file. The default is `vpnd.conf` in the current working directory|

### Configuration File Parameters
|Parameter Name|Description|Required?|
|---|---|---|
|role|The networking role to assume: `net-gw`, `host-gw`, or `host`. These roles are explained above|no, defaults to `net-gw`|
|device|The tunnel device path  |no, defaults to `/dev/tun0`.|
|stats_prefix|prefix to use for Graphite data  |no, defaults to value from`gethostname(3)`.|
|local_sk|The local secret key|yes, use values from `keypair` program.|
|local_port|local UDP port to listen on|no, defaults to 1337.|
|remote_pk|The peer's public key|yes, use values from `keypair` program|
|remote_host|hostname or IP address of remote peer.|yes, in `host` and `net-gw` role.|
|host_addr|In `host-gw` mode, the address to assign to the client and the prefix length of the associated network|yes, in `host-gw` role. Specified in CIDR notation, ie 192.168.1.1/24|
|resolv_addr|In `host-gw` mode, the address of the DNS resolver to be used by the client|no|
|resolv_domain|In `host-gw` mode, the DNS search domain to be used by the client|no|
|resolvconf_path|In `host` mode, the path to the `resolvconf` utility|no, defaults to `/sbin/resolvconf`|
|remote_port|UDP port on peer to listen on|no, defaults to 1337.|
|max_key_age|Maximum age for ephemeral key, in seconds.|no, defaults to 60 seconds. Range is 30-3,600|
|max_key_packets|Maximum number of packets that can be sent with ephemeral key|no, defaults to 100,000. Range is 5000-10,000,000|
|nonce_file|Name of nonce reset point file|no, defaults to `vpnd.nonce`|
|nonce_reset_incr|Interval for creating nonce reset point|no, defaults to 10000. Range is 16-20000|
### Configuration Examples

#### Network Gateways

In this example, private network #1 is 172.16.0.0/16 and the VPN gateway's
address on this network is 172.16.0.2. Private network #2 is 10.1.0.0/16
and the VPN gateway's address on this network is 10.1.0.2. We assume that
both networks have another host that acts as the default router.

##### Gateway #1 config:

```
local_sk: <local secret key>
remote_pk: <gateway #2 public key>
role: net-gw
remote_host: vpn-gw.network-2.com
```
Private network #1's default router needs to be configured with a route
to private network #2, via its local VPN gateway:

`route add 10.1.0.0/16 172.16.0.2`

##### Gateway #2 config:

```
local_sk: <local secret key>
remote_pk: <gateway #1 public key>
role: net-gw
remote_host: vpn--gw.network-1.com
```
Similar to the above, private network #2's default router needs to
be configured with a route to private network #1, via its local VPN
gateway:

`route add 172.16.0.0/16 10.1.0.2`

#### Host/Host Gateway

In this example the host gateway's network is 192.168.1.0/24. The client host
can be anywhere. On the host gateway, the `vpnd` can be simply started beforehand
in the background.

##### Host Gateway config:

```
local_sk: <host gateway secret key>
remote_pk: <client host public key>
role: host-gw
client_addr: 192.168.1.66/24
```

##### Host configuration

```
local_sk: <client host secret key>
remote_pk: <host gateway public key>
role: host
remote_host: vpn-host-gw.some-domain.com
```
No route establishment, interface configuration or ARP table commands need 
to be manually issued. `vpnd` will perform the necessary configuration.

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
|Mac OS X|Doesn't compile currently and needs the 3rd-party `tun(4)` KEXT. Some compatibility functions are needed for `clock_gettime(2)` and `strtonum(3)`.|
|FreeBSD|Compiles and runs as a `net-gw` and maybe `host`. `host-gw` does not work due to differences in the way the `arp(8)` command works for proxy ARP. This is under investigation.|
|OpenBSD|Doesn't compile: some function signatures are rejected, different `#include`s are needed, some `tun(4)` related `#define`s are different (or not present).|
|NetBSD|unknown (not tried yet)|
|Linux|Could be supported by replacing the event handling code (based on `kqueue`) with `epoll` and the `timerfd_*` and `signalfd` family of functions. A prerequisite is reorganizing the code into OS-specific and non-specific modules.|

## Protocol Details

The `vpnd` network protocol is [explained in detail here](docs/protocol.md) 
