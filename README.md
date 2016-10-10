# vpnd
tun-based VPN

## Overview

`vpnd` provides an encrypted virtual connection between two hosts,
allowing the creation of secure network topologies.

`vpnd` is designed to be simple and, as a result, secure. It requires
little configuration. It was inspired by other, similar projects,
principally QuickTUN, whose author helpfully gave some advice on
network configuration while this project was still in the planning
stage.

## Features

- Uses cryptographic primitives from the well-regarded NaCl library.

- No reduced security modes: no options for unencrypted transport or
  unchanging nonces.

- To prevent decryption of recorded conversatons in the case of a
  future private key compromise (a characteristic known as "perfect
  forward secrecy"), `vpnd` uses frequently-changing encryption keys
  while running.

- BSD only at the moment. Linux could be supported by replacing the
  event handling code (based on `kqueue`) with `epoll` and the
  `timerfd_*` and `signalfd` family of functions.

- Layer 3 transport. Saves bandwidth and prevents broadcast traffic
  from traversing the link.

- Supports two well-defined modes of operation:

	- An individual client host needing access to a remote network,
	  and a security gateway providing access to one or more such
	  clients. This allows individual clients to access a main
	  network.

	- A pair of hosts acting as security gateways that connect two
	  private networks together via a secure link. This connects
	  all the hosts in two sites together.


## Requirements

1. FreeBSD or DragonFlyBSD (might work on the other BSDs too).
2. libsodium >= 1.0.7


## Modes of Operation

### Gateway Mode

In this mode, a pair of hosts, each with an interface on an internal
network and another on the Internet, provide a communcation path for
hosts on the internal networks. This is akin to VPN software that
connects geographically separated sites together. This is a useful
setup, but less often seen outside of large companies.

The configuration in this case is static because information about
each network can be shared in advance and does not change often.
Each gateway knows the address of its peer. The addresses of the
other peer's insternal network is also known, and a route to it
via the VPN gateway can be configured in the default gateway for each
internal network. The VPN gateways, in effect become layer 3 routers,
and use the operating system's packet forwarding to move data.

### Client/Server Mode

In this mode, a client host, often operating from behind a firewall,
connects to a host that acts as a gateway to its internal
network. This mode is used more widely: this is how mobile or remote
users connect to corporate networks.

Here, the network configuration is dynamic due to the nature of mobile
hosts and NATs. The gateway needs the address of the client, something
not known until the client actually begins communication. The client
needs an address on the gateway's internal network. Finally, when the
connection becomes active, the gateway host becomes an ARP proxy for
the client for which it is providing access. This allows the client
host (or any number of clients) to participate on the remote network
without needing to configure routes on gateways on the remote
network. Because layer 2 is terminated at the VPN host, the connection
need only pass layer 3. This reduces bandwidth and prevents broadcast
traffic from traversing the link. It also simplifies the codebase,
because only one type of tunnel (the `tun(4)`) needs to be supported.


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
|client_addr|In `host-gw` mode, the address to assign to the client and the prefix length of the associated network|yes, in `host-gw` role. This  Specified in CIDR notation, ie 192.168.1.1/24|
|remote_port|UDP port on peer to listen on|no, defaults to 1337.|
|max_key_age|Maximum age for ephemeral key, in seconds.|no, defaults to 60 seconds. Range is 30-3,600|
|max_key_packets|Maximum number of packets that can be sent with ephemeral key|no, defaults to 100,000. Range is 5000-10,000,000|
|nonce_file|Name of nonce reset point file|no, defaults to `vpnd.nonce`|
|nonce_reset_incr|Interval for creating nonce reset point|no, defaults to 10000. Range is 16-20000|
### Configuration Examples

#### Gateway

TBD

#### Client Server

TBD

### Statistics and Diagnostics

The current state is sent to the current logging output if the process receives
the `USR1` signal or if `stats` is typed into the console in foreground
mode. Graphite plaintext formatted statistics are available by connecting to
the `/var/run/vpnd_stats.sock` UNIX domain socket. An example of doing this
on the command line is:

`nc -U /var/run/vpnd_stats.sock`

or

`socat - UNIX-CONNECT:/var/run/vpnd_stats.sock`
