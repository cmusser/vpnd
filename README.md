# vpnd
tun-based VPN for BSD

## Overview

vpnd provides an encrypted tunnel between two BSD machines serving as
security gateways. It uses security primitives in the NaCl
cryptography library and implements a protocol that frequently changes
the keys used to encrypt the traffic. The intent of this is to provide
"perfect forward secrecy", wherein the future compromise of long-term
keys does not compromise the security of past sessions. The persistently
stored keys are only used to start (or restart) the communication. The
system uses ```tun(4)``` interfaces to provide a layer 3 tunnel,
transporting encrypted packets in UDP datagrams.

Other modes of operation, for example layer 2 tunneling, or a mode in
which a client host directly attaches to the VPN are possible, but have
not been explored yet.

vpnd is designed to be simple and hopefully secure as a result of
that. It requires little configuration and has only one mode of
operation. It was inspired by other, similar projects, principally
QuickTUN, whose author helpfully gave some advice on network
configuration while this project was still in the planning stage.

vpnd differs from QuickTUN in the following ways mostly in ways that
yield a small, hopefully readable codebase:

- No reduced security modes: no options for unencrypted transport or
  an unchanging nonce. vpnd always uses a sequence of ephemeral 
  sessuib keys to encrypt and decrypt traffic.

- BSD only at the moment. Linux could be supported by replacing the
  event handling code (kqueue) with epoll and whatever handles signals
  and timers.

- Layer 3 only. It could open up a tap(4) interface instead of a
  tun(4), but more investigation into the specific network
  configuration is required.

- Doesn't run an ancillary script to set up the networking.


## Requirements

1. FreeBSD or DragonFlyBSD (might work on the other BSDs too).
2. libsodium >= 1.0.7


## Usage

### Configuration And Startup

The configuration file (```vpnd.conf``` in the current directory, by
default) contains one parameter per line, in the following format:

```param_name: value```

1. Use the ```keypair``` program to create a public/private keypair and
   the resulting public key to the operator of the peer system
2. Get the peer's public key.
3. In the configuration file, specify the following parameters:
		- ```local_sk``` the locally generate secret key.
		- ```remote_pk``` the peer's public key
		- ```remote_host```: the name or IP address of the peer gateway.
4. Start the server (```vpnd```). When getting a setup working
   initially, foreground mode (```-f```) is helpful.


### Networking

After the server processes are started, secure communication between
them should work. If they were started in foreground mode, you can
type lines of text into a console and they will appear in the console
of the other side. This will work even if no networking setup (steps 1
and 2 below) has been done.

To enable communication between the two internal networks, interfaces
and routes must be set up. The current design assumes that two private
networks are to be connected by gateways connected to a public
network.

1. Make sure the local machine has an address on the network that you
   want to make available to the remote side. The ```test/ifup.sh```
   script is a contrived example of this, adding an extra address to
   the existing wlan0 interface. A host already serving as a gateway
   will likely already have addresses on external and an internal
   interfaces. In this case, the internal address is of interest.

2. Add a route to the remote side's internal network via the
   ```tun0``` interface. The ```test/tunup.sh``` script is an example
   of this. Note that the addresses in the script (which specify the
   local and destination addresses of the point-to-point link) are not
   necessary in order to route traffic. These addresses are in the
   script because, on DragonFlyBSD, sending traffic to an interface
   without an address causes a kernel panic. These addresses can be
   removed on FreeBSD and maybe other BSD variants.

3. Repeat these steps for the remote side.

4. Communication between the two private networks should now be
   possible. Pings should work and the
   ```test/nc-{client,server}.sh``` scripts run netcat for the purpose
   of verifying real two-way traffic.
