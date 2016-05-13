# vpnd
tun-based VPN for BSD

## Overview

vpnd provides an encrypted tunnel between two BSD machines serving as
security gateways. It uses security primitives provided by the NaCl
cryptography library uses frequently changing ephemeral keys to provide
"perfect forward secrecy". This means a future compromise of long-term
keys does not compromise the security of past sessions. The persistently
stored keys are only used to start (or restart) the communication.

Other modes of operation, for example layer 2 tunneling, or a mode in
which a client host directly attaches to the VPN are possible, but have
not been explored yet.

vpnd is designed to be simple and hopefully secure as a result of
that. It requires little configuration and has only one mode of
operation. It was inspired by other, similar projects, principally
QuickTUN, whose author helpfully gave some advice on network
configuration while this project was still in the planning stage.


- No reduced security modes: no options for unencrypted transport
  unchanging nonces. Ephemeral keys are always used.

- BSD only at the moment. Linux could be supported by replacing the
  event handling code (based on ```kqueue```) with ```epoll``` and
  whatever handles signals and timers.

- Layer 3 only. It could open up a ```tap(4)``` interface instead of a
  ```tun(4)```, but more investigation into the specific network
  configuration is required.

- Doesn't run an ancillary script to set up the networking. An
  example script is provided.

- Easy to configure on a pair of router hosts, but also can be used on
  a client. This is harder to manage for lots of clients because the
  process is currently designed to talk to a single peer.



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

### Complete List Of Parameters

|Parameter Name|Description|Required?|
|---|---|---|
|device|The tunnel device path  |no, defaults to ```/dev/tun0```.|
|stats_prefix|prefix to use for Graphite data  |no, defaults to value from```gethostname(3)```.|
|local_sk|The local secret key|yes, use values from ```keypair``` program.|
|local_port|local UDP port to listen on|no, defaults to 1337.|
|remote_pk|The peer's public key|yes, use values from ```keypair``` program|
|remote_host|hostname or IP address of|yes|
|remote_port|UDP port on peer to listen on|no, defaults to 1337.|
|max_key_age|Maximum age for ephemeral key, in seconds.|no, defaults to 60 seconds.|
|max_key_packets|Maximum number of packets that can be sent with ephemeral key|no defaults to 100,000.|

### Networking

After the server processes are started, secure communication between
them should work. If they were started in foreground mode, you can
type lines of text into a console and they will appear in the console
of the other side. This will work even if no networking setup (steps 1
and 2 below) has been done.

To enable communication between the two internal networks, interfaces
and routes must be set up. The ```test/test.sh``` has examples of the
commands to run, but the procedure is outlined below:

1. Make sure the local machine has an address on the network that you
   want to make available to the remote side. The ```test/test.sh```
   script adds an extra address to an existing interface, but a host already
   serving as a gateway will likely already have addresses on external
   and internal interfaces.

2. Add a route to the remote side's internal network via the
   tunnel interface. The ```test/test.sh``` script has an example
   of this as well.

3. Repeat these steps for the remote side. To set up a simple test
   on a pair of laptops using the test script, run the following pair
   of commands, one on the client and the other on the server:

       test/test.sh -iwlan0 -mclient
       test/test.sh -iwlan0 -mserver

   The -iwlan0 can be omitted after the first run.

4. Communication between the two private networks should now be
   possible. Pings should work and the ```netcat(1)``` program started
   by the test script can be used for verifying real two-way traffic.

### Statistics and Diagnostics

The current state is sent to the current logging output if the process receives
the ```USR1``` signal or if ```stats``` is typed into the console in foreground
mode. Graphite plaintext formatted statistics are available by connecting to
the ```/var/run/vpnd_stats.sock``` UNIX domain socket. An example of doing this
is:
    sudo nc -U /var/run/vpnd_stats.sock
or
    socat - UNIX-CONNECT:/var/run/vpnd_stats.sock
