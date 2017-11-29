# Message Protocol

This describes the protocol used by vpnd peers

## Overview

The goal of the network protocol is to securely transmit data between
the two peers, changing the encryption keys used on a regular basis
and retransmitting protocol (meaning non-data) messages if the peer
acknowledgement is not received. UDP is used, meaning that retransmission
of the data packets is up to the higher layer protocols being transported

## Roles

`vpnd` supports two uses cases. The first is a pair of network gateways
providing access to hosts on the peer's internal network. The second is
a "client/server" pair in which one peer provides access to its internal
network to a single host.

In the first use case, both peers use the `net-gw` role. In the second,
the client assumes the `host` role and the server (the access provider)
assumes the `host-gw` role.

## Key Master/Slave

At the outset of communication, `vpnd` peers choose one peer to be the
initiator of periodic key changes. The protocol states that begin with
`MASTER_` or `SLAVE_` denote this particular attribute. Either peer
can be initiator; it is not based on the role. The decision is based on
the peers exchanging random numbers and comparing them to see which is
largest.

## Protocol operation

1. On startup, `vpnd` obtains a random number used to determine which
   peer is to initiate periodic key regeneration. It uses the local
   private key and remote public key that appear in the configuration
   file to generate the initial shared key.

2. If a `vpnd` is configured as a HOST_GW, i.e. servicing a specific
   client, its initial state is `HOST_WAIT`. It passively listens for
   the initial `PEER_INFO` message from the peer. It gets the peer's
   address from the received datagram and changes to the `INIT` state.

3. For all other roles, the initial state is `INIT`. `vpnd` transmits
   a `PEER_INFO` message containing the random number generated
   earlier.  When these messages are received in this state, the
   peer's number is compared with the locally generated number. If the
   local number is greater than the peer, this `vpnd` will become the
   key master and changes to the `MASTER_KEY_STALE` state. If the
   local number is less, `vpnd` will become the key slave and remains
   in the `INIT` state waiting for its peer's new public key.

4. When the `KEY_MASTER_STALE` state is entered, `vpnd` generates a
   new keypair and sends a `KEY_SWITCH_START` message containing the
   new public key.

5. When the key slave receives the `KEY_SWITCH_START`, it generates
   its own new keypair and computes a new shared key using the new
   private key and the received public key from the `KEY_SWITCH_START`
   message.  The shared key is remembered, but not used yet. The key
   slave changes to the `SLAVE_KEY_SWITCHING` state, which sends a
   `KEY_SWITCH_ACK` message containing the new public key.

6. When the key master receives the `KEY_SWITCH_ACK`, it remembers the
   previous shared key and uses it to transmit a `KEY_READY`
   message. The previous key is remembered in case `KEY_READY` needs
   to be retransmitted. It then computes a new shared key based on its
   new private key and new public key received in the `KEY_SWITCH_ACK`
   and changes to the `MASTER_KEY_READY` state.

7. When the key slave receives the `KEY_READY` message, it makes the
   shared key computed earlier the active key and changes to the
   `ACTIVE_SLAVE` state, which sends a `PEER_INFO` message.

8. When the key_master receives a `PEER_INFO` or `DATA` message in the
   `MASTER_KEY_READY` state, it changes to the `ACTIVE_MASTER` state.

9. The key master tracks the number of packets and time elapsed using
   a key and when thresholds are exceeded, changes back to the
   `MASTER_KEY_STALE` state so that new keys can be generated. The
   process starts at step 4.

## Retransmission

Every transmission of a protocol control (non-data) message starts a
retransmission timer. On expiry, the timeout handler retransmits the
message if the peer is believed to be alive and the state machine has
not progressed to the next state.

If the peer seems dead, `vpnd` returns to the `INIT` state and the
original shared key (derived from the key data in the configuration)
is restored.

When running in the `host-gw` role, a period of inactivity spent in
the `INIT` state causes a change back to the `HOST_WAIT` state.
