# Nonce Handling

This describes how nonces are handled by vpnd, and how that handling
has evolved.

## Background

Proper usage of nonces is important in security systems that use
them. Nonce re-use exposes the system to risks, such as the
decryption of packets and replays of previously captured traffic.f

Early versions of VPND verified the uniqueness of received nonces
in a way that did not account for out-of-order packet delivery. This
resulted in protection against replay attacks, but resulted in dropped
packets because the system could not distinguish replayed packets from
ones that merely arrived late.

The technique relied on the peers sending nonces with monotonically
increasing values. On the receiving peer, the following rules were
applied:

1. When a packet arrives with a nonce less than or equal to the
   highest value yet received, it is considered a replay and the
   packet is dropped.

2. When a packet arrives with a nonce greater than the highest valued
   nonce yet received, the nonce has not been seen before and the
   packet is decrypted and the received nonce value replaces the
   current highest-valued nonce.


The problem is that there is no way to distinguish between a late
packet and a replayed packet or reused nonce. This is because there
is no tracking of nonces that have been seen for a given keypair.

## Current Implmentation

The system still transmits, and expects, monotonically increasing
nonces, but some additional logic has been added to account for
legitimate packets that arrive late. The essence is: allow a nonce
less than the current-highest *once*, then remember it so that
subsequent packets with this nonce can be dropped. The specific rules
are:

1. When a packet arrives with a nonce less than the current-highest
   one, perform the following:

  - If the nonce value is not found in the collection, add it to the
    collection of late nonces and forward the packet.

  - If the nonce value can be found in the collection, drop the packet.

2. When a packet arrives with a nonce equal to the current-highest,
   it is considered a replay and the packet is dropped.

3. When a packet arrives with a nonce greater than the highest valued
   nonce yet received, the nonce has not been seen before. The packet
   is decrypted and the received nonce value replaces the current
   highest-valued nonce. This is the same treatment as in the initial
   implementation. These are valid, having arrived either in order or
   early, but their greater than the highest-yet-seen is the assurance
   that the nonce has not been used.

3. Whenever the keypair is renegotiated, flush the collection.

## Persistent Key: Special Handling

When VPND starts up, it uses a key persistently stored on disk for the
initial communication, which is how the peers can verify each others'
identity. Since this key is used multiple times (across process
restarts), it's harder to maintain knowledge of already-seen
nonces. A nonce may have been used during a previous run, so if it
reappears after a restart, the strategy of allowing it once and
remembering it is ineffective at blocking a replay: the new process
has no recollection of a nonce received by a now-departed process.

In order to close off this vulnerability, use the following strategy:

- Continue to use the original nonce-checking rules (drop packets less
  than the highest) while the persistent keypair is in use. Since the
  process of transitioning to an active state involves negotiating a
  new shared key, the system never uses the pre-shared keys for very long.

Note that the system returns to using the initial keypair whenever a
session ends, so a state indicating whether the persistent keypair is
in use needs to be maintained. During session setup, the number of
packets is small: there is no data transfer and the packets are sent
in sequence according to the protocol. The chance of having an
out-of-order delivery is small here, so the stricter rules are
unlikely to hinder operation.
