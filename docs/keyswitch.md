#Key Change Protocol

##Overview

The peer elected to initiate key changes starts a three-way handshake
that results in a new ephemeral secret encryption key. The purpose of
the handshake is to exchange newly-generated ephemeral public keys and
compute the shared secret key using the Diffie-Hellman key exchange
protocol.

During the transition, the new shared key exists first on the
responding peer. It begins using the new key for outgoing messages,
but continues using the old for incoming messages. The reason is that
the responder assumes that the initiator will receive the responder's
public key shortly and generate the same shared key, enabling it (the
initiator) to decrypt messages using the new key. However, it holds
off on using the new key for decryption until it receives confirmation
from the initiator that this has happened. This allows the initiator
who does not have the new key (because of a lost packet) to retransmit
a decryptable request to resend the responder's public key. After this
confirmation is received, the responder switches to the new key for
decryption, and both sides proceed with the new ephemeral secret
key.

For the first and second steps in the sequence, the sender retransmits
the message if it does not receive the expected response in a timely
fashion. Care is taken to use the older key to ensure that the
retransmissions can still be decrypted by the receiver.


##Peers, Data, States and Messages
**I**: initiator of key change  
**R:** responder for key change  
**IPs/IPp:** the initiator's permanent secret/public keypair  
**RPs/RPp:** the responder's permanent secret/public keypair  
**IEs/IEp:** the initiator's ephemeral secret/public keypair  
**REs/REp:** the responder's ephemeral secret/public keypair  
**Ko:** the current shared key  
**Kn:** the new shared key  
**`KEY_OK`:** state for normal operation  
**`KEY_STALE`:** state indicating that a key switch has been requested (`I` only)  
**`KEY_SWITCHING`:** state indicating that the key switch is partially complete (`R` only)  
**`KEY_SWITCH_START`:** message from `I`. Sent in `KEY_OK`; may be retried in `KEY_STALE`.  
**`KEY_SWITCH_ACK`:**  message from `R`. Sent in `KEY_SWITCHING`, may be retried in that state.  
**`KEY_SWITCH_DONE`:** message from I. Sent in `KEY_STALE`; may be sent in `KEY_OK` in response to a `KEY_SWITCH_ACK`  


##Protocol Steps
 
1. I sends `KEY_SWITCH_START(IEp)` to `R`.
    
   **I Notes**  
   `I` generates a new keypair `IEs/IEp`, sends the public key to `R`
   and awaits `REp`. It continues to use `Kc` until `REp` arrives,
   allowing it to generate `Kn`. Because `I` expects
   `KEY_SWITCH_ACK(REp)` shortly, it starts a timer to retransmit
   `KEY_SWITCH_START(IEp)` upon expiry.
   
   *state:* `KEY_OK` >> `KEY_STALE`  
   *TX encryption:* `Kc`  
   *RX decryption:* `Kc`
   
   **R Notes**  
   `R` is not aware of a request for the key to be changed. As such, it
   uses `Kc`.
   
   *state:* `KEY_OK`  
   *TX encryption:* `Kc`  
   *RX decryption:* `Kc`

2. `R` receives `KEY_SWITCH_START(IEp)`, sends `KEY_SWITCH_ACK(REp)`

   **I Notes**  
   As before, `I` awaits `REp`. It continues to send messages with
   `Kc` until it receives `REp`. During this period, `I` may receive
   messages from `R` encrypted with `Kn`, perhaps because
   `KEY_SWITCH_ACK(REp)` was delayed or lost.. These cannot be
   decrypted and will be discarded.

	If `I`'s retransmit timer expires while waiting for
   `R`'s `KEY_SWITCH_ACK` message, the cause is ambiguous, but the
   remediation is the same in all cases. If `I`'s `KEY_SWITCH_START`
   message was lost, then R does not have `Kn`. If `R`'s response 
   (`KEY_SWITCH_ACK`) was lost, then `R` does have `Kn`. However,
   because it continues to use `Kc` for decryption, it's OK for `I`'s
   retransmission of `KEY_SWITCH_START` to use `Kc` unconditionally.

   *state:* `KEY_STALE`  
   *TX encryption:*  `Kc`  
   *RX decryption:* `Kc`

   **R Notes**  
   `R` generates new keypair `REs/REp`, generates new shared key `Kn`,
   and sends `KEY_SWITCH_ACK(REp)` to `I`. It continues to use `Kc`
   for decryption because the confirmation that `I` has generated `Kn`
   has not been received.  However, it begins to use `Kn` for
   encryption, with the assumption that `REp` will be received shortly
   by `I`. If messages encrypted with `Kn` arrive at `I` before `REp`,
   they will be dropped as described above. `R` expects
   `KEY_SWITCH_DONE` shortly and starts a timer to retransmit
   `KEY_SWITCH_ACK(REp)` upon expiry.

   *state:* `KEY_OK` --> `KEY_SWITCHING`  
   *TX encryption:* `Kn`, except for retransmissions of `KEY_SWITCH_ACK`, which use both `Kc` and `Kn`  
   *RX decryption:* `Kc`

3. `I` receives `KEY_SWITCH_ACK(REp)`, sends `KEY_SWITCH_DONE`

   **I Notes**  
   `I` now generates `Kn`. It encrypts a message with `Kc` containing
   `KEY_SWITCH_DONE`. Henceforth, it uses `Kn` because it knows (from
   the previous message) that R has generated the new shared key.
 
   *state:* `KEY_STALE` >> `KEY_OK`  
   *TX encryption:* `Kn`  
   *RX decryption:* `Kn`

   **R Notes**  
   `R` awaits `KEY_SWITCH_DONE`, continuing to decrypt incoming
   messages with `Kc` and encrypting outgoing ones with `Kn`. If
   messages from `I` encrypted with `Kn` arrive before
   `KEY_SWITCH_DONE`, they will not be decryptable and will be
   discarded.

    If `R`'s retransmit timer expires while waiting for
   `I`'s `KEY_SWITCH_DONE` message, the cause is ambiguous. If `R`'s
   `KEY_SWITCH_ACK` message was lost, then `I` does not have `Kn` and
   it can only decrypt messages encrypted with `Kc`. If `I`'s response
   (`KEY_SWITCH_DONE`) was lost, then `I` does have `Kn` and can only
   decrypt messages encrypted with `Kn`. To ensure that
   `KEY_SWITCH_ACK` can be decrypted in al cases, the initial message
   should be encrypted with `Kc` and every retry should comprise two
   messages, one encrypted with `Kc` and another with `Kn`.

   *state:* `KEY_SWITCHING`  
   *TX encryption:* `Kc`  
   *RX decryption:* `Kn`

4. `R` receives `KEY_SWITCH_DONE`.

   **I Notes**  
   `I` is using the new key. Nothing has changed from the previous state.

   If `KEY_SWITCH_DONE` is lost, `I` will be
   encrypting with `Kn` but `R` will be decrypting with `Kc`. The way
   to avoid a deadlock is for `I` to retain `Kc` so that, if a
   `KEY_SWITCH_ACK` is received after I has returned to the `KEY_OK`
   state, `KEY_SWITCH_DONE` can be retransmitted and decrypted by
   R. This prevents R from getting stuck at the penultimate step.
   
   *state:* `KEY_OK`  
   *TX encryption:* `Kn`, except for retransmissions of `KEY_SWITCH_DONE`, which use `Kc`  
   *RX decryption:* `Kn`

   **R Notes**  
   `R` switches to using `Kn` for receiving in addition to sending.
   
   *state:* `KEY_SWITCHING` >> `KEY_OK`  
   *TX encryption:* `Kn`  
   *RX decryption:* `Kn`

##Normal State Transitions
(I state, R state)  
`KEY_OK`, `KEY_OK`  
`KEY_STALE`, `KEY_OK`  
`KEY_STALE`, `KEY_SWITCHING`  
`KEY_OK`, `KEY_SWITCHING`  

##Timers
`I`, in `KEY_STALE`, retransmits `KEY_SWITCH_START(IEp)`
until `KEY_SWITCH_ACK(REp)` received.

`R`, in `KEY_SWITCHING`, retransmits `KEY_SWITCH_ACK(REp)` until
`KEY_SWITCH_DONE` received
