#Bootstrap Protocol

##Overview

Both peers start with each other's public key and address and generate
the first of a series of ephemeral keypairs and shared secret keys.
These keys will be changed periodically once the VPN tunnel is
running.  They start by deciding which peer is the initiator of key
change requests, then proceed to execute the Diffie-Hellman key
exchange protocol. No shared key exists yet, so encryption must use
be with the public keys. During the initial startup phase, no traffic
can be exchanged.

##Peers, Data, States and Messages
**I**: initiator of key change  
**R:** responder for key change  
**IPs/IPp:** the initiator's permanent secret/public keypair  
**RPs/RPp:** the responder's permanent secret/public keypair  
**IEs/IEp:** the initiator's ephemeral secret/public keypair  
**REs/REp:** the responder's ephemeral secret/public keypair  
**K:** the shared key  
**`INIT`:** state indicating that the peer has not started  
**`KEY_NONE`:** state indicating that the first key has been requested (`I` only)  
**`KEY_STARTING`:** state indicating that setting up the first key is partially complete (`R` only)  
**`KEY_OK`:** state for normal operation  
**`PEER_START`:** message sent in `INIT`; may be retried in `d`.  
**`KEY_INIT_START`:** message from `I`. Sent in `KEY_NONE`; may be retried.  
**`KEY_INIT_ACK`:**  message from `R`. Sent in `KEY_STARTING`, may be retried in that state.  
**`KEY_INIT_DONE`:** message from I. Sent in `KEY_STARTING`; may be sent in `KEY_OK` in response to a `KEY_INIT_ACK`  

##Protocol Steps

1. Send `PEER_START(r)`

   **Notes**
   Generate a random number `r`, encrypt it with the public key of the
   peer and sends it to the peer.

   The process starts a timer to retransmit `PEER_START(r)` if the
   peer's `PEER_START(r)` doesn't arrive before the timeout expires.

   **state:** `INIT`
   
2. Receive `PEER_START(r)`, `I` sends `KEY_INIT_START(IEp)`

    **I Notes**  
   Compare the number received in `PEER_INIT(r)` with the locally generated
   one. If the number is lower, this peer becomes I.

   `I` generates keypair `IEs/IEp` and sends
   `KEY_INIT_START(IEp)`. Meanwhile, `R` waits for it. Because `I`
   expects `KEY_INIT_ACK(REp)` shortly, it starts a timer that
   retransmits `KEY_INIT_START(IEp)` upon exiry.

   
   *state:* `INIT` >> `KEY_NONE`

   **R Notes**  
   Compare the number received in `PEER_INIT(r)` with the locally
   generated one. If the number is higher, this peer becomes R.

   R awaits `KEY_INIT_START(IEp)`. This may be received by `R` before
   `R` knows what role it plays, either because `PEER_START(r)` arrives
   later than `KEY_INIT_START(IEp)`, or not at all. This is OK because
   `I` can be determined unilaterally, by the first side to possess
   both random numbers.

   *state:* `INIT`

3. `R` receives `KEY_INIT_START(IEp)`, sends `KEY_INIT_ACK(IEp)`

   **I Notes**  
   `I` awaits `KEY_INIT_ACK(REp)` If it does not arrive before the
   timer expires, I will retransmit `KEY_INIT_START(IEp)`. 
   
   *state:* `KEY_NONE`

   **R Notes**  
   `R` generates `REs/REp`, computes `K` and sends `KEY_INIT_ACK(IEp)`
   to `I`.`R` expects `KEY_SWITCH_DONE` shortly and starts a timer to
   retransmit `KEY_SWITCH_ACK(REp)` upon expiry.
   
   *state:* `INIT` >> `KEY_STARTING`

4. `I` receives `KEY_INIT_ACK(IEp)`, sends `KEY_INIT_DONE`

   **I Notes**  
   `I` computes `K` and sends `KEY_INIT_DONE` to `R`. It initializes the
   running state machine and is ready to pass traffic.
   
   *state:* `KEY_NONE` >> `KEY_OK`

   **R Notes**  
   `R` awaits `KEY_INIT_DONE`. If it does not arrive before the timer expires,
   `R` will retransmit `KEY_INIT_ACK(REp)`.
   
   *state:* `KEY_STARTING`

5. `R` receives `KEY_INIT_DONE`.

   **I Notes**
   `I` is ready to pass traffic. Nothing has changed from the previous state.

   *state:* `KEY_OK`

   **R Notes**  
   `R` initializes the running state machine and is ready to pass traffic.

   *state:* `KEY_STARTING` >> `KEY_OK`

##Normal State Transitions
(I state, R state)  

##Timers
Both peers, in `INIT`, retransmit `PEER_INIT(r)` until either a `PEER_INIT(r)`
or a `KEY_INIT_START(IEp)` is received.

`I`, in `KEY_NONE`, retransmits `KEY_INIT_START(IEp)`
until `KEY_INIT_ACK(REp)` received.

`R`, in `KEY_STARTING`, retransmits `KEY_INIT_ACK(REp)` until
`KEY_INIT_DONE` received
