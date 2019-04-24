# Client key rotation

one key, one peer

## protocol

Example of a successful key registration:

    c -> s: register_key=1\nkey=/2Qnt3SWg6AQHpzFLWYGYaLD4NvX9niVrRaCG13MBwM\n\n
    s -> c: register_key=1\nlladdr=fe80::badc:ffe:e0dd:f00d/128\nerrno=0\n\n

## data and states

### server

TOOD: explain 'forwardkey' (and maybe change the name?)

- forwardkey: 0..*

  - data:
    - current-peer [peer]
    - new-peer [peer]

  - states and possible transitions:
    - <new>    -> NOTINUSE
    - NOTINUSE -> INUSE
    - INUSE    -> SHREDDED
    - SHREDDED -> <delete>

  - triggers:
    - request: incoming register_key request from client
    - session-up: wg event "session established with new-peer"
    - session-down: wg event "session closed with current-peer"

  - state transitions:
    - <new>:
      - request -> NOTINUSE
    - NOTINUSE:
      - session-up -> INUSE
    - INUSE:
      - session-down -> SHREDDED
    - SHREDDED:
      - <delete>

### client

- forwardkey: 0..1

  - data:
    - keypair

  - states and possible transitions:
    - <new>      -> REGISTERED
    - REGISTERED -> INUSE
      INUSE      -> SHREDDED
    - SHREDDED   -> <delete>

  - triggers:
    - policy-keyreg: mandated by policy, f.ex. wg session down
      - key_generate(); register_key errno=0; wg_add_peer()
    - this-peer-up: wg event "this peer up"
    - other-peer-up: wg event "other peer up"

  - state transitions:
    - <new>:
      - policy-keyreg -> REGISTERED
    - REGISTERED:
      - this-peer-up -> INUSE
    - INUSE:
      - other-peer-up -> SHREDDED
    - SHREDDED:
      - <delete>
