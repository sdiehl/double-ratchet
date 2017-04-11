Double Ratchet Algorithm
========================

[![CircleCI](https://circleci.com/gh/adjoint-io/double-ratchet/tree/master.svg?style=svg)](https://circleci.com/gh/adjoint-io/double-ratchet/tree/master)

An implementation of Open Whisper System's Double Ratchet Algorithm in Haskell.

The Double Ratchet algorithm is used by two parties to exchange encrypted
messages based on a shared secret key. Typically the parties will use some key
agreement protocol (such as X3DH) to agree on the shared secret key.  Following
this, the parties will use the Double Ratchet to send and receive encrypted
messages. This gives the cryptosystem the property of **perfect forward secrecy** 
in which compromise of long-term keys does not compromise past session keys. 
Forward secrecy protects past sessions against future compromises of secret keys 
or passwords.

The parties derive new keys for every Double Ratchet message so that earlier
keys cannot be calculated from later ones. The parties also send Diffie-Hellman
public values attached to their messages. The results of Diffie-Hellman
calculations are mixed into the derived keys so that later keys cannot be
calculated from earlier ones. These properties gives some protection to earlier
or later encrypted messages in case of a compromise of a party's keys.

Usage
-----

The example will use the pre-shared keys `bob_private` and `bob_public` and `ssk`.

To compile the example:

```bash
> stack ghc Example.hs --package ratchet 
> ./Example server
> ./Example client
```

To load in GHCi:

```bash
> stack ghci --package network
> :load Example.hs
```

Protocol
--------

After an initial key exchange it manages the ongoing renewal and maintenance of
short-lived session keys. It combines a cryptographic ratchet based on the
Diffie–Hellman key exchange (DH) and a ratchet based on a key derivation
function (KDF) like e.g. a hash function and is therefore called a double
ratchet.

* [The Double Ratchet Algorithm](https://whispersystems.org/docs/specifications/doubleratchet/)

Signal Protocol protocol combines the Double Ratchet Algorithm, prekeys, and a
triple Diffie–Hellman (3-DH) handshake, and uses Curve25519, AES-256 and
HMAC-SHA256 as primitives.

* [Extended Triple Diffie-Hellman](https://whispersystems.org/docs/specifications/x3dh/)

License
-------

```
Copyright 2017 Adjoint Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
