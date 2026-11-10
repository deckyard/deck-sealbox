<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Sealed boxes

`sealbox.seal(plaintext, key)` encrypts with AES-256-GCM under a fresh
random 12-byte nonce and returns `nonce || ciphertext || tag`: the nonce
travels in front of the ciphertext, so `sealbox.open(box, key)` needs
nothing but the key. The box is 28 bytes longer than the plaintext.

```jennifer
use convert;
import "@deckyard/sealbox/" as sealbox;

def key as bytes init sealbox.newKey();
def box as bytes init sealbox.seal(convert.bytesFromString("utf-8", "the launch code"), $key);
def back as bytes init sealbox.open($box, $key);
```

GCM is authenticated: a changed or truncated box, or the wrong key, does not
open. Sealing the same plaintext twice gives two different boxes.

## Associated data

`sealbox.sealWith(plaintext, key, aad)` binds data that is not encrypted
but must not change, such as a record id or a header, to the box.
`sealbox.openWith(box, key, aad)` opens it only with the same `aad`, so a
box moved to another record fails.

```jennifer
def box as bytes init sealbox.sealWith($row, $key, convert.bytesFromString("utf-8", "record 42"));
def back as bytes init sealbox.openWith($box, $key, convert.bytesFromString("utf-8", "record 42"));
```

## How many boxes per key

The nonces are random, and random 96-bit nonces can repeat by the birthday
bound. NIST SP 800-38D caps one key at 2^32 messages (about four billion);
rotate the key well before that. No ordinary workload comes close.

## Boxes from Jennifer 0.25

Before 0.26, `crypto.encrypt(key, plaintext)` sealed exactly this layout
with a 32-byte key. `sealbox.open` opens those boxes unchanged.
