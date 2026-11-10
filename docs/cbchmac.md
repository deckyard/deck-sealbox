<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Encrypt-then-MAC

`sealbox.cbcHmacSeal(plaintext, encKey, macKey)` encrypts with AES-CBC
(PKCS#7 padding, a fresh random IV) and computes HMAC-SHA256 over `iv ||
ciphertext` with a second, independent key. It returns a `sealbox.CbcHmac`
with the three parts, because formats that use this construction store them
in different ways (separate fields, joined with a separator, base64-encoded).

```jennifer
use crypto;
use convert;
import "@deckyard/sealbox/" as sealbox;

def encKey as bytes init crypto.randBytes(32);
def macKey as bytes init crypto.randBytes(32);
def box as sealbox.CbcHmac init sealbox.cbcHmacSeal(convert.bytesFromString("utf-8", "payroll.csv"), $encKey, $macKey);
def back as bytes init sealbox.cbcHmacOpen($box, $encKey, $macKey);
```

`sealbox.cbcHmacOpen(box, encKey, macKey)` checks the MAC in constant time
before it decrypts anything. That order matters: decrypting first and
reporting a padding error separately from a MAC error lets an attacker
decrypt CBC ciphertext byte by byte (a padding oracle). Here both are the one
`cannot open` error.

- `encKey` is 16, 24 or 32 bytes (AES-128, 192 or 256).
- `macKey` is at least 16 bytes; 32 is the usual size.
- Use two independent keys, or derive both from one secret with
  `crypto.hkdf` and different `info` strings.

Prefer a [sealed box](seal.md) for your own data: GCM does the same job in
one key and one call.
