<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# sealbox cheatsheet

Every export of `@deckyard/sealbox`. Guides are listed in
[the introduction](index.md).

```jennifer
import "@deckyard/sealbox/" as sealbox;
```

Every failure to open is `Error{kind: "sealbox"}` with the message
`sealbox: cannot open (wrong key, or the data was changed)`.

## Sealed boxes

| Function | Returns | Does |
|---|---|---|
| `sealbox.newKey()` | `bytes` | 32 crypto-grade random bytes |
| `sealbox.seal(plaintext, key)` | `bytes` | AES-256-GCM under a fresh nonce: `nonce \|\| ciphertext \|\| tag` |
| `sealbox.open(box, key)` | `bytes` | The plaintext of a box `seal` made |
| `sealbox.sealWith(plaintext, key, aad)` | `bytes` | `seal` with associated data |
| `sealbox.openWith(box, key, aad)` | `bytes` | Open with the same associated data |

## Encrypt-then-MAC

| Function | Returns | Does |
|---|---|---|
| `sealbox.cbcHmacSeal(plaintext, encKey, macKey)` | `CbcHmac` | AES-CBC (PKCS#7, random IV) and HMAC-SHA256 over `iv \|\| ciphertext` |
| `sealbox.cbcHmacOpen(box, encKey, macKey)` | `bytes` | Check the MAC in constant time, then decrypt |

### `CbcHmac`

| Field | Meaning |
|---|---|
| `iv as bytes` | the 16-byte CBC IV |
| `ciphertext as bytes` | AES-CBC with PKCS#7 padding |
| `mac as bytes` | the 32-byte HMAC-SHA256 over `iv \|\| ciphertext` |

## Fernet

| Function | Returns | Does |
|---|---|---|
| `sealbox.fernetEncrypt(plaintext, key)` | `string` | A Fernet token; `key` is 32 bytes in base64url |
| `sealbox.fernetDecrypt(token, key, ttlSeconds)` | `bytes` | The plaintext; `ttlSeconds` 0 accepts any age (a token from the future is still refused); only the canonical base64url spelling is accepted |

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `KEY_BYTES` | `32` | key length for `seal` / `open` |
| `NONCE_BYTES` | `12` | nonce in front of a sealed box |
| `TAG_BYTES` | `16` | GCM tag at the end of a sealed box |
| `FERNET_MAX_CLOCK_SKEW` | `60` | seconds a Fernet timestamp may lie in the future |
