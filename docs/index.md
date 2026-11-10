<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# @deckyard/sealbox

One-call encryption on top of Jennifer's `crypto` library. `crypto` gives
one function per operation with every parameter spelled out: the algorithm,
the nonce, the IV, the associated data. That is what a protocol needs, and it
leaves the dangerous parts to the caller. This deck packages them into
formats, so a program encrypts and decrypts with one call and never handles a
nonce, an IV or a MAC.

| Format | Functions | Guide |
|---|---|---|
| Sealed box: AES-256-GCM, nonce in front | `seal` / `open`, `sealWith` / `openWith` | [Sealed boxes](seal.md) |
| Encrypt-then-MAC: AES-CBC + HMAC-SHA256 | `cbcHmacSeal` / `cbcHmacOpen` | [Encrypt-then-MAC](cbchmac.md) |
| Fernet tokens (Python `cryptography.fernet`) | `fernetEncrypt` / `fernetDecrypt` | [Fernet](fernet.md) |

For your own data use a sealed box. The other two exist to read and write
data that other software defines.

## Conventions

Snippets assume this import:

```jennifer
import "@deckyard/sealbox/" as sealbox;
```

- **Arguments:** the data first, then the keys
  (`sealbox.seal(plaintext, key)`), as in Jennifer's own libraries.
- **Errors:** every failure to open - a wrong key, a changed byte, a
  truncated box, a bad padding, an expired Fernet token - is one
  `Error{kind: "sealbox"}` with the message `sealbox: cannot open (wrong
  key, or the data was changed)`. It does not say which check failed:
  that is what an attacker probing the format wants to learn. Misuse, such
  as a key of the wrong length, is also kind `"sealbox"`, with a message
  that says what is wrong.
- **Runs on** both `jennifer` and `jennifer-tiny`, 0.26.0 or newer, with
  no capabilities: it is pure computation over `crypto`, `hash` and
  `encoding`.

## Keys

Keys are bytes from `sealbox.newKey()` (32 bytes) or `crypto.randBytes`.
Store them apart from the data they protect. To derive a key from a password,
use `crypto.pbkdf2("sha256", password, salt, iterations, 32)` with a random
salt kept next to the data.
