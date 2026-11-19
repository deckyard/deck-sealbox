<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Design

## Scope

The deck packages the `crypto` library's primitives into encryption
formats, so a caller never handles a nonce, an IV or a MAC:

- **Sealed boxes**: `seal` / `open` and, with associated data, `sealWith` /
  `openWith`, AES-256-GCM with a fresh random nonce stored in front;
  `newKey` gives a key.
- **Encrypt-then-MAC**: `cbcHmacSeal` / `cbcHmacOpen`, AES-CBC with PKCS#7
  and HMAC-SHA256, the construction many file formats use.
- **Fernet**: `fernetEncrypt` / `fernetDecrypt`, the token format of
  Python's `cryptography.fernet`.

It is pure computation over `crypto`, `hash` and `encoding`, needs no
capability and runs on both `jennifer` and `jennifer-tiny`.

What the deck does not do: it adds no primitive of its own (algorithms,
block modes, signatures and key exchange stay in `crypto`), derives no key
from a password, and manages no keys beyond generating one.

## Decisions

- **A deck, not core.** After `jennifer`'s M28.40, `crypto.encrypt` takes
  every parameter (algorithm, nonce, associated data) and `blockEncrypt`
  gives the raw block modes: the core keeps one way to reach each
  primitive. Formats are layouts built from them, and there are many, so
  they live in a deck.
- **The sealed box keeps the old layout.** A box is
  `nonce(NONCE_BYTES) || ciphertext || tag(TAG_BYTES)`, the bytes
  `crypto.encrypt` wrote before M28.40, so boxes made by jennifer 0.25 open
  unchanged. Keys are `KEY_BYTES` (32) bytes. The docs advise rotating the
  key well before 2^32 messages, the random-nonce limit of NIST SP 800-38D.
- **One error for every failure to open.** A wrong key, a changed byte, a
  bad padding, an expired token or a bad version byte all throw the same
  error with the same message. Telling them apart is what an attacker
  probing the format wants to learn. Misuse by the caller (a key of the
  wrong length, a negative TTL) is specific, since it reveals nothing about
  the data.
- **MAC before decrypt.** `cbcHmacOpen` and Fernet check the HMAC in
  constant time (`hash.equal`) before any decryption, so a changed
  ciphertext never reaches the padding check. `cbcHmacOpen` takes the
  `CbcHmac` struct returned by `cbcHmacSeal`; the MAC covers `iv ||
  ciphertext`. The two keys should be independent; the MAC key is at least
  16 bytes.
- **Fernet as Python writes it.** Version byte, timestamp, IV,
  AES-128-CBC, HMAC-SHA256, base64url; the key is 32 bytes in base64url,
  half signing and half encryption. `fernetDecrypt` takes a TTL in seconds.
  A token from more than `FERNET_MAX_CLOCK_SKEW` (60 s) in the future is
  refused even with TTL 0, which accepts any age; Python skips that check
  without a TTL.
- **Canonical base64url only.** A token or key has exactly one accepted
  spelling. The deck re-encodes what it decoded and compares, which also
  guards interpreters whose decoder was lenient: 16 spellings of one Fernet
  token used to open, which would let a token kept as a replay or
  revocation key be respelled past the check.
- **No sums in the time checks.** The age check compares `now - stamp`
  rather than `stamp + ttl`, since a huge TTL would overflow, and an
  overflow is a runtime error rather than a deck error. A timestamp with the
  top bit set is refused before it is read, because it does not fit an
  `int`.

## Errors

Every failure is `Error{kind: "sealbox"}`. A failure to open always has the
same message, `sealbox: cannot open (wrong key, or the data was changed)`;
usage errors have messages that start with
`sealbox: ` and say what is wrong. The deck calls nothing that fails with
another kind in normal use; there is no error struct, because there are no
fields a caller should read.

## Security and limits

- Nonces and IVs come from `crypto.randBytes`; the caller never supplies
  one in the sealing functions.
- Opening is constant-time in the MAC comparison and reveals nothing about
  which check failed.
- Fernet tokens are bounded in time by the TTL and by the clock-skew limit.
- There is no size cap: data is held in memory, as `crypto` holds it.

## Testing and validation

- Known-answer tests: a box made by the pre-M28.40 `crypto.encrypt`
  (jennifer 0.25); the Fernet specification's `generate`, `verify` and
  `invalid` vectors (github.com/fernet/spec), reproduced through private
  functions that take the clock and the IV; and a CBC + HMAC box made with
  `openssl enc -aes-256-cbc` and `openssl dgst -sha256 -mac HMAC`.
- A flipped bit in every byte of every format fails to open.
- The canonical-spelling check, the TTL and clock-skew edges and the
  usage errors are tested directly.

Not covered: interoperability is checked against vectors and files, not by
round trips with Python's `cryptography` at test time.

## Known limitations and open questions

- Random 96-bit nonces limit one key to well under 2^32 sealed boxes;
  rotating keys is the caller's job.
- Fernet's 128-bit AES and the format's fixed layout are the specification's
  choices and cannot be changed without leaving the format.

## Dependencies on the interpreter

- `jennifer`'s M28.40 (`crypto`: one function per operation, block modes),
  for `crypto.encrypt` with explicit parameters and `crypto.blockEncrypt` /
  `blockDecrypt`; first released in 0.26.0, the floor.
- `jennifer`'s M28.43 (canonical-only base32 / base64 decoding), found while
  reviewing this deck; the deck's own re-encoding check stays as a guard.
- `binary.readUint` for the Fernet timestamp, `hash.hmac` and `hash.equal`.
