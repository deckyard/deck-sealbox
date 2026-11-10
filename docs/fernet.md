<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Fernet

[Fernet](https://github.com/fernet/spec) is the token format of Python's
`cryptography.fernet`, also implemented for Go, Ruby, JavaScript and others.
A token is base64url text that carries a timestamp, so the reader can refuse
old tokens. `sealbox` reads and writes the same tokens: a key made in Python
works here and the other way round.

```jennifer
use crypto;
use encoding;
use convert;
import "@deckyard/sealbox/" as sealbox;

# A Fernet key: 32 random bytes in base64url (Fernet.generate_key() in Python).
def key as string init encoding.toText("base64-url", crypto.randBytes(32));
def token as string init sealbox.fernetEncrypt(convert.bytesFromString("utf-8", "session 1234"), $key);
def back as bytes init sealbox.fernetDecrypt($token, $key, 300);
```

`sealbox.fernetDecrypt(token, key, ttlSeconds)` refuses a token:

- whose MAC does not match (checked before decrypting);
- older than `ttlSeconds`, unless `ttlSeconds` is 0, which accepts any
  age;
- dated more than `sealbox.FERNET_MAX_CLOCK_SKEW` (60) seconds in the
  future, whatever `ttlSeconds` is (Python skips this check when no TTL is
  given; a token minted on a clock that runs fast is refused here);
- that is not base64url in its one canonical spelling (with padding, no
  line breaks), has the wrong version byte, or the wrong length.

The key is the padded 44-character base64url text; a key with a line break
or another spelling is a usage error.

All of these are the one `cannot open` error, as in Python, where every
case is `InvalidToken`.

The format: `0x80` (version), an 8-byte big-endian Unix timestamp, a
16-byte IV, the AES-128-CBC ciphertext with PKCS#7 padding, and an
HMAC-SHA256 over all of that; the key's first 16 bytes are the signing key
and the last 16 the encryption key. It is tested against the specification's
own `generate`, `verify` and `invalid` vectors.
