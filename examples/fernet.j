#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * Fernet tokens, readable by Python's cryptography.fernet and back:
 * jennifer run examples/fernet.j
 */

use io;
use crypto;
use encoding;
use convert;

import "../src/sealbox.j" as sealbox;

# A Fernet key is 32 random bytes in base64url (Fernet.generate_key() in Python).
def key as string init encoding.toText("base64-url", crypto.randBytes(32));
def token as string init sealbox.fernetEncrypt(
    convert.bytesFromString("utf-8", "session 1234"),
    $key);
io.printf("token: %d characters, starts %s\n", len($token), $token[0..4]);

# Accept tokens up to five minutes old.
io.printf(
    "decrypt: %s\n",
    convert.stringFromBytes("utf-8", sealbox.fernetDecrypt($token, $key, 300)));

try {
    sealbox.fernetDecrypt($token, encoding.toText("base64-url", crypto.randBytes(32)), 300);
} catch (e) {
    io.printf("other key: %s\n", $e.message);
}
