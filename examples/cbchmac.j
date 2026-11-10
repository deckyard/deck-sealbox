#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * Encrypt-then-MAC with AES-CBC and HMAC-SHA256, and what a changed byte does:
 * jennifer run examples/cbchmac.j
 */

use io;
use crypto;
use convert;

import "../src/sealbox.j" as sealbox;

def encKey as bytes init crypto.randBytes(32);
def macKey as bytes init crypto.randBytes(32);
def box as sealbox.CbcHmac init sealbox.cbcHmacSeal(
    convert.bytesFromString("utf-8", "payroll.csv"),
    $encKey,
    $macKey);
io.printf(
    "iv %d bytes, ciphertext %d bytes, mac %d bytes\n",
    len($box.iv),
    len($box.ciphertext),
    len($box.mac));
io.printf(
    "open: %s\n",
    convert.stringFromBytes("utf-8", sealbox.cbcHmacOpen($box, $encKey, $macKey)));

def changed as sealbox.CbcHmac init $box;
$changed.ciphertext[0] = $changed.ciphertext[0] ^ 1;
try {
    sealbox.cbcHmacOpen($changed, $encKey, $macKey);
} catch (e) {
    io.printf("changed byte: %s\n", $e.message);
}
