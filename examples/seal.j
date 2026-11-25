#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.28.0

/**
 * Seal and open a box, with and without associated data:
 * jennifer run examples/seal.j
 */

use io;
use encoding;

import "../src/sealbox.j" as sealbox;

def key as bytes init sealbox.newKey();
def box as bytes init sealbox.seal(encoding.encode("utf-8", "the launch code"), $key);
io.printf("box: %d bytes (12 nonce + 15 ciphertext + 16 tag)\n", len($box));
io.printf("open: %s\n", encoding.decode("utf-8", sealbox.open($box, $key)));

# Associated data is authenticated, not encrypted: the box opens only with it.
def header as bytes init encoding.encode("utf-8", "record 42");
def tagged as bytes init sealbox.sealWith(encoding.encode("utf-8", "row data"), $key, $header);
try {
    sealbox.openWith($tagged, $key, encoding.encode("utf-8", "record 43"));
} catch (e) {
    io.printf("other header: %s\n", $e.message);
}
