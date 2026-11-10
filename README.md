# @deckyard/sealbox

[![test](https://github.com/deckyard/deck-sealbox/actions/workflows/test.yml/badge.svg)](https://github.com/deckyard/deck-sealbox/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-github%20pages-blue)](https://deckyard.github.io/deck-sealbox/)
[![release](https://img.shields.io/github/v/release/deckyard/deck-sealbox)](https://github.com/deckyard/deck-sealbox/releases/latest)

One-call encryption formats for [Jennifer](https://jennifer-lang.dev/), on top
of its `crypto` library: sealed boxes (AES-256-GCM with the nonce stored in
front), encrypt-then-MAC (AES-CBC + HMAC-SHA256), and Fernet tokens compatible
with Python's `cryptography.fernet`. The caller never handles a nonce, an IV
or a MAC, and every failure to open is one error that does not say which
check failed.

**[Documentation](https://deckyard.github.io/deck-sealbox/)**

## Install

```sh
jvc add @deckyard/sealbox
```

This vendors the deck to `vendor/<scope>/sealbox/`. Without `jvc`, unpack the
`src/` subtree of a release archive (`<scope>-sealbox-<version>.tar.gz`) there.

## Usage

```jennifer
use convert;
import "@deckyard/sealbox/" as sealbox;

def key as bytes init sealbox.newKey();
def box as bytes init sealbox.seal(convert.bytesFromString("utf-8", "secret"), $key);
def back as bytes init sealbox.open($box, $key);
```

## Requirements

Jennifer 0.26.0 or newer. Pure computation: no network, programs or
databases, so it runs on `jennifer-tiny` too.

## Development

```sh
tools/check-all.sh                   # the full gate, as CI runs it
jennifer test src/sealbox_test.j      # the test overlay
tools/check-docs.sh                  # docs against the code
tools/pack.sh dist                   # build the release archive
```

## Licence

LGPL-3.0-only, see [LICENSE](LICENSE). Copyright (C) 2026 mplx &lt;mplx@jennifer-lang.dev&gt;.

`tools/check-headers.sh` checks every source file's SPDX header against
`deck.toml`.
