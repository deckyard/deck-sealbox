# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * One-call encryption formats on top of the `crypto` library. `crypto` keeps
 * one function per operation with every parameter spelled out (algorithm,
 * nonce, IV, associated data); this deck packages them into formats, so the
 * caller never handles a nonce, an IV or a MAC:
 *
 *   seal / open                AES-256-GCM, a fresh nonce stored in front
 *   sealWith / openWith        the same, with associated data
 *   cbcHmacSeal / cbcHmacOpen  AES-CBC + HMAC-SHA256, encrypt-then-MAC
 *   fernetEncrypt / Decrypt    Fernet tokens (Python cryptography.fernet)
 *
 * Every failure to open is one `Error{kind: "sealbox"}` that does not say
 * which check failed: telling a wrong key from a changed byte or a bad padding
 * is what an attacker probing the format wants to learn. Misuse by the caller
 * (a key of the wrong length) is a `sealbox` error that says what is wrong.
 *
 * @module sealbox
 */
use crypto;
use hash;
use binary;
use encoding;
use convert;
use time;

/**
 * The key length `seal` / `open` take: 32 bytes, AES-256.
 */
export def const KEY_BYTES as int init 32;

/**
 * The nonce length stored in front of a sealed box.
 */
export def const NONCE_BYTES as int init 12;

/**
 * The GCM tag length at the end of a sealed box.
 */
export def const TAG_BYTES as int init 16;

/**
 * The seconds a Fernet token's timestamp may lie in the future before it is
 * refused, as in Python's `cryptography.fernet`.
 */
export def const FERNET_MAX_CLOCK_SKEW as int init 60;

/**
 * A CBC + HMAC box: the IV, the ciphertext, and the HMAC-SHA256 over
 * `iv || ciphertext`. Formats store the three parts their own way.
 * @field iv {bytes} the 16-byte CBC IV
 * @field ciphertext {bytes} AES-CBC with PKCS#7 padding
 * @field mac {bytes} the 32-byte HMAC-SHA256 over `iv || ciphertext`
 */
export def struct CbcHmac {
    iv as bytes,
    ciphertext as bytes,
    mac as bytes
};

# The one message for every failure to open: it does not say which check failed.
def const OPEN_FAILED as string init "sealbox: cannot open (wrong key, or the data was changed)";

def const FERNET_VERSION as int init 128;

# --- helpers (private) ------------------------------------------------------

func fail(message as string) {
    throw Error{kind: "sealbox", message: "sealbox: " + $message};
}

func openFailed() {
    throw Error{kind: "sealbox", message: OPEN_FAILED};
}

func noData() {
    def none as bytes;
    return $none;
}

func requireKey(key as bytes) {
    if (len($key) != KEY_BYTES) {
        fail("key must be 32 bytes, got " + convert.toString(len($key)));
    }
}

func requireAesKey(key as bytes) {
    def n as int init len($key);
    if (not ($n == 16 or $n == 24 or $n == 32)) {
        fail("encKey must be 16, 24 or 32 bytes, got " + convert.toString($n));
    }
}

func requireMacKey(macKey as bytes) {
    if (len($macKey) < 16) {
        fail("macKey must be at least 16 bytes, got " + convert.toString(len($macKey)));
    }
}

# be64 renders a non-negative int as 8 big-endian bytes.
func be64(n as int) {
    def out as bytes init binary.make(0);
    for (def i in 0..8) {
        $out[] = ($n >> (56 - 8 * $i)) & 255;
    }
    return $out;
}

func nowSeconds() {
    return time.unixMillis(time.now()) // 1000;
}

# --- sealed box: AES-256-GCM, nonce || ciphertext || tag --------------------

/**
 * A fresh random 32-byte key for `seal` / `open`.
 * @return {bytes} 32 crypto-grade random bytes
 */
export func newKey() {
    return crypto.randBytes(KEY_BYTES);
}

/**
 * Seal `plaintext` with AES-256-GCM under a fresh random nonce. The box is
 * `nonce || ciphertext || tag`, the layout the pre-0.26 `crypto.encrypt` made,
 * so boxes it sealed open with `open`. Rotate the key well before 2^32 boxes:
 * random 96-bit nonces may collide after that many (NIST SP 800-38D).
 * @param plaintext {bytes} the data to protect
 * @param key {bytes} a 32-byte key (`newKey()`)
 * @return {bytes} the box, 28 bytes longer than the plaintext
 * @throws {Error} kind "sealbox" when the key is not 32 bytes
 * @example
 *   def key as bytes init sealbox.newKey();
 *   def box as bytes init sealbox.seal(convert.bytesFromString("utf-8", "hi"), $key);
 *   def back as bytes init sealbox.open($box, $key);
 */
export func seal(plaintext as bytes, key as bytes) {
    return sealWith($plaintext, $key, noData());
}

/**
 * Open a box `seal` made.
 * @param box {bytes} `nonce || ciphertext || tag`
 * @param key {bytes} the 32-byte key it was sealed with
 * @return {bytes} the plaintext
 * @throws {Error} kind "sealbox" when the key is not 32 bytes, or the box does
 *   not open (wrong key, or a changed or truncated box)
 */
export func open(box as bytes, key as bytes) {
    return openWith($box, $key, noData());
}

/**
 * `seal` with associated data: `aad` is authenticated but not encrypted (a
 * header, a record id), and the box opens only with the same `aad`.
 * @param plaintext {bytes} the data to protect
 * @param key {bytes} a 32-byte key
 * @param aad {bytes} associated data, may be empty
 * @return {bytes} `nonce || ciphertext || tag`
 * @throws {Error} kind "sealbox" when the key is not 32 bytes
 */
export func sealWith(plaintext as bytes, key as bytes, aad as bytes) {
    requireKey($key);
    def nonce as bytes init crypto.randBytes(NONCE_BYTES);
    return binary.concat($nonce, crypto.encrypt("aes-gcm", $plaintext, $key, $nonce, $aad));
}

/**
 * Open a box `sealWith` made, with the same associated data.
 * @param box {bytes} `nonce || ciphertext || tag`
 * @param key {bytes} the 32-byte key
 * @param aad {bytes} the associated data it was sealed with
 * @return {bytes} the plaintext
 * @throws {Error} kind "sealbox" when the key is not 32 bytes, or the box does
 *   not open
 */
export func openWith(box as bytes, key as bytes, aad as bytes) {
    requireKey($key);
    if (len($box) < NONCE_BYTES + TAG_BYTES) {
        openFailed();
    }
    def nonce as bytes init $box[0..NONCE_BYTES];
    def sealed as bytes init $box[NONCE_BYTES..len($box)];
    try {
        return crypto.decrypt("aes-gcm", $sealed, $key, $nonce, $aad);
    } catch (e) {
        openFailed();
    }
    return noData();
}

# --- encrypt-then-MAC: AES-CBC + HMAC-SHA256 --------------------------------

/**
 * Encrypt with AES-CBC (PKCS#7, a fresh random IV) and MAC `iv || ciphertext`
 * with HMAC-SHA256 under a separate key: the encrypt-then-MAC construction
 * many file formats use. Use two independent keys.
 * @param plaintext {bytes} the data to protect
 * @param encKey {bytes} the AES key, 16, 24 or 32 bytes
 * @param macKey {bytes} the HMAC key, at least 16 bytes
 * @return {CbcHmac} the IV, ciphertext and MAC
 * @throws {Error} kind "sealbox" on a key of the wrong length
 */
export func cbcHmacSeal(plaintext as bytes, encKey as bytes, macKey as bytes) {
    requireAesKey($encKey);
    requireMacKey($macKey);
    def iv as bytes init crypto.randBytes(16);
    def ct as bytes init crypto.blockEncrypt("aes-cbc-pkcs7", $plaintext, $encKey, $iv);
    def mac as bytes init hash.hmac("sha256", binary.concat($iv, $ct), $macKey);
    return CbcHmac{iv: $iv, ciphertext: $ct, mac: $mac};
}

/**
 * Check the MAC in constant time, then decrypt. The MAC is checked before any
 * decryption, so a changed ciphertext never reaches the padding check, and a
 * wrong MAC and a bad padding are the same error.
 * @param box {CbcHmac} what `cbcHmacSeal` returned
 * @param encKey {bytes} the AES key
 * @param macKey {bytes} the HMAC key
 * @return {bytes} the plaintext
 * @throws {Error} kind "sealbox" on a key of the wrong length, or when the box
 *   does not open
 */
export func cbcHmacOpen(box as CbcHmac, encKey as bytes, macKey as bytes) {
    requireAesKey($encKey);
    requireMacKey($macKey);
    if (len($box.iv) != 16) {
        openFailed();
    }
    def signed as bytes init binary.concat($box.iv, $box.ciphertext);
    def want as bytes init hash.hmac("sha256", $signed, $macKey);
    if (not hash.equal($want, $box.mac)) {
        openFailed();
    }
    try {
        return crypto.blockDecrypt("aes-cbc-pkcs7", $box.ciphertext, $encKey, $box.iv);
    } catch (e) {
        openFailed();
    }
    return noData();
}

# --- Fernet -----------------------------------------------------------------

/**
 * Encrypt into a Fernet token (the format of Python's `cryptography.fernet`):
 * base64url of `0x80 || timestamp || iv || ciphertext || hmac`, AES-128-CBC
 * with PKCS#7 and HMAC-SHA256. Make a key with
 * `encoding.toText("base64-url", crypto.randBytes(32))`.
 * @param plaintext {bytes} the data to protect
 * @param key {string} the Fernet key: 32 bytes, base64url (padded, 44 characters)
 * @return {string} the token
 * @throws {Error} kind "sealbox" when the key is not a Fernet key
 */
export func fernetEncrypt(plaintext as bytes, key as string) {
    return fernetEncryptAt($plaintext, $key, nowSeconds(), crypto.randBytes(16));
}

/**
 * Decrypt a Fernet token. The MAC is checked before decrypting; a token older
 * than `ttlSeconds`, or dated more than `FERNET_MAX_CLOCK_SKEW` seconds in the
 * future, is refused. The future check applies with any `ttlSeconds`, 0
 * included (Python skips it when no TTL is given). Only the canonical
 * base64url spelling of a token is accepted.
 * @param token {string} the token
 * @param key {string} the Fernet key
 * @param ttlSeconds {int} the oldest token accepted, in seconds; 0 accepts any
 *   age (a token from the future is still refused)
 * @return {bytes} the plaintext
 * @throws {Error} kind "sealbox" when the key is not a Fernet key, `ttlSeconds`
 *   is negative, or the token does not open (wrong key, changed, malformed,
 *   expired or from the future)
 */
export func fernetDecrypt(token as string, key as string, ttlSeconds as int) {
    return fernetDecryptAt($token, $key, $ttlSeconds, nowSeconds());
}

# fernetKeys splits a Fernet key into its signing (first 16 bytes) and
# encryption (last 16 bytes) halves.
func fernetKeys(key as string) {
    def raw as bytes;
    try {
        $raw = encoding.fromText("base64-url", $key);
    } catch (e) {
        fail("a Fernet key is 32 bytes in base64url (padded, 44 characters)");
    }
    # The decoder skips line breaks and ignores the unused low bits of the last
    # character; only the one canonical spelling is a key.
    if (len($raw) != 32 or encoding.toText("base64-url", $raw) != $key) {
        fail("a Fernet key is 32 bytes in base64url (padded, 44 characters)");
    }
    return [$raw[0..16], $raw[16..32]];
}

# fernetEncryptAt is fernetEncrypt with the clock and IV given, for the spec's
# fixed vectors.
func fernetEncryptAt(plaintext as bytes, key as string, now as int, iv as bytes) {
    def keys as list of bytes init fernetKeys($key);
    def ct as bytes init crypto.blockEncrypt("aes-cbc-pkcs7", $plaintext, $keys[1], $iv);
    def head as bytes init binary.join([binary.make(1, FERNET_VERSION), be64($now), $iv, $ct]);
    def mac as bytes init hash.hmac("sha256", $head, $keys[0]);
    return encoding.toText("base64-url", binary.concat($head, $mac));
}

# fernetDecryptAt is fernetDecrypt with the clock given.
func fernetDecryptAt(token as string, key as string, ttlSeconds as int, now as int) {
    def keys as list of bytes init fernetKeys($key);
    if ($ttlSeconds < 0) {
        fail("ttlSeconds must be 0 or more, got " + convert.toString($ttlSeconds));
    }
    def raw as bytes init fernetBytes($token);
    # version 1 + timestamp 8 + IV 16 + at least one block 16 + HMAC 32
    def n as int init len($raw);
    if ($n < 73 or ($n - 57) % 16 != 0 or $raw[0] != FERNET_VERSION) {
        openFailed();
    }
    def body as bytes init $raw[0..$n - 32];
    def want as bytes init hash.hmac("sha256", $body, $keys[0]);
    if (not hash.equal($want, $raw[$n - 32..$n])) {
        openFailed();
    }
    # A timestamp with the top bit set does not fit an int (and is millennia
    # away); it is refused like any other bad token, not read.
    if ($raw[1] > 127) {
        openFailed();
    }
    fernetCheckTime(binary.readUint("be", $raw, 1, 8), $ttlSeconds, $now);
    def iv as bytes init $raw[9..25];
    def ct as bytes init $raw[25..$n - 32];
    try {
        return crypto.blockDecrypt("aes-cbc-pkcs7", $ct, $keys[1], $iv);
    } catch (e) {
        openFailed();
    }
    return noData();
}

# fernetBytes decodes the token's base64url; malformed text is the one error.
# Only the canonical spelling is accepted: the decoder skips line breaks and
# ignores the unused low bits of the last character, so without the round-trip
# check many strings would decode to one token, and an application using the
# token text as a replay or revocation key could be bypassed.
func fernetBytes(token as string) {
    def raw as bytes;
    try {
        $raw = encoding.fromText("base64-url", $token);
    } catch (e) {
        openFailed();
    }
    if (encoding.toText("base64-url", $raw) != $token) {
        openFailed();
    }
    return $raw;
}

# fernetCheckTime refuses a token from the future beyond the clock skew and,
# with a TTL, one older than the TTL. It compares differences, never sums, so
# no timestamp or TTL can overflow an int (an overflow is a runtime error).
func fernetCheckTime(stamp as int, ttlSeconds as int, now as int) {
    def age as int init $now - $stamp;
    if ($age < 0 - FERNET_MAX_CLOCK_SKEW) {
        openFailed();
    }
    if ($ttlSeconds > 0 and $age > $ttlSeconds) {
        openFailed();
    }
}
