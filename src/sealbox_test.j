# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * White-box tests for sealbox: jennifer test src/sealbox_test.j
 *
 * Vectors from other implementations: a box sealed by the Jennifer 0.25
 * `crypto.encrypt`, a CBC + HMAC box made with `openssl enc` and `openssl dgst
 * -mac HMAC`, and the Fernet spec's generate / verify / invalid vectors
 * (github.com/fernet/spec). Every part of every format is flipped once.
 */
use testing;
use crypto;
use encoding;
use convert;
use binary;
use hash;

def const HEX_KEY as string init "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

def const FERNET_SECRET as string init "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=";

def const FERNET_TOKEN as string init
    "gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOP" +
    "mrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==";

# 1985-10-26T01:20:00-07:00, the spec's "now" for generate.json
def const FERNET_NOW as int init 499162800;

func hex(s as string) {
    return encoding.fromText("hex", $s);
}

func text(s as string) {
    return convert.bytesFromString("utf-8", $s);
}

func flip(b as bytes, at as int) {
    def out as bytes init $b;
    $out[$at] = $out[$at] ^ 1;
    return $out;
}

# opensBox reports whether open() succeeds, failing the test if it throws
# anything but a sealbox error.
func opensBox(box as bytes, key as bytes) {
    try {
        open($box, $key);
    } catch (e) {
        testing.assertEqual($e.kind, "sealbox");
        return false;
    }
    return true;
}

# --- sealed box -------------------------------------------------------------

func testSealOpensAndIsLongerByNonceAndTag() {
    def key as bytes init newKey();
    def box as bytes init seal(text("hello"), $key);
    testing.assertEqual(len($box), 5 + NONCE_BYTES + TAG_BYTES);
    testing.assertEqual(open($box, $key), text("hello"));
    testing.assertFalse(seal(text("hello"), $key) == $box);
}

func testABoxFromTheOldEncryptOpens() {
    # Sealed by `crypto.encrypt($key, plaintext)` on jennifer 0.25.0-dev.
    def old as bytes init hex(
        "30ebe0258dccbb23d811ded9df3573043bba3d154a4b13c486dbce19781910a7" +
            "ac607dd37e42187c1207015e80236723feeee3");
    testing.assertEqual(open($old, hex(HEX_KEY)), text("sealed by jennifer 0.25"));
}

func testEveryFlippedByteOfABoxFails() {
    def key as bytes init newKey();
    def box as bytes init seal(text("abc"), $key);
    for (def i in 0..len($box)) {
        testing.assertFalse(opensBox(flip($box, $i), $key));
    }
    testing.assertFalse(opensBox($box[0..len($box) - 1], $key));
    testing.assertFalse(opensBox($box[0..27], $key));
    testing.assertFalse(opensBox($box, newKey()));
}

func testAssociatedDataMustMatch() {
    def key as bytes init newKey();
    def box as bytes init sealWith(text("body"), $key, text("header"));
    testing.assertEqual(openWith($box, $key, text("header")), text("body"));
    def message as string init "";
    try {
        openWith($box, $key, text("Header"));
    } catch (e) {
        testing.assertEqual($e.kind, "sealbox");
        $message = $e.message;
    }
    testing.assertContains($message, "cannot open");
}

func sealShortKey() {
    seal(text("x"), crypto.randBytes(16));
}

func openShortKey() {
    open(binary.make(40), crypto.randBytes(31));
}

func testAKeyOfTheWrongLengthSaysSo() {
    testing.assertThrows("sealShortKey", "sealbox");
    testing.assertThrows("openShortKey", "sealbox");
    try {
        sealShortKey();
    } catch (e) {
        testing.assertContains($e.message, "key must be 32 bytes, got 16");
    }
}

# --- CBC + HMAC -------------------------------------------------------------

func opensslBox() {
    return CbcHmac{
        iv: hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
        ciphertext: hex("ceb96ec39e390fc24e195fce5baad2d8b667f64e559708c0d17f7538bf9dc29a"),
        mac: hex("c7349dd09a2d2b714ae60dd3931841ba78790d8e2dd9735af8ea998ab95729b5")
    };
}

func macKey() {
    return text("mac key, 32 bytes, for testing!");
}

func cbcOpens(box as CbcHmac) {
    try {
        cbcHmacOpen($box, hex(HEX_KEY), macKey());
    } catch (e) {
        testing.assertEqual($e.kind, "sealbox");
        testing.assertContains($e.message, "cannot open");
        return false;
    }
    return true;
}

func testCbcHmacOpensAnOpensslBox() {
    testing.assertEqual(
        cbcHmacOpen(opensslBox(), hex(HEX_KEY), macKey()),
        text("encrypt then mac"));
}

func testCbcHmacRoundTrip() {
    def box as CbcHmac init cbcHmacSeal(text("round trip"), hex(HEX_KEY), macKey());
    testing.assertEqual(len($box.iv), 16);
    testing.assertEqual(len($box.mac), 32);
    testing.assertEqual(cbcHmacOpen($box, hex(HEX_KEY), macKey()), text("round trip"));
}

func testEveryFlippedPartOfACbcBoxFails() {
    def good as CbcHmac init opensslBox();
    for (def i in 0..16) {
        def b as CbcHmac init $good;
        $b.iv = flip($good.iv, $i);
        testing.assertFalse(cbcOpens($b));
    }
    for (def i in 0..len($good.ciphertext)) {
        def b as CbcHmac init $good;
        $b.ciphertext = flip($good.ciphertext, $i);
        testing.assertFalse(cbcOpens($b));
    }
    for (def i in 0..32) {
        def b as CbcHmac init $good;
        $b.mac = flip($good.mac, $i);
        testing.assertFalse(cbcOpens($b));
    }
    # Sealed under another MAC key, or cut to one block.
    testing.assertFalse(cbcOpens(cbcHmacSeal(text("x"), hex(HEX_KEY), crypto.randBytes(32))));
    def cut as CbcHmac init $good;
    $cut.ciphertext = $good.ciphertext[0..16];
    testing.assertFalse(cbcOpens($cut));
}

func cbcShortMacKey() {
    cbcHmacSeal(text("x"), hex(HEX_KEY), crypto.randBytes(8));
}

func cbcBadEncKey() {
    cbcHmacSeal(text("x"), crypto.randBytes(20), macKey());
}

func testCbcHmacKeyLengths() {
    testing.assertThrows("cbcShortMacKey", "sealbox");
    testing.assertThrows("cbcBadEncKey", "sealbox");
}

# --- Fernet -----------------------------------------------------------------

func testFernetGenerateVector() {
    def iv as bytes init hex("000102030405060708090a0b0c0d0e0f");
    testing.assertEqual(
        fernetEncryptAt(text("hello"), FERNET_SECRET, FERNET_NOW, $iv),
        FERNET_TOKEN);
}

func testFernetVerifyVector() {
    testing.assertEqual(
        fernetDecryptAt(FERNET_TOKEN, FERNET_SECRET, 60, FERNET_NOW + 1),
        text("hello"));
}

func fernetRejects(token as string, now as int) {
    try {
        fernetDecryptAt($token, FERNET_SECRET, 60, $now);
    } catch (e) {
        testing.assertEqual($e.kind, "sealbox");
        testing.assertContains($e.message, "cannot open");
        return true;
    }
    return false;
}

func testFernetInvalidVectors() {
    def now as int init FERNET_NOW + 1;
    # invalid.json, in order: incorrect mac, too short, invalid base64, payload
    # size not a multiple of the block size, payload padding error, far-future
    # timestamp, expired TTL (checked at 01:21:31), incorrect IV.
    testing.assertTrue(fernetRejects(
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzX" +
            "TuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==",
        $now));
    testing.assertTrue(fernetRejects(
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPA==",
        $now));
    testing.assertTrue(fernetRejects(
        "%%%%%%%%%%%%%AECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzX" +
            "TuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
        $now));
    testing.assertTrue(fernetRejects(
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPOm73QeoCk9u" +
            "Gib28Xe5vz6oxq5nmxbx_v7mrfyudzUm",
        $now));
    testing.assertTrue(fernetRejects(
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0ODz4LEpdELGQAad7aNEHbf-JkLPIpuiYR" +
            "LQ3RtXatOYREu2FWke6CnJNYIbkuKNqOhw==",
        $now));
    testing.assertTrue(fernetRejects(
        "gAAAAAAdwStRAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAnja1xKYyhd" +
            "-Y6mSkTOyTGJmw2Xc2a6kBd-iX9b_qXQcw==",
        $now));
    testing.assertTrue(fernetRejects(
        "gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzX" +
            "TuGb4hR8AKtwcaX1YdykRtfsH-p1YsUD2Q==",
        499162891));
    testing.assertTrue(fernetRejects(
        "gAAAAAAdwJ6xBQECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAkLhFLHpGtD" +
            "BRLRTZeUfWgHSv49TF2AUEZ1TIvcZjK1zQ==",
        $now));
}

func testFernetTimeLimits() {
    # The token's timestamp is FERNET_NOW.
    testing.assertFalse(fernetRejects(FERNET_TOKEN, FERNET_NOW + 60));
    testing.assertTrue(fernetRejects(FERNET_TOKEN, FERNET_NOW + 61));
    testing.assertFalse(fernetRejects(FERNET_TOKEN, FERNET_NOW - FERNET_MAX_CLOCK_SKEW));
    testing.assertTrue(fernetRejects(FERNET_TOKEN, FERNET_NOW - FERNET_MAX_CLOCK_SKEW - 1));
    # A TTL of 0 accepts any age.
    testing.assertEqual(
        fernetDecryptAt(FERNET_TOKEN, FERNET_SECRET, 0, FERNET_NOW + 999999999),
        text("hello"));
}

func testFernetEveryFlippedByteFails() {
    def raw as bytes init encoding.fromText("base64-url", FERNET_TOKEN);
    for (def i in 0..len($raw)) {
        def changed as string init encoding.toText("base64-url", flip($raw, $i));
        testing.assertTrue(fernetRejects($changed, FERNET_NOW));
    }
}

func testFernetRoundTripNow() {
    def key as string init encoding.toText("base64-url", crypto.randBytes(32));
    def token as string init fernetEncrypt(text("now"), $key);
    testing.assertEqual(fernetDecrypt($token, $key, 60), text("now"));
}

func fernetShortKey() {
    fernetEncrypt(text("x"), encoding.toText("base64-url", crypto.randBytes(16)));
}

func fernetNotBase64Key() {
    fernetDecrypt(FERNET_TOKEN, "not a key!", 60);
}

func fernetNegativeTtl() {
    fernetDecrypt(FERNET_TOKEN, FERNET_SECRET, -1);
}

func testFernetArgumentErrors() {
    testing.assertThrows("fernetShortKey", "sealbox");
    testing.assertThrows("fernetNotBase64Key", "sealbox");
    testing.assertThrows("fernetNegativeTtl", "sealbox");
}

func testBe64() {
    testing.assertEqual(be64(499162800), hex("000000001dc09eb0"));
    testing.assertEqual(be64(0), hex("0000000000000000"));
}

# forgeToken signs a token under the spec's key with any 8 timestamp bytes, so
# the time checks see stamps no honest clock produces.
func forgeToken(stamp as bytes) {
    def keys as list of bytes init fernetKeys(FERNET_SECRET);
    def iv as bytes init binary.make(16);
    def ct as bytes init crypto.blockEncrypt("aes-cbc-pkcs7", text("x"), $keys[1], $iv);
    def head as bytes init binary.join([binary.make(1, 128), $stamp, $iv, $ct]);
    return encoding.toText(
        "base64-url",
        binary.concat($head, hash.hmac("sha256", $head, $keys[0])));
}

func testFernetExtremeTimestampsAreTheOneError() {
    # Top bit set: does not fit an int, refused rather than read.
    testing.assertTrue(fernetRejects(forgeToken(binary.make(8, 255)), FERNET_NOW));
    # The largest int, far in the future.
    def biggest as bytes init binary.concat(binary.make(1, 127), binary.make(7, 255));
    testing.assertTrue(fernetRejects(forgeToken($biggest), FERNET_NOW));
    # Timestamp 0 is very old: refused with a TTL, accepted without one.
    testing.assertTrue(fernetRejects(forgeToken(binary.make(8, 0)), FERNET_NOW));
    def any as bytes init fernetDecryptAt(
        forgeToken(binary.make(8, 0)),
        FERNET_SECRET,
        0,
        FERNET_NOW);
    testing.assertEqual($any, text("x"));
}

func testFernetHugeTtlDoesNotOverflow() {
    def back as bytes init fernetDecryptAt(
        FERNET_TOKEN,
        FERNET_SECRET,
        9223372036854775807,
        FERNET_NOW + 5);
    testing.assertEqual($back, text("hello"));
}

# --- edges: empty data, minimum lengths, key sizes --------------------------

func testEmptyPlaintextInEveryFormat() {
    def key as bytes init newKey();
    def box as bytes init seal(text(""), $key);
    testing.assertEqual(len($box), NONCE_BYTES + TAG_BYTES);
    testing.assertEqual(len(open($box, $key)), 0);
    def c as CbcHmac init cbcHmacSeal(text(""), hex(HEX_KEY), macKey());
    testing.assertEqual(len($c.ciphertext), 16);
    testing.assertEqual(len(cbcHmacOpen($c, hex(HEX_KEY), macKey())), 0);
    def token as string init fernetEncryptAt(text(""), FERNET_SECRET, FERNET_NOW, binary.make(16));
    testing.assertEqual(len(encoding.fromText("base64-url", $token)), 73);
    testing.assertEqual(len(fernetDecryptAt($token, FERNET_SECRET, 60, FERNET_NOW)), 0);
}

func testShortBoxesAreTheOneError() {
    def key as bytes init newKey();
    testing.assertFalse(opensBox(binary.make(0), $key));
    testing.assertFalse(opensBox(binary.make(27), $key));
    testing.assertFalse(opensBox(binary.make(28), $key));
}

func testEmptyAadIsTheSameAsNone() {
    def key as bytes init newKey();
    testing.assertEqual(open(sealWith(text("a"), $key, text("")), $key), text("a"));
    testing.assertEqual(openWith(seal(text("b"), $key), $key, text("")), text("b"));
}

func testCbcBoxWithBadIvOrMacLength() {
    def good as CbcHmac init opensslBox();
    def shortIv as CbcHmac init $good;
    $shortIv.iv = $good.iv[0..15];
    testing.assertFalse(cbcOpens($shortIv));
    def shortMac as CbcHmac init $good;
    $shortMac.mac = $good.mac[0..31];
    testing.assertFalse(cbcOpens($shortMac));
    def noMac as CbcHmac init $good;
    $noMac.mac = binary.make(0);
    testing.assertFalse(cbcOpens($noMac));
}

func testCbcHmacEveryAesKeySize() {
    for (def n in [16, 24, 32]) {
        def k as bytes init crypto.randBytes($n);
        def box as CbcHmac init cbcHmacSeal(text("sized"), $k, macKey());
        testing.assertEqual(cbcHmacOpen($box, $k, macKey()), text("sized"));
    }
}

# --- Fernet: canonical spelling, keys, the clock ----------------------------

func testFernetOnlyTheCanonicalSpellingOpens() {
    # The token ends "IwqDA==": the decoder would also take "IwqDB==" .. as the
    # same bytes (the low bits of the last character are unused).
    def n as int init len(FERNET_TOKEN);
    def head as string init FERNET_TOKEN[0..$n - 3];
    testing.assertTrue(fernetRejects($head + "B==", FERNET_NOW));
    def broken as string init FERNET_TOKEN[0..20] + "\n" + FERNET_TOKEN[20..$n];
    testing.assertTrue(fernetRejects($broken, FERNET_NOW));
    testing.assertTrue(fernetRejects(FERNET_TOKEN[0..$n - 2], FERNET_NOW));
    testing.assertTrue(fernetRejects("", FERNET_NOW));
    testing.assertTrue(fernetRejects("gAAAAAAdwJ6wäöü", FERNET_NOW));
    testing.assertFalse(fernetRejects(FERNET_TOKEN, FERNET_NOW));
}

func fernetKeyWithNewline() {
    fernetDecrypt(FERNET_TOKEN, FERNET_SECRET + "\n", 0);
}

func fernetKeyUnpadded() {
    fernetDecrypt(FERNET_TOKEN, FERNET_SECRET[0..43], 0);
}

func testFernetKeyMustBeCanonical() {
    testing.assertThrows("fernetKeyWithNewline", "sealbox");
    testing.assertThrows("fernetKeyUnpadded", "sealbox");
}

func testFernetOtherKeyIsTheOneError() {
    def other as string init encoding.toText("base64-url", crypto.randBytes(32));
    def message as string init "";
    try {
        fernetDecryptAt(FERNET_TOKEN, $other, 0, FERNET_NOW);
    } catch (e) {
        testing.assertEqual($e.kind, "sealbox");
        $message = $e.message;
    }
    testing.assertContains($message, "cannot open");
}

func testFernetTtlZeroStillRefusesTheFuture() {
    def message as string init "";
    try {
        fernetDecryptAt(FERNET_TOKEN, FERNET_SECRET, 0, FERNET_NOW - FERNET_MAX_CLOCK_SKEW - 1);
    } catch (e) {
        $message = $e.message;
    }
    testing.assertContains($message, "cannot open");
}

func testFernetNegativeTtlSaysSo() {
    def message as string init "";
    try {
        fernetNegativeTtl();
    } catch (e) {
        $message = $e.message;
    }
    testing.assertContains($message, "ttlSeconds must be 0 or more, got -1");
}
