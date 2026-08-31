"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const pw = require("../web/js/pw.js");

const golden = JSON.parse(
    fs.readFileSync(path.join(__dirname, "v1-vectors.json"), "utf8")
);

// ---------------------------------------------------------------------------
// The point of this file. Every password this tool has ever produced has to
// keep coming out the same, because users have already set them on real sites.
// These vectors were generated from the original implementation, so a failure
// here means a change altered someone's password.
// ---------------------------------------------------------------------------
test("v1 passwords are unchanged", async (t) => {
    for (const [input, length, expected] of golden.vectors) {
        await t.test(`getPassword(${JSON.stringify(input)}, ${length})`, async () => {
            assert.strictEqual(await pw.getPassword(input, length), expected);
        });
    }
});

test("v1 raw hashes are unchanged", async (t) => {
    for (const [input, length, expected] of golden.hashes) {
        await t.test(`getEncodedHash(${JSON.stringify(input)}, ${length})`, async () => {
            assert.strictEqual(await pw.getEncodedHash(input, length), expected);
        });
    }
});

// --- ported from the original JsTestDriver suite ----------------------------

test("strips base64 special characters", () => {
    assert.strictEqual(pw.stripSpecialChars("=0+1/2//3++4==56789abcDEF=+/"), "0123456789abcDEF");
    assert.strictEqual(pw.stripSpecialChars("0123456789abcDEF"), "0123456789abcDEF");
});

test("truncates", () => {
    assert.strictEqual(pw.truncate("1234567890", 10), "1234567890");
    assert.strictEqual(pw.truncate("1234567890", 0), "1234567890");
    assert.strictEqual(pw.truncate("1234567890", 8), "12345678");
});

test("checks character-type mix", () => {
    assert.strictEqual(pw.isStrongEnough("aaaaa"), true);
    assert.strictEqual(pw.isStrongEnough("aaaaaa"), false);
    assert.strictEqual(pw.isStrongEnough("aaaaA1"), true);
    assert.strictEqual(pw.isStrongEnough("aaaaA1aaaaa"), true);
    assert.strictEqual(pw.isStrongEnough("aaaaA1aaaaaa"), false);
    assert.strictEqual(pw.isStrongEnough("aaaaA1aaaaA1"), true);
});

// --- new behaviour ----------------------------------------------------------

test("returns exactly the requested number of characters", async () => {
    // Lengths past ~200 used to come back silently short, because the margin
    // for stripped base64 characters was a fixed 8 regardless of length.
    for (const length of [12, 100, 200, 250, 256]) {
        assert.strictEqual((await pw.getPassword("correct horse battery staple", length)).length, length);
    }
});

test("emits only unreserved alphanumerics", async () => {
    for (const length of [12, 64, 200]) {
        assert.match(await pw.getPassword("a passphrase", length), /^[A-Za-z0-9]+$/);
    }
});

test("rejects lengths that are not plain in-range integers", () => {
    for (const bad of ["", " ", "abc", "12abc", "1.5", "-5", "0", "1e3", "٣", null, undefined, NaN, "257", "99999"]) {
        assert.strictEqual(pw.parseLength(bad), null, `expected ${JSON.stringify(bad)} to be rejected`);
    }
});

test("accepts lengths at and inside the boundaries", () => {
    assert.strictEqual(pw.parseLength("12"), 12);
    assert.strictEqual(pw.parseLength(" 12 "), 12);
    assert.strictEqual(pw.parseLength(12), 12);
    assert.strictEqual(pw.parseLength(String(pw.MIN_LENGTH)), pw.MIN_LENGTH);
    assert.strictEqual(pw.parseLength(String(pw.MAX_LENGTH)), pw.MAX_LENGTH);
});

test("retries deterministically rather than recursing without bound", async () => {
    // "passphrase1" fails the mix check on its first derivation, so this
    // exercises the retry path; it must be stable across calls.
    const first = await pw.getPassword("passphrase1", 12);
    assert.strictEqual(await pw.getPassword("passphrase1", 12), first);
    assert.strictEqual(pw.isStrongEnough(first), true);
});
