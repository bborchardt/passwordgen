"use strict";

const test = require("node:test");
const assert = require("node:assert");
const strength = require("../web/js/strength.js");

const bits = (s) => strength.estimate(s).bits;
const label = (s) => strength.estimate(s).label;

test("decorating a common password does not rescue it", () => {
    // The failure mode of every length-times-alphabet meter.
    for (const s of ["password", "Password1", "Password1!", "P@ssw0rd", "passw0rd!",
                     "hunter2", "abc123", "letmein123", "monkey!"]) {
        assert.strictEqual(label(s), "weak", `${s} scored ${bits(s)} bits`);
    }
});

test("keyboard runs and repeats do not count as length", () => {
    for (const s of ["qwertyuiop", "aaaaaaaaaaaaaaaa", "abcdefghijklmnop", "1234567890"]) {
        assert.ok(bits(s) < 20, `${s} scored ${bits(s)} bits`);
    }
});

test("a multi-word passphrase scores well", () => {
    assert.ok(bits("correct horse battery staple") >= 46,
        "four random words should reach at least the good band");
    assert.strictEqual(label("correct horse battery staple xylophone"), "strong");
});

test("adding a word never lowers the score", () => {
    const growing = ["correct", "correct horse", "correct horse battery",
                     "correct horse battery staple"];
    for (let i = 1; i < growing.length; i += 1) {
        assert.ok(bits(growing[i]) > bits(growing[i - 1]),
            `${growing[i]} (${bits(growing[i])}) not above ${growing[i - 1]} (${bits(growing[i - 1])})`);
    }
});

test("empty input is reported as empty, not as an error", () => {
    const r = strength.estimate("");
    assert.strictEqual(r.bits, 0);
    assert.strictEqual(r.label, "empty");
});

test("handles null and undefined without throwing", () => {
    for (const v of [null, undefined]) {
        assert.strictEqual(strength.estimate(v).bits, 0);
    }
});

test("the estimate errs low rather than high", () => {
    // A genuinely random 16-character string has far more than this in reality;
    // the word model charges its alphabetic runs as if they were dictionary
    // words. Under-rating strong input is the safe direction, and this test
    // pins that intent so a future change cannot quietly invert it.
    const random16 = "j4K#9vQ!zR2mW7pL";
    assert.ok(bits(random16) < 16 * Math.log2(95),
        "estimate should be below the naive brute-force figure");
    assert.ok(bits(random16) >= 35, "but should still clear the weak band");
});

test("labels follow the documented bands", () => {
    const seen = new Set(["password", "Tr0ub4dor&3", "my dog has fleas",
                          "correct horse battery staple xylophone"].map(label));
    assert.ok(seen.has("weak"));
    assert.ok(seen.has("strong"));
});
