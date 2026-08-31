"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const pwv2 = require("../web/js/pwv2.js");

const base = {
    passphrase: "correct horse battery staple",
    site: "gmail.com",
    username: "bob",
    counter: 1,
    length: 16
};
const gen = (over) => pwv2.getPassword(Object.assign({}, base, over));

const golden = JSON.parse(
    fs.readFileSync(path.join(__dirname, "v2-vectors.json"), "utf8")
);

// --- the frozen contract ----------------------------------------------------

test("v2 passwords are unchanged", async (t) => {
    for (const v of golden.vectors) {
        await t.test(v.name, async () => {
            assert.strictEqual(await pwv2.getPassword(v.input), v.expected);
        });
    }
});

// --- what v2 exists to fix --------------------------------------------------

test("the same passphrase gives different passwords per site", async () => {
    const a = await gen({site: "gmail.com"});
    const b = await gen({site: "github.com"});
    assert.notStrictEqual(a, b);
});

test("username is bound into the password", async () => {
    assert.notStrictEqual(await gen({username: "bob"}), await gen({username: "alice"}));
});

test("the counter rotates the password", async () => {
    assert.notStrictEqual(await gen({counter: 1}), await gen({counter: 2}));
});

test("appending to the passphrase does not collide (v1's aliasing bug)", async () => {
    // In v1, getPassword("X") and getPassword("X1") returned the same password
    // whenever X failed the strength check. v2 has no retry rule at all.
    const a = await gen({passphrase: "passphrase1"});
    const b = await gen({passphrase: "passphrase11"});
    assert.notStrictEqual(a, b);
});

test("character selection is free of modulo bias", () => {
    // Every alphabet size v2 can use, plus the shuffle's ranges. Each reachable
    // index must be produced by exactly the same number of the 256 byte values.
    for (let size = 2; size <= 128; size += 1) {
        const counts = new Map();
        for (let b = 0; b < 256; b += 1) {
            const i = pwv2._pick(b, size);
            if (i >= 0) {
                counts.set(i, (counts.get(i) || 0) + 1);
            }
        }
        assert.strictEqual(counts.size, size, `size ${size}: not every index reachable`);
        const seen = [...new Set(counts.values())];
        assert.strictEqual(seen.length, 1, `size ${size}: uneven distribution ${seen}`);
    }
});

test("salt encoding cannot be made ambiguous by field contents", () => {
    // Separator-joined salts would collide here; length prefixes cannot.
    assert.notStrictEqual(
        pwv2._buildSalt("a", "bc", 1),
        pwv2._buildSalt("ab", "c", 1)
    );
    assert.notStrictEqual(
        pwv2._buildSalt("a:b", "c", 1),
        pwv2._buildSalt("a", "b:c", 1)
    );
});

// --- output shape -----------------------------------------------------------

test("every character class is present when symbols are on", async () => {
    for (const length of [8, 16, 32]) {
        const p = await gen({length, symbols: true});
        assert.match(p, /[a-z]/, p);
        assert.match(p, /[A-Z]/, p);
        assert.match(p, /[0-9]/, p);
        assert.match(p, new RegExp("[" + pwv2.V2.symbol.replace(/[\^\]\\-]/g, "\\$&") + "]"), p);
    }
});

test("symbols can be turned off", async () => {
    const p = await gen({length: 24, symbols: false});
    assert.match(p, /^[A-Za-z0-9]+$/);
    assert.match(p, /[a-z]/);
    assert.match(p, /[A-Z]/);
    assert.match(p, /[0-9]/);
});

test("returns exactly the requested length", async () => {
    for (const length of [8, 20, 64]) {
        assert.strictEqual((await gen({length})).length, length);
    }
});

test("derivation is deterministic", async () => {
    assert.strictEqual(await gen({}), await gen({}));
});

test("site and username are case- and whitespace-insensitive", async () => {
    const canonical = await gen({site: "gmail.com", username: "bob"});
    assert.strictEqual(await gen({site: "  GMAIL.com ", username: "Bob "}), canonical);
});

test("rejects lengths outside the supported range", async () => {
    for (const length of [0, 7, 129, -1, NaN]) {
        await assert.rejects(() => gen({length}), /length out of range/);
    }
});
