var strength = (function () {
    "use strict";

    // ---------------------------------------------------------------------
    // A deliberately pessimistic passphrase strength estimate.
    //
    // This exists because passphrase entropy matters far more than the KDF: at
    // v2's cost, moving a user from ~35 bits to ~46 is worth roughly 2000x,
    // where the entire choice of key derivation function is worth perhaps 50x.
    //
    // It is an estimate, and it is designed to be wrong in the safe direction.
    // The score is the MINIMUM over several attack models, because an attacker
    // takes the cheapest path available, not the average one. A meter that
    // scored "Password1!" as strong - as any length-times-alphabet formula
    // does - would be worse than showing nothing at all.
    //
    // It is not zxcvbn. It has no dictionary, so instead it assumes the
    // attacker has one: any alphabetic run is charged as though it were a
    // common word. That under-rates genuinely random strings, which is the
    // acceptable direction to be wrong in.
    // ---------------------------------------------------------------------

    // Guesses per second for an attacker with ~10 GPUs against v2's PBKDF2 at
    // 4,000,000 iterations. Order of magnitude, not a benchmark.
    var GUESSES_PER_SECOND = 15000;

    // A word an attacker's dictionary almost certainly contains. 2^11 = 2048.
    var BITS_PER_KNOWN_WORD = 11;

    var COMMON = ("password passwd pass123 123456 12345678 123456789 qwerty abc123 letmein " +
        "monkey dragon master sunshine princess football baseball welcome admin " +
        "login iloveyou trustno1 starwars whatever qazwsx zaq12wsx passw0rd " +
        "hunter2 superman batman shadow michael jennifer jordan harley ranger " +
        "changeme secret summer winter spring autumn january december").split(" ");

    var KEYBOARD = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

    var log2 = function (n) {
        return Math.log(n) / Math.log(2);
    };

    var charsetSize = function (s) {
        var size = 0;
        if (/[a-z]/.test(s)) { size += 26; }
        if (/[A-Z]/.test(s)) { size += 26; }
        if (/[0-9]/.test(s)) { size += 10; }
        if (/[^A-Za-z0-9]/.test(s)) { size += 33; }
        return size || 1;
    };

    // Undo the substitutions people reach for first, so "P@ssw0rd" is scored as
    // "password" rather than as a string with three character classes.
    var deleet = function (s) {
        return s.toLowerCase()
            .replace(/[04]/g, "o").replace(/[13!|]/g, "i").replace(/3/g, "e")
            .replace(/@/g, "a").replace(/[5$]/g, "s").replace(/7/g, "t");
    };

    var isCommon = function (s) {
        var lower = s.toLowerCase();
        // Strip the trailing digits and punctuation that get bolted on to
        // satisfy a site's rules; they add far less than they appear to.
        var core = lower.replace(/[^a-z]+$/, "");
        var i;
        for (i = 0; i < COMMON.length; i += 1) {
            if (lower === COMMON[i] || core === COMMON[i] || deleet(core) === COMMON[i]) {
                return true;
            }
        }
        return false;
    };

    // Runs like "abcdef", "aaaa" or "qwerty" cost an attacker almost nothing,
    // so they should not count toward length.
    var patternedLength = function (s) {
        var lower = s.toLowerCase();
        var counted = 0;
        var i = 0;
        while (i < lower.length) {
            var run = 1;
            while (i + run < lower.length && isPredictable(lower, i + run)) {
                run += 1;
            }
            // A predictable run of any length is worth about one free choice.
            counted += (run > 2) ? 1 : run;
            i += run;
        }
        return counted;
    };

    var isPredictable = function (lower, i) {
        var prev = lower.charCodeAt(i - 1);
        var cur = lower.charCodeAt(i);
        if (cur === prev || cur === prev + 1 || cur === prev - 1) {
            return true;
        }
        var r, at;
        for (r = 0; r < KEYBOARD.length; r += 1) {
            at = KEYBOARD[r].indexOf(lower.charAt(i - 1));
            if (at >= 0 && Math.abs(KEYBOARD[r].indexOf(lower.charAt(i)) - at) === 1 &&
                    KEYBOARD[r].indexOf(lower.charAt(i)) >= 0) {
                return true;
            }
        }
        return false;
    };

    // Treat every alphabetic run as a word the attacker already has, unless
    // guessing it character by character would genuinely be cheaper.
    var wordModelBits = function (s) {
        var tokens = deleet(s).split(/[^a-z]+/).filter(function (t) { return t.length > 0; });
        if (tokens.length === 0) {
            return Infinity;
        }
        var bits = 0;
        var i;
        for (i = 0; i < tokens.length; i += 1) {
            bits += Math.min(BITS_PER_KNOWN_WORD, tokens[i].length * log2(26));
        }
        // Whatever is left over - digits, symbols, separators - still costs
        // something, but far less than its face value.
        var leftovers = s.length - tokens.join("").length;
        bits += leftovers * log2(10);
        return bits;
    };

    var estimate = function (input) {
        var s = String(input == null ? "" : input);
        if (s.length === 0) {
            return {bits: 0, label: "empty", crackTime: "instantly"};
        }
        if (isCommon(s)) {
            return describe(Math.min(12, s.length * log2(charsetSize(s))));
        }
        var bruteForce = patternedLength(s) * log2(charsetSize(s));
        return describe(Math.min(bruteForce, wordModelBits(s)));
    };

    var describe = function (bits) {
        return {
            bits: Math.round(bits),
            label: label(bits),
            crackTime: humanTime(Math.pow(2, bits - 1) / GUESSES_PER_SECOND)
        };
    };

    // Bands chosen from what the number actually buys against this tool's own
    // key derivation, not from a generic scale.
    var label = function (bits) {
        if (bits < 35) { return "weak"; }
        if (bits < 46) { return "fair"; }
        if (bits < 60) { return "good"; }
        return "strong";
    };

    var humanTime = function (seconds) {
        if (seconds < 1) { return "instantly"; }
        if (seconds < 3600) { return Math.max(1, Math.round(seconds / 60)) + " minutes"; }
        if (seconds < 86400) { return Math.round(seconds / 3600) + " hours"; }
        if (seconds < 86400 * 365) { return Math.round(seconds / 86400) + " days"; }
        var years = seconds / (86400 * 365);
        if (years < 1000) { return Math.round(years) + " years"; }
        if (years < 1e6) { return Math.round(years / 1000) + " thousand years"; }
        return "millions of years";
    };

    return {estimate: estimate, _patternedLength: patternedLength, _wordModelBits: wordModelBits};
}());

if (typeof module !== "undefined" && module.exports) {
    module.exports = strength;
}
