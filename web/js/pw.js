var pw = (function () {
    "use strict";

    // ---------------------------------------------------------------------
    // v1 derivation parameters.
    //
    // These values define every password this tool has ever produced. Changing
    // any of them silently changes every password every user has already set,
    // and there is no way to tell which parameters produced an existing
    // password, so they are frozen. A future scheme gets its own parameter set
    // alongside this one and a way for the user to choose between them - it
    // never edits these in place.
    //
    // Known weaknesses, all of them output-changing and so deferred to v2:
    //   - the salt is a single public constant shared by every user, so it
    //     defeats no precomputation;
    //   - nothing binds a password to a site, so one passphrase yields one
    //     password everywhere;
    //   - the retry rule below maps input X and input X + "1" to the same
    //     password whenever X is rejected;
    //   - PBKDF2 at 100k iterations is below current guidance and is cheap to
    //     attack on a GPU.
    // ---------------------------------------------------------------------
    var V1 = {
        salt: "xnBhH53E3iwFt4GIG0e5Og23",
        iterations: 100000
    };

    var MIN_LENGTH = 1;
    var MAX_LENGTH = 256;

    var subtle = function () {
        var c = (typeof globalThis !== "undefined" ? globalThis : self).crypto;
        if (!c || !c.subtle) {
            // Only served over a secure context (https, localhost, or file).
            throw new Error("WebCrypto unavailable: serve this page over HTTPS.");
        }
        return c.subtle;
    };

    var utf8 = function (s) {
        return new TextEncoder().encode(s);
    };

    var base64ToBytes = function (b64) {
        var binary = atob(b64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i += 1) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    };

    var bytesToBase64 = function (bytes) {
        var binary = "";
        for (var i = 0; i < bytes.length; i += 1) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    };

    var getEncodedHash = async function (input, lengthInBytes) {
        var s = subtle();
        var salt = base64ToBytes(V1.salt);
        // make sure our key size is large enough to get the desired length
        var keySizeBits = Math.ceil(lengthInBytes / 4) * 3 * 8 + 48;
        var key = await s.importKey("raw", utf8(input), "PBKDF2", false, ["deriveBits"]);
        var hash = await s.deriveBits(
            {name: "PBKDF2", salt: salt, iterations: V1.iterations, hash: "SHA-256"},
            key, keySizeBits
        );
        return bytesToBase64(new Uint8Array(hash));
    };

    // getEncodedHash budgets a fixed 8-character margin for the base64
    // characters we strip. That margin is proportionally smaller the longer the
    // password, and runs out somewhere past 200 characters, where the result is
    // silently shorter than asked for. Derive a longer hash until enough
    // characters survive.
    //
    // This does not disturb passwords that were already the right length:
    // PBKDF2 emits independent blocks, every key size here is a whole number of
    // 3-byte base64 groups, and stripping is a per-character filter, so a
    // shorter derivation is always a prefix of a longer one.
    var getUsableChars = async function (input, length) {
        var request = length;
        var chars = stripSpecialChars(await getEncodedHash(input, request));
        while (chars.length < length && request < MAX_LENGTH * 2) {
            request += (length - chars.length) + 8;
            chars = stripSpecialChars(await getEncodedHash(input, request));
        }
        return chars;
    };

    var getPassword = async function (input, length) {
        var password = truncate(await getUsableChars(input, length), length);
        // v1 rejection rule: retry with "1" appended until the result has a
        // good mix of character types. Iterative where the original recursed -
        // the retry has no depth limit, so deep chains risked the stack. Which
        // passwords come out is unchanged.
        while (!isStrongEnough(password)) {
            input = input + "1";
            password = truncate(await getUsableChars(input, length), length);
        }
        return password;
    };

    var stripSpecialChars = function (input) {
        return input.replace(/\+|\/|=/g, '');
    };

    var truncate = function (input, length) {
        if (length > 0 && length < input.length) {
            input = input.substring(0, length);
        }
        return input;
    };

    var isStrongEnough = function (input) {
        if (input.length < 6) {
            // don't bother checking short passwords
            return true;
        } else {
            // test for a good mix of upper/lower/numeric
            return containsMinCharTypeMix(input, Math.floor(input.length / 6));
        }
    };

    var containsMinCharTypeMix = function (input, count) {
        return countMatches(input, /[0-9]/g) >= count &&
            countMatches(input, /[a-z]/g) >= count &&
            countMatches(input, /[A-Z]/g) >= count;
    };

    var countMatches = function (input, regex) {
        return (input.match(regex) || []).length;
    };

    // An unparseable length used to reach the derivation as NaN and produce a
    // 41-character password; 0 produced 8 characters and a negative number
    // produced 4. Reject anything that is not a plain in-range integer.
    var parseLength = function (raw) {
        var trimmed = String(raw).trim();
        if (!/^\d+$/.test(trimmed)) {
            return null;
        }
        var length = parseInt(trimmed, 10);
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            return null;
        }
        return length;
    };

    return {
        MIN_LENGTH: MIN_LENGTH,
        MAX_LENGTH: MAX_LENGTH,
        getEncodedHash: getEncodedHash,
        getPassword: getPassword,
        parseLength: parseLength,
        stripSpecialChars: stripSpecialChars,
        truncate: truncate,
        isStrongEnough: isStrongEnough
    };
}());

if (typeof module !== "undefined" && module.exports) {
    module.exports = pw;
}
