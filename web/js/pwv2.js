var pwv2 = (function () {
    "use strict";

    // ---------------------------------------------------------------------
    // v2 derivation parameters.
    //
    // Frozen for the same reason v1's are: these values define the passwords
    // users set on real sites. Every one of them - the iteration count, the
    // alphabets, the salt encoding, the info strings, the normalisation, the
    // placement shuffle - is part of the contract. Changing any of them
    // changes passwords.
    //
    // What v2 fixes, relative to v1:
    //   - the salt is derived from site + username + counter, so the same
    //     passphrase no longer yields the same password everywhere, and one
    //     precomputation no longer covers every user;
    //   - the counter allows rotation without changing the passphrase;
    //   - PBKDF2 runs natively via WebCrypto at 4,000,000 iterations rather
    //     than 100,000 in JS, roughly a 40x increase in attacker work;
    //   - character classes are guaranteed by deterministic placement rather
    //     than by v1's retry rule, which mapped input X and X + "1" to the
    //     same password;
    //   - characters are drawn by rejection sampling, so every position is
    //     uniform over the alphabet with no modulo bias.
    //
    // What v2 does NOT fix: the salt inputs are guessable, so a targeted
    // attacker who already holds one derived password still gets to attack
    // the passphrase offline. KDF cost is the only defence there, and
    // passphrase entropy matters more than the KDF - hence the strength
    // meter in the UI.
    // ---------------------------------------------------------------------
    var V2 = {
        iterations: 4000000,
        hash: "SHA-256",
        domain: "passwordgen/v2",
        lower: "abcdefghijklmnopqrstuvwxyz",
        upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        digit: "0123456789",
        // Deliberately conservative: no quotes, backslash, backtick, space,
        // angle brackets, slash or pipe, which sites and shells most often
        // reject or mangle.
        symbol: "!#$%&()*+,-.:;=?@[]^_{}"
    };

    var MIN_LENGTH = 8;
    var MAX_LENGTH = 128;

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

    // Netstring-style length prefixes, so that no combination of field values
    // can produce the same salt as a different combination. Plain separators
    // would collide as soon as a field contained the separator.
    var field = function (s) {
        var bytes = utf8(s).length;
        return bytes + ":" + s;
    };

    // Site and username are identifiers, not secrets: fold case and trim so
    // that "Gmail.com " and "gmail.com" do not silently produce different
    // passwords. The passphrase gets NFC only - the standard normalisation for
    // passwords - so the same typed phrase matches across keyboards without
    // altering what the user chose.
    var normaliseId = function (s) {
        return String(s == null ? "" : s).normalize("NFKC").trim().toLowerCase();
    };

    var normalisePassphrase = function (s) {
        return String(s == null ? "" : s).normalize("NFC");
    };

    var buildSalt = function (site, username, counter) {
        return V2.domain +
            field(normaliseId(site)) +
            field(normaliseId(username)) +
            field(String(counter));
    };

    var alphabetFor = function (useSymbols) {
        var classes = [V2.lower, V2.upper, V2.digit];
        if (useSymbols) {
            classes.push(V2.symbol);
        }
        return classes;
    };

    // One expensive PBKDF2 block, then cheap HKDF expansion. Deriving the full
    // stream straight from PBKDF2 would re-run every iteration per 32-byte
    // block: at 4M iterations a 64-character password would cost seconds
    // rather than milliseconds, and the cost would grow with length.
    var deriveSeed = async function (passphrase, salt) {
        var s = subtle();
        var key = await s.importKey(
            "raw", utf8(normalisePassphrase(passphrase)), "PBKDF2", false, ["deriveBits"]
        );
        return s.deriveBits(
            {name: "PBKDF2", salt: utf8(salt), iterations: V2.iterations, hash: V2.hash},
            key, 256
        );
    };

    // Deterministic byte stream from the seed. Chunked so that rejection
    // sampling can never run out of bytes, however unlucky the draw.
    var streamFrom = async function (seed, label) {
        var s = subtle();
        var key = await s.importKey("raw", seed, "HKDF", false, ["deriveBits"]);
        var chunk = 0;
        var buffer = new Uint8Array(0);
        var offset = 0;
        var more = async function () {
            var bits = await s.deriveBits(
                {name: "HKDF", hash: V2.hash, salt: new Uint8Array(0),
                 info: utf8(V2.domain + "/" + label + field(String(chunk)))},
                key, 512 * 8
            );
            chunk += 1;
            var next = new Uint8Array(buffer.length + 512);
            next.set(buffer);
            next.set(new Uint8Array(bits), buffer.length);
            buffer = next;
        };
        return {
            next: async function () {
                if (offset >= buffer.length) {
                    await more();
                }
                var b = buffer[offset];
                offset += 1;
                return b;
            }
        };
    };

    // Uniform index into an alphabet. Taking byte % size directly would favour
    // the first (256 % size) characters; discarding the tail removes that bias.
    var pick = function (byte, size) {
        var limit = 256 - (256 % size);
        return byte < limit ? byte % size : -1;
    };

    var drawFrom = async function (stream, alphabet) {
        var index = -1;
        while (index < 0) {
            index = pick(await stream.next(), alphabet.length);
        }
        return alphabet.charAt(index);
    };

    // Guarantee one character from each class by construction, then shuffle the
    // positions. v1 instead re-derived with "1" appended when a result looked
    // weak, which made two different inputs collide onto one password.
    var shuffle = async function (chars, stream) {
        var i, j;
        for (i = chars.length - 1; i > 0; i -= 1) {
            j = -1;
            while (j < 0) {
                j = pick(await stream.next(), i + 1);
            }
            var tmp = chars[i];
            chars[i] = chars[j];
            chars[j] = tmp;
        }
        return chars;
    };

    var getPassword = async function (options) {
        var length = options.length;
        var useSymbols = options.symbols !== false;
        var classes = alphabetFor(useSymbols);
        var all = classes.join("");

        if (!(length >= MIN_LENGTH && length <= MAX_LENGTH)) {
            throw new Error("length out of range");
        }

        var salt = buildSalt(options.site, options.username, options.counter);
        var seed = await deriveSeed(options.passphrase, salt);
        // The label binds the stream to the alphabet and length, so changing
        // either produces an unrelated password rather than a prefix of one.
        var label = "chars" + field(useSymbols ? "s" : "a") + field(String(length));
        var stream = await streamFrom(seed, label);

        var chars = [];
        var i;
        for (i = 0; i < classes.length; i += 1) {
            chars.push(await drawFrom(stream, classes[i]));
        }
        while (chars.length < length) {
            chars.push(await drawFrom(stream, all));
        }
        return (await shuffle(chars, stream)).join("");
    };

    return {
        MIN_LENGTH: MIN_LENGTH,
        MAX_LENGTH: MAX_LENGTH,
        V2: V2,
        getPassword: getPassword,
        _buildSalt: buildSalt,
        _pick: pick
    };
}());

if (typeof module !== "undefined" && module.exports) {
    module.exports = pwv2;
}
