(function (document, pw, pwv2, strength) {
    "use strict";

    var byId = function (id) {
        return document.getElementById(id);
    };

    var el = {};

    var setMessage = function (text, isError) {
        el.message.textContent = text || "";
        el.message.className = isError ? "message message-error" : "message";
    };

    var setOutput = function (password) {
        el.output.value = password;
        if (password) {
            el.output.select();
            el.output.focus();
        }
    };

    var isLegacy = function () {
        return el.legacy.checked;
    };

    // The meter is the point of v2 as much as the crypto is: passphrase
    // entropy outweighs the key derivation function by more than an order of
    // magnitude, so the user needs to see where they stand.
    var showStrength = function () {
        var value = el.input.value;
        if (!value) {
            el.strength.textContent = "";
            el.strength.className = "strength";
            return;
        }
        var r = strength.estimate(value);
        el.strength.textContent =
            r.label + " · about " + r.bits + " bits · " +
            (r.label === "weak" ? "cracked " : "holds ") + r.crackTime +
            " against an attacker who already has one of your passwords";
        el.strength.className = "strength strength-" + r.label;
    };

    var showScheme = function () {
        var legacy = isLegacy();
        el.v2fields.hidden = legacy;
        el.symbolsRow.hidden = legacy;
        el.schemeHint.textContent = legacy
            ? "v1 reproduces passwords made before the site field existed. It has no "
              + "site binding, so one phrase gives one password everywhere."
            : "v2 binds each password to its site, so a breach at one site does not "
              + "expose the others.";
        el.lengthField.value = legacy ? "12" : "16";
    };

    var readLegacyOptions = function () {
        var length = pw.parseLength(el.lengthField.value);
        if (length === null) {
            return {error: "Length must be a whole number between " +
                pw.MIN_LENGTH + " and " + pw.MAX_LENGTH + ".", focus: el.lengthField};
        }
        if (!el.input.value) {
            return {error: "Enter a master phrase.", focus: el.input};
        }
        return {length: length};
    };

    var readOptions = function () {
        var raw = String(el.lengthField.value).trim();
        if (!/^\d+$/.test(raw)) {
            return {error: "Length must be a whole number.", focus: el.lengthField};
        }
        var length = parseInt(raw, 10);
        if (length < pwv2.MIN_LENGTH || length > pwv2.MAX_LENGTH) {
            return {error: "Length must be between " + pwv2.MIN_LENGTH +
                " and " + pwv2.MAX_LENGTH + ".", focus: el.lengthField};
        }
        if (!el.input.value) {
            return {error: "Enter a master phrase.", focus: el.input};
        }
        if (!el.site.value.trim()) {
            return {error: "Enter the site this password is for.", focus: el.site};
        }
        var counter = String(el.counter.value).trim();
        if (!/^\d+$/.test(counter)) {
            return {error: "Counter must be a whole number.", focus: el.counter};
        }
        return {
            passphrase: el.input.value,
            site: el.site.value,
            username: el.username.value,
            counter: parseInt(counter, 10),
            length: length,
            symbols: el.symbols.checked
        };
    };

    var showPassword = async function () {
        var legacy = isLegacy();
        var options = legacy ? readLegacyOptions() : readOptions();
        if (options.error) {
            setOutput("");
            setMessage(options.error, true);
            options.focus.focus();
            return;
        }

        setMessage("Generating…");
        el.generate.disabled = true;
        try {
            if (legacy) {
                // v1 is synchronous and blocks; yield first so the pending
                // state actually paints.
                await new Promise(function (resolve) { window.setTimeout(resolve, 0); });
                setOutput(pw.getPassword(el.input.value, options.length));
            } else {
                setOutput(await pwv2.getPassword(options));
            }
            setMessage("");
        } catch (e) {
            setOutput("");
            setMessage(e && e.message ? e.message : "Could not generate a password.", true);
        } finally {
            el.generate.disabled = false;
        }
    };

    var toggleReveal = function () {
        var hidden = el.input.type === "password";
        el.input.type = hidden ? "text" : "password";
        el.reveal.textContent = hidden ? "Hide" : "Show";
        el.reveal.setAttribute("aria-pressed", hidden ? "true" : "false");
        el.input.focus();
    };

    var copyPassword = function () {
        if (!el.output.value) {
            return;
        }
        el.output.select();
        var done = function () { setMessage("Copied to clipboard."); };
        var fallback = function () {
            try {
                if (document.execCommand("copy")) {
                    done();
                    return;
                }
            } catch (e) {
                // fall through to the manual instruction below
            }
            setMessage("Press Ctrl+C / ⌘C to copy.");
        };
        // navigator.clipboard is unavailable outside a secure context.
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(el.output.value).then(done, fallback);
        } else {
            fallback();
        }
    };

    document.addEventListener("DOMContentLoaded", function () {
        el = {
            input: byId("passwordin"),
            strength: byId("strength"),
            v2fields: byId("v2fields"),
            site: byId("site"),
            username: byId("username"),
            counter: byId("counter"),
            lengthField: byId("passwordlength"),
            symbols: byId("symbols"),
            symbolsRow: byId("symbolsrow"),
            output: byId("passwordout"),
            generate: byId("generate"),
            reveal: byId("reveal"),
            copy: byId("copy"),
            legacy: byId("legacy"),
            schemeHint: byId("schemehint"),
            message: byId("message")
        };

        el.generate.addEventListener("click", showPassword);
        el.reveal.addEventListener("click", toggleReveal);
        el.copy.addEventListener("click", copyPassword);
        el.input.addEventListener("input", showStrength);
        el.legacy.addEventListener("change", showScheme);

        // There is no form element to submit, so Enter needs wiring by hand.
        [el.input, el.site, el.username, el.counter, el.lengthField].forEach(function (field) {
            field.addEventListener("keydown", function (event) {
                if (event.key === "Enter") {
                    event.preventDefault();
                    showPassword();
                }
            });
        });

        // Selecting the output on focus makes it a single tap to copy on iOS.
        // Bound once here; v1 rebound it on every generate, so the handlers
        // accumulated for the life of the page.
        el.output.addEventListener("focus", function () {
            el.output.setSelectionRange(0, 9999);
        });

        showScheme();
        el.input.focus();
    });
}(document, pw, pwv2, strength));
