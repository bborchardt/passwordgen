(function (document, pw) {
    "use strict";

    var byId = function (id) {
        return document.getElementById(id);
    };

    var input, lengthField, output, generateButton, revealButton, copyButton, message;

    var setMessage = function (text, isError) {
        message.textContent = text || "";
        message.className = isError ? "message message-error" : "message";
    };

    var setOutput = function (password) {
        output.value = password;
        if (password) {
            output.select();
            output.focus();
        }
    };

    // The derivation blocks the main thread for a few hundred milliseconds, and
    // longer whenever the strength retry fires. Paint the pending state before
    // starting so the page does not just freeze.
    var showPassword = function () {
        var length = pw.parseLength(lengthField.value);
        if (length === null) {
            setOutput("");
            setMessage("Length must be a whole number between " +
                pw.MIN_LENGTH + " and " + pw.MAX_LENGTH + ".", true);
            lengthField.focus();
            return;
        }
        if (!input.value) {
            setOutput("");
            setMessage("Enter something to generate a password from.", true);
            input.focus();
            return;
        }

        setMessage("Generating…");
        generateButton.disabled = true;
        window.setTimeout(function () {
            try {
                setOutput(pw.getPassword(input.value, length));
                setMessage("");
            } catch (e) {
                setOutput("");
                setMessage("Could not generate a password.", true);
            } finally {
                generateButton.disabled = false;
            }
        }, 0);
    };

    var toggleReveal = function () {
        var hidden = input.type === "password";
        input.type = hidden ? "text" : "password";
        revealButton.textContent = hidden ? "Hide" : "Show";
        revealButton.setAttribute("aria-pressed", hidden ? "true" : "false");
        input.focus();
    };

    var copyPassword = function () {
        if (!output.value) {
            return;
        }
        output.select();
        var done = function () {
            setMessage("Copied to clipboard.");
        };
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
            navigator.clipboard.writeText(output.value).then(done, fallback);
        } else {
            fallback();
        }
    };

    document.addEventListener("DOMContentLoaded", function () {
        input = byId("passwordin");
        lengthField = byId("passwordlength");
        output = byId("passwordout");
        generateButton = byId("generate");
        revealButton = byId("reveal");
        copyButton = byId("copy");
        message = byId("message");

        generateButton.addEventListener("click", showPassword);
        revealButton.addEventListener("click", toggleReveal);
        copyButton.addEventListener("click", copyPassword);

        // There is no form element to submit, so Enter needs wiring by hand.
        [input, lengthField].forEach(function (field) {
            field.addEventListener("keydown", function (event) {
                if (event.key === "Enter") {
                    event.preventDefault();
                    showPassword();
                }
            });
        });

        // Selecting the output on focus makes it a single tap to copy on iOS.
        // Bound once here; the original rebound it on every generate, so the
        // handlers accumulated for the life of the page.
        output.addEventListener("focus", function () {
            output.setSelectionRange(0, 9999);
        });

        input.focus();
    });
}(document, pw));
