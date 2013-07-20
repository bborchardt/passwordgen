var pw = (function (document, $) {
    "use strict";
    var showPassword = function () {
        var input = getInput();
        var length = parseInt(getLength(), 10);
        var password = getPassword(input, length);
        setOutput(password);
    };

    var getInput = function () {
        return $("#passwordin").val();
    };

    var getLength = function () {
        return $("#passwordlength").val();
    };

    var getPassword = function (input, length) {
        // get a hash of double the desired length + 2 so we have enough to work with
        // after base64 encoding and stripping special chars
        var password = getEncodedHash(input, length);
        password = stripSpecialChars(password);
        password = truncate(password, length);
        if (isStrongEnough(password)) {
            return password;
        } else {
            console.log("calling recursively");
            return getPassword(input + "1", length);
        }
    };

    var getEncodedHash = function (input, lengthInBytes) {
        var salt = sjcl.codec.base64.toBits("xnBhH53E3iwFt4GIG0e5Og23");
        // make sure our key size is large enough to get the desired length
        var keySize = Math.ceil(lengthInBytes/4) * 3 * 8 + 48;
        var start = new Date().getTime();
        var hash = sjcl.misc.pbkdf2(input, salt, 100000, keySize);
        console.log(new Date().getTime() - start);
        return sjcl.codec.base64.fromBits(hash);
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
            return containsMinCharTypeMix(input, Math.floor(input.length/6));
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

    var setOutput = function (output) {
        var e = $("#passwordout");
        e.val(output);
        e.focus(function () {
            this.setSelectionRange(0, 9999);
            return false;
        }).mouseup(function () {
            return false;
        });
        e.select();
        e.focus();
    };

    $(document).ready(function () {
        $("#passwordin").focus();
    });

    return {
        showPassword:showPassword,
        _private:{
            getEncodedHash:getEncodedHash,
            getPassword:getPassword,
            stripSpecialChars:stripSpecialChars,
            truncate:truncate,
            isStrongEnough:isStrongEnough
        }
    };
}(document, $));