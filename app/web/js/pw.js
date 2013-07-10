var pw = (function(document, $) {
    "use strict";
    var showPassword = function() {
        var input = getInput();
        var length = parseInt(getLength(), 10);
        var password = getPassword(input, length);
        setOutput(password);
    };

    var getInput = function() {
        return $("#passwordin").val();
    };

    var getLength = function() {
        return $("#passwordlength").val();
    };

    var getPassword = function(input, length) {
        var password = getHashedBase64(input);
        password = replaceSpecialChars(password);
        password = truncate(password, length);
        if(isStrong(password)) {
            return password;
        } else {
            return getPassword(input + "1", length);
        }
    };

    var getHashedBase64 = function(input) {
        return CryptoJS.MD5(input).toString(CryptoJS.enc.Base64);
    };

    var replaceSpecialChars = function(input) {
        var base64SpecialChars = ["+", "/", "="];
        var index = -1, i, specialChar;
        for(i=0; i<base64SpecialChars.length; i++) {
            specialChar = base64SpecialChars[i];
            while((index = input.indexOf(specialChar)) >= 0) {
                input = replaceChar(input, index, index % 10);
            }
        }
        return input;
    };

    var replaceChar = function(input, replaceIndex, replacement) {
        if(replaceIndex === 0) {
            return replacement + input.substring(1);
        } else if(replaceIndex === input.length-1) {
            return input.substring(0, input.length - 1) + replacement;
        } else {
            return input.substring(0, replaceIndex) + replacement + input.substring(replaceIndex+ 1, input.length);
        }
    };

    var truncate = function(input, length) {
        if(length > 0 && length < input.length) {
            input = input.substring(0, length);
        }
        return input;
    };

    var isStrong = function(input) {
        return input.length >= 3 &&
            countMatches(input, /[0-9]/g) > 0 &&
            countMatches(input, /[a-z]/g) > 0 &&
            countMatches(input, /[A-Z]/g) > 0;
    };

    var countMatches = function(input, regex) {
        return (input.match(regex) || []).length;
    };

    var setOutput = function(output) {
        var e = $("#passwordout");
        e.val(output);
        e.focus(function () {
            this.setSelectionRange(0, 9999); return false;
        }).mouseup( function () { return false; });
        e.select();
        e.focus();
    };

    $(document).ready(function() {
        $("#passwordin").focus();
    });

    return {
        showPassword: showPassword,
        _private: {
            getHashedBase64: getHashedBase64,
            getPassword: getPassword,
            replaceSpecialChars: replaceSpecialChars,
            replaceChar: replaceChar,
            truncate: truncate,
            isStrong: isStrong
        }
    };
}(document, $));