var pw = (function(document, $) {
    var showPassword = function() {
        var input = getInput();
        var hash = CryptoJS.MD5(input);
        var password = hash.toString(CryptoJS.enc.Base64);
        password = password.replace(/\+/g, "7");
        password = password.replace(/\//g, "2");
        password = password.replace(/=/g, "4");
        var truncated = truncate(password);
        var strong = strengthen(truncated);
        setOutput(strong);
    };

    var getInput = function() {
        return $("#passwordin").val();
    };

    var getLength = function() {
        return $("#passwordlength").val();
    };

    var truncate = function(text) {
        var length = parseInt(getLength());
        if(length > 0 && length < text.length) {
            text = text.substring(0, length)
        }
        return text;
    };

    var strengthen = function(text) {
        if(text.length >= 6) {
            if(!text.match(/[0-9].*[0-9]/g)) {
                text = "9" + text.substring(0, text.length - 2) + "3";
            }
            if(!text.match(/[A-Z].*[A-Z]/g)) {
                text = "N" + text.substring(0, text.length - 2) + "W";
            }
            if(!text.match(/[a-z].*[a-z]/g)) {
                text = "q" + text.substring(0, text.length - 2) + "b";
            }
        }
        return text;
    };

    var setOutput = function(output) {
        var e = $("#passwordout");
        e.val(output);
        e.focus(function () {
            this.setSelectionRange(0, 9999); return false;
        }).mouseup( function () { return false; });
        e.focus();
    };

    $(document).ready(function() {
        $("#passwordin").focus();
    });

    return {
        showPassword: showPassword
    }
})(document, jQuery);