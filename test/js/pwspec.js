TestCase("PasswordSpec", {
    "test strip special characters": function () {
        assertEquals("0123456789abcDEF", pw._private.stripSpecialChars("=0+1/2//3++4==56789abcDEF=+/"));
        assertEquals("0123456789abcDEF", pw._private.stripSpecialChars("0123456789abcDEF"));
    },

    "test truncate": function() {
        assertEquals("1234567890", pw._private.truncate("1234567890", 10));
        assertEquals("1234567890", pw._private.truncate("1234567890", 0));
        assertEquals("12345678", pw._private.truncate("1234567890", 8));
    },

    "test is strong password": function() {
        assertTrue(pw._private.isStrongEnough("aaaaa"));
        assertFalse(pw._private.isStrongEnough("aaaaaa"));
        assertTrue(pw._private.isStrongEnough("aaaaA1"));
        assertTrue(pw._private.isStrongEnough("aaaaA1aaaaa"));
        assertFalse(pw._private.isStrongEnough("aaaaA1aaaaaa"));
        assertTrue(pw._private.isStrongEnough("aaaaA1aaaaA1"));
    },

    "test get hash": function() {
        assertEquals("/dOR78/tDCLn", pw._private.getEncodedHash("aaaa", 3));
        assertEquals("/dOR78/tDCLnDpk+mFEW", pw._private.getEncodedHash("aaaa", 12));
    },

    "test get password": function() {
        assertEquals("dOR", pw._private.getPassword("aaaa", 3));
        assertEquals("dOR78t", pw._private.getPassword("aaaa", 6));
        assertEquals("dOR78tDCLnDp", pw._private.getPassword("aaaa", 12));
    }
});