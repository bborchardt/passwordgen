TestCase("PasswordSpec", {
    "test replace character": function() {
        assertEquals("xaa", pw._private.replaceChar("aaa", 0, "x"));
        assertEquals("axa", pw._private.replaceChar("aaa", 1, "x"));
        assertEquals("aax", pw._private.replaceChar("aaa", 2, "x"));
    },

    "test replace special characters": function () {
        assertEquals("01234567890123456789", pw._private.replaceSpecialChars("===================="));
        assertEquals("01234567890123456789", pw._private.replaceSpecialChars("++++++++++++++++++++"));
        assertEquals("01234567890123456789", pw._private.replaceSpecialChars("////////////////////"));
        assertEquals("a123Z1", pw._private.replaceSpecialChars("a/+=Z1"));
    },

    "test truncate": function() {
        assertEquals("1234567890", pw._private.truncate("1234567890", 10));
        assertEquals("1234567890", pw._private.truncate("1234567890", 0));
        assertEquals("12345678", pw._private.truncate("1234567890", 8));
    },

    "test strong password": function() {
        assertFalse(pw._private.isStrong("abcXYZ"));
        assertFalse(pw._private.isStrong("abc123"));
        assertFalse(pw._private.isStrong("ABC123"));
        assertTrue(pw._private.isStrong("aB1"));
    },

    "test get password": function() {
        assertEquals("kAFQmDzST7DWlj99KOF/cg==", pw._private.getHashedBase64("abc"));
        assertEquals("I3NM1SrUpPuHfYoeJuXfXw==", pw._private.getHashedBase64("abc1"));
        assertEquals("kAFQmDzST7DWlj99KOF9cg23", pw._private.getPassword("abc"));
        assertEquals("kAFQmDzST7DWlj9", pw._private.getPassword("abc", 15));
        assertEquals("I3NM1SrUp", pw._private.getPassword("abc", 9));
        assertEquals("I3NM1SrUp", pw._private.getPassword("abc1", 9));
    }
});