<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Password Generator</title>
</head>
<body>
<table>
    <tr>
        <td><label for="passwordin">Input:</label></td>
        <td><input type="text" id="passwordin" size="40"/></td>
    </tr>
    <tr>
        <td><label for="passwordlength">Length:</label></td>
        <td><input type="text" id="passwordlength" value="14" size="40"/></td>
    </tr>
    <tr>
        <td><label for="passwordout">Password:</label></td>
        <td><input type="text" id="passwordout" readonly="true" size="40"/></td>
    </tr>
</table>
<button type="button" accesskey="m" onclick="pw.showMD5()">MD5</button>
<button type="button" accesskey="p" onclick="pw.showPassword()">Password</button>
</body>
<script src="js/md5.js"></script>
<script src="js/enc-base64.js"></script>
<script src="js/jquery.js"></script>
<script src="js/pw.js"></script>
</html>