<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html>
<head>
    <title>Password Generator</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="css/bootstrap.min.css" rel="stylesheet" media="screen">
    <style type="text/css">
        body {
            padding-top: 40px;
            padding-bottom: 40px;
            background-color: #f5f5f5;
        }

        .form-signin {
            max-width: 400px;
            padding: 19px 29px 29px;
            margin: 0 auto 20px;
            background-color: #fff;
            border: 1px solid #e5e5e5;
            -webkit-border-radius: 5px;
            -moz-border-radius: 5px;
            border-radius: 5px;
            -webkit-box-shadow: 0 1px 2px rgba(0,0,0,.05);
            -moz-box-shadow: 0 1px 2px rgba(0,0,0,.05);
            box-shadow: 0 1px 2px rgba(0,0,0,.05);
        }
        .form-signin .form-signin-heading {
            text-align: center;
        }
        .form-signin input[type="text"] {
            font-size: 16px;
            height: auto;
            margin-bottom: 15px;
            padding: 7px 9px;
        }
        .form-signin button {
            margin-top: 15px;
            margin-bottom: 24px;
        }

    </style>
    <link href="css/bootstrap-responsive.min.css" rel="stylesheet" media="screen">
</head>
<body>
<div class="container">
    <form class="form-signin">
        <h2 class="form-signin-heading">Password Generator</h2>
        <label class="control-label" for="passwordin">Input</label>
        <div class="controls"><input type="text" id="passwordin" class="input-block-level"/></div>
        <label class="control-label" for="passwordlength">Password Length</label>
        <input type="text" id="passwordlength" class="input-block-level" value="12"/>
        <button type="button" class="btn btn-large btn-primary" accesskey="p" onclick="pw.showPassword()"
                ><i class="icon-lock"></i> Generate <u>P</u>assword</button>
        <label class="control-label" for="passwordout">Generated Password</label>
        <input type="text" id="passwordout" class="input-block-level" disabled/>
    </form>
</div>
<script src="js/md5.js"></script>
<script src="js/enc-base64.js"></script>
<script src="js/jquery.js"></script>
<script src="js/bootstrap.min.js"></script>
<script src="js/pw.js"></script>
</body>
</html>