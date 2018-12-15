<%--
  Created by IntelliJ IDEA.
  User: jl250
  Date: 2018/12/10
  Time: 22:27
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Login</title>
</head>
<body>
<h2>欢迎登陆</h2>
<form action="/loginUser" method="post">
    <input type="text" name="username"> <br>
    <input type="password" name="password"> <br>
    <input type="submit" value="提交">
</form>
</body>
</html>
