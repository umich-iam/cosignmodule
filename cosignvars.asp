<%@ Language=VBScript %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html>
<head>
<title>Cosign Server Variables</title>
</head>
<body>

<p>
<strong>REMOTE_USER: </strong>
<%=Request.ServerVariables("REMOTE_USER") %>
<br />

<strong>COSIGN_FACTOR: </strong>
<%=Request.ServerVariables("COSIGN_FACTOR") %>
<br />

<strong>COSIGN_SERVICE: </strong>
<%=Request.ServerVariables("COSIGN_SERVICE") %>
<br />

</p>
<a href="/">Home</a> | <a href="http://weblogin.org">Cosign</a> | <a href="logout.asp">Classic ASP Logout</a> | <a href="logout.aspx">ASP.NET Logout</a>
</body>
</html>
