<%@ Language=VBScript %>
<%
Response.AddHeader "Set-Cookie", Request.ServerVariables("COSIGN_SERVICE" ) + "="
Response.Redirect( "http://weblogin.example.edu/cgi-bin/logout?http://www.example.edu/" )
%>
