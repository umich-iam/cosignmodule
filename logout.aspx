<%@ Page Language="C#" %>

<%
   Response.Cookies[ Request.ServerVariables["COSIGN_SERVICE"] ].Value = "";
   Response.Redirect( "http://weblogin.example.edu/cgi-bin/logout?http://www.example.edu/" );
%>
