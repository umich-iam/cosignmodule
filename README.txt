
== Installation instructions for IIS 7 CosignModule ==

== Configure SSL certificates and permissions ==

Generate an SSL certificate and have it signed, if needed:
http://technet.microsoft.com/en-us/library/cc732906(WS.10).aspx


IIS_USRS (or the account or group IIS runs as) needs Full Control and Read permissions in the following Registry key:
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\MY	

(Note: unlike the IIS 6 version of the cosign filter, there is no need to export or generate a key/cert pair
as a plain text file.  The IIS7 CosignModule retrieves a certificate from the Windows certificate store.  See
configuration below.)

Give IIS_IUSRS permission from within certificate manager.
	Start -> Run
	"mmc" (or mmc /64)
	ctrl + M
	Select Certificates
	Add ->
	select Computer Account
	select Local Computer
	Finish, Ok
	
	Select Certificates -> Personal -> Certificates
	Select the certificate that matches the one to use for cosign.  Right-click-> All Tasks -> Manage Private Keys
	Give IIS_IUSRS "Full Control" and "Read" permissions.


Create a folder for the service cookie cache:
	md C:\inetpub\temp\Cosign Cookie DB

Permissions: IIS_IUSRS, full control


== Install any necessary Certificate authority files ==
Cosign uses a certificate authority file to verify the identity of the weblogin server it is talking to.

For example, the University of Michigan weblogin servers' certificates are signed by the UM Web Certificate authority.
To install UMWebCA.pem certificate:
    Download the file: http://www.umich.edu/~umweb/umwebCA.pem
	Open Certificates from local machine (see above).
	Action | All tasks | Import ...
	Select the umwebca.pem file.


== Configuration ==

In the applicationhost.config file, add the following options:

	<configSections>
		...
		<sectionGroup name="system.webServer">
			...
			<section name="cosign" overrideModeDefault="Allow" />
			...
		</sectionGroup>
    </configSections>

	...
	
    <system.webServer>

      ...

      <cosign>
        <webloginServer name="weblogin.example.org" loginUrl="https://weblogin.example.org/?" port="6663"
			postErrorRedirectUrl="https://weblogin.example.org/post_error.html" />
        <crypto certificateCommonName="www.example.org" />
        <cookieDb directory="%systemDrive%\inetpub\temp\Cosign Cookie DB\" expireTime="120" />
	    <proxyCookies directory="%SystemDrive%\inetpub\temp\Cosign Proxy DB" />
        <validation validReference="https?://www\.example\.org(/.*)?"
                    errorRedirectUrl="http://weblogin.example.org/validation_error.html" />      
        <cookies secure="true" httpOnly="true" />
        <service name="cosign-www.example.org" />
        <protected status="off" />
      </cosign>

      ...
      
   </system.webServer>


Each directory can also have a web.config file that overrides inherited configuration options:

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
       <cosign>
            <protected status="off" />
        </cosign>
    </system.webServer>
</configuration>

== Installation ==

Here are the command line options for adding and removing the cosign module.
 
@REM remove module
appcmd delete module "Cosign" /app.name:"Default Web Site/"
appcmd uninstall module "Cosign"
iisreset
@REM copy Cosign_Schema.xml
copy /Y Cosign_Schema.xml C:\Windows\System32\inetsrv\config\schema
@REM add module
copy /Y CosignModule.dll C:\Windows\System32\inetsrv
appcmd install module /name:"Cosign" /image:"CosignModule.dll" /add:"false"
appcmd add module /name:"Cosign" /app.name:"Default Web Site/"

The module can also be added from the IIS Manager interface.  Please note: the cosign module
is not designed to be loaded as a global module.


== Configure a Handler Mapping ==

This can be done from within the IIS Manager under "Sites", "[name of your web site]", Handler Mappings, then select
"Add Module Mapping...", and specify the following items:

RequestPath:
/cosign/valid*

Module:
Cosign

Name:
Cosign Validation


The validation handler can also be added with the following command:
appcmd set config /section:handlers /+[name='Cosign Validation',path='/cosign/valid*',verb='*',modules='Cosign']

Also, turn cosign-protection off to prevent redirect loops:
<location path="Default Web Site/cosign/valid">
    <system.webServer>
	    <cosign>
            <protected status="off" />
	    </cosign>
    </system.webServer>
</location>	



== Using the authentication data in an ASP script ==

COSIGN_FACTOR = <%=Request.ServerVariables("COSIGN_FACTOR")%><br />
COSIGN_SERVICE =  <%=Request.ServerVariables("COSIGN_SERVICE")%><br />
REMOTE_REALM = <%=Request.ServerVariables("REMOTE_REALM")%><br />
REMOTE_USER = <%=Request.ServerVariables("REMOTE_USER")%><br />


== Help ==

http://weblogin.org/

Please join the discussion list before sending e-mail:
https://lists.sourceforge.net/lists/listinfo/cosign-discuss
cosign-discuss@lists.sourceforge.net

To receive announcements, please join:
https://lists.sourceforge.net/lists/listinfo/cosign-announce
cosign-announce@lists.sourceforge.net

