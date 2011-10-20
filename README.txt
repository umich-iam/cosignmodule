
== Installation instructions for IIS 7 CosignModule ==

1) Configure SSL certificates and https.
	1.a) Install rewritemodule to redirect http traffic to https.
2) Modify permissions for ssl certs and private keys.
	2.a) Install any necessary certificate authority files.
3) Create cookie database directory.
4) Copy the cosignmodule files.
5) Modify applicationhost.config with cosign values.
	.a) Turn off cosign protection for /cosign/valid
6) Enable the cosignmodule.
	.a) 32-bit application pools.
7) Create the cosign validation handler.
	.a) 32-bit validation handler.
8) Test a cosign-protected page.
() Turn cosign protection on and off, factors
() Getting more help.

(1) Configure SSL and https (1)
===================================================
Generate an SSL certificate and have it signed, if needed:
http://technet.microsoft.com/en-us/library/cc732906(WS.10).aspx

Before proceeding, be sure that your web site is accessible over https. By default, the CosignModule marks its
cookies as secure. This means if a user logs in and browses to an http part of your web site, it will appear
to the cosignmodule that the user is not logged in. Being sure this works correctly now, as well as any redirects
from http to https (see below), will save you headaches later.


(1.a) Install RewriteModule to redirect http traffic to https (1.a)
To ensure users are sent to the secure, cosign-protected portion of your web site, it may be necessary to
intercept http requests and redirect them to their https equivalent. The Microsoft Rewrite Module is
recommended.

It can be downloaded here:
http://www.iis.net/download/urlrewrite


(2) Modify Permissions for SSL Private Keys (2)
===================================================
The account or group the application pool runs as needs Full Control and Read permissions in the
following Registry key:
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\MY	

By default, this account is IIS AppPool\DefaultAppPool in Windows 2008 R2. "Network Services" should
work for Windows 2008.

Give said account permission from within certificate manager.
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

(2.a) Install Any Necessary Certificate Authority Files (2.a)

Cosign needs a certificate authority file to verify the identity of the weblogin server it is talking to.

For example, the University of Michigan weblogin servers' certificates are signed by the UM Web Certificate authority.
To install UMWebCA.pem certificate:
    Download the file: http://www.umich.edu/~umweb/umwebCA.pem
	Open Certificates from local machine (see above).
	Action | All tasks | Import ...
	Select the umwebca.pem file.


(3) Create a Directory for the Cookie Cache (3)
===================================================
Create a folder for the service cookie cache:
	md C:\inetpub\temp\Cosign Cookie DB

Permissions: IIS_IUSRS, full control


(4) Copy the CosignModule Files (4)
===================================================

copy /Y x64/CosignModule.dll C:\Windows\System32\inetsrv
copy /Y x86/CosignModule.dll C:\Windows\SysWOW64\inetsrv
copy /Y Cosign_Schema.xml C:\Windows\System32\inetsrv\config\schema


(5) Modify applicationhost.config with cosign values.
===================================================

In the applicationhost.config file, add the following options. Note that the
proxyCookies section can be ignored. Only add this line, uncommented, of course
if your weblogin servers are configured to provide your web site with
proxy cookies.


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
	    <!-- proxyCookies directory="%SystemDrive%\inetpub\temp\Cosign Proxy DB" / -->
        <validation validReference="https?://www\.example\.org(/.*)?"
                    errorRedirectUrl="http://weblogin.example.org/validation_error.html" />      
        <cookies secure="true" httpOnly="true" />
        <service name="cosign-www.example.org" />
        <protected status="on" />
      </cosign>

      ...
      
   </system.webServer>


(5.a) Turn Off Cosign Protection for /cosign/valid (5.a)

For the validation handler (see below) to work correctly, cosign protection
needs to be turned off for the /cosign/valid location. This can be done by
adding the following XML to applicationHost.config:

<location path="Default Web Site/cosign/valid">
    <system.webServer>
	    <cosign>
            <protected status="off" />
	    </cosign>
    </system.webServer>
</location>	


(6) Enable the CosignModule.(5)
===================================================

Here are the command line options for adding and removing the cosign module.
If appcmd.exe is not in your %PATH%, you can find it in 
%windier%\system32\inetsrv

appcmd delete module "Cosign" /app.name:"Default Web Site/"
appcmd uninstall module "Cosign"
appcmd install module /name:"Cosign" /image:"CosignModule.dll" /add:"false"
appcmd add module /name:"Cosign" /app.name:"Default Web Site/"

The module can also be added and removed from the IIS Manager interface.


(6.a) 32-bit Application Pools (6.a)
If you have 32-bit applications enabled and want to use cosign with these sites
you will need to add the 32-bit module as well.

appcmd install module /name:"Cosign-x86" /image:"%windir%\SysWOW64\inetsrv\CosignModule.dll" /add:"false" /precondition="bitness32"
appcmd add module /name:"Cosign-x86" /app.name:"32-bit legacy app"


(7) Create the Cosign Validation Handler.
===================================================

This can be done from within the IIS Manager under "Sites", "[name of your web site]", Handler Mappings, then select
"Add Module Mapping...", and specify the following items:

RequestPath:
/cosign/valid*

Module:
Cosign

Name:
Cosign Validation


The validation handler can also be added with the following command:
appcmd set config "Default Web Site" /section:handlers /+[name='Cosign-Validation',path='/cosign/valid*',verb='*',modules='Cosign']

(7.a) 32-bit Validation Handler (7.a)
Same as above, but be sure to specify the 32-bit CosignModule and set the
precondition to bitness32.

appcmd set config "32-bit legacy app" /section:handlers /+[name='Cosign-Validation',path='/cosign/valid*',verb='*',modules='Cosign-x86',precondition='bitness32']


(8) Test a cosign-protected page.
===================================================

Load up your favorite, modern web browser and navigate to a cosign-protected
page on your web site. If everything went smoothly, you should be redirected
to your weblogin server and back to your cosign-protected web site.

Also see the included example scripts to get an idea of how to access the
cosign server variables.


() Turn cosign protection on and off, factors ()
===================================================

Each directory can also have a web.config file that overrides inherited configuration options:

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
       <cosign>
            <protected status="off" />
        </cosign>
    </system.webServer>
</configuration>


If your server needs to configure specific authentication factors, you'll need
to add some items to the <service> tag.

<service name="cosign-www.example.org" />
	<add factor="rsatoken" />
</service>

If you need to enable the optional ignore suffix, it will look like this:

<service name="cosign-www.example.org" />
	<add factor="rsatoken" />
	<add ignoreSuffix="-magic" />
</service>

Note that the "factor" items must all be satisfied, the "ignoreSuffix" will be
matched to any factor. For example, this configuration...

<service name="cosign-www.example.org" />
	<add factor="rsatoken" />
	<add factor="kerberos" />
	<add ignoreSuffix="-magic" />
</service>

... will match the following factor combinations:

rsatoken kerberos
rsatoken-magic kerberos-magic
rsatoken-magic kerberos
rsatoken kerberos-magic


NOTE: Running an application pool in "classic mode" may result in the server variables not being available to ASP scripts.  There is a compatibilityMode
option to correct this.  You can add it to the <cosign> section of your config file.

<cosign>
...
    <compatibilityMode mode="true" />
</cosign>


() Getting More Help ()
===================================================

http://weblogin.org/
http://webapps.itcs.umich.edu/cosign/index.php/Troubleshooting

Please join the discussion list before sending e-mail:
https://lists.sourceforge.net/lists/listinfo/cosign-discuss
cosign-discuss@lists.sourceforge.net

To receive announcements, please join:
https://lists.sourceforge.net/lists/listinfo/cosign-announce
cosign-announce@lists.sourceforge.net

