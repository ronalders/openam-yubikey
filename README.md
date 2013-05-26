openam-yubikey
==============

OpenAM Yubikey Authentication module

Authentication module for use with ForgeRock OpenAM (http://forgerock.com/). 

The module validated Yubikey OTP agains Yubico YubiCloud validation platform
See: http://www.yubico.com for more details

For valdition of OTP is depends onYubico Java client v2 (currently 2.0.1). 
See: https://github.com/Yubico/yubico-java-client

By default all parts use the Yubico YubiCloud validation platform, but can
be configured for another validaiton server. To use YubiCloud you need a
client id and an API key that can be fetched from
https://upgrade.yubico.com/getapikey/. 

Installation instruction of Authentication module on OpenAM instance:

* Activate ssoadm web interface: Activate ssoadm.jsp (see https://wikis.forgerock.org/confluence/display/openam/Activate+ssoadm.jsp)
* Go to /openam/ssoadm.jsp?cmd=create-svc
* Paste in your amAuthYubikeyModule.xml and submit the form
* Go to /openam/ssoadm.jsp?cmd=register-auth-module
* Supply auth module class 'nl.alders.openam.YubikeyModule' and submit stop the webcontainer
* Copy the amAuthYubikeyModule.properties and amAuthYubikeyModule.xml files to WEB-INF/classes 
* Copy the YubikeyModule.xml to config/auth/default
* Copy the openam-yubikey-{version}-jar-with-dependencies.jar to WEB-INF/lib
* Start the webcontainer
* Access Control ->  realm ->  Authentication ->  Modules -> you should be able to add a new instance of your module.


Configure Yubikey module with apikey and secretkey and OpenAM identity attrubute and your ready for use.
