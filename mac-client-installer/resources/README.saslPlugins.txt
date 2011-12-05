********************************************************
* WARNING:
* Plugins are being installed into /usr/local/lib/sasl2,
* but the library will look for them in /usr/lib/sasl2.
* You need to make sure that the plugins will eventually
* be in /usr/lib/sasl2 -- the easiest way is to make a
* symbolic link from /usr/lib/sasl2 to /usr/local/lib/sasl2,
* but this may not be appropriate for your site, so this
* installation procedure won't do it for you.
*
* If you don't want to do this for some reason, you can
* set the location where the library will look for plugins
* by setting the environment variable SASL_PATH to the path
* the library should use.
********************************************************
