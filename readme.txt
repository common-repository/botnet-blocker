=== Botnet Blocker ===
Contributors: achbed, znaeff
Tags: comments, spam, blocking, DNSBL, spamhaus, spamcop, free
Requires at least: 4.0.0
Tested up to: 4.3.1
Stable tag: 1.2.5
License: GPLv2

Botnet identifier using public DNSBL bases and a hardcoded whitelist/blacklist.

== Description ==

This plugin provides a global object that will validate an incoming IP address against one or several DNSBLs, as well as internal white and black lists. Uses .xbl.spamhaus.org by default.  This is based on a slightly modified version of the public DNSBL class, and was inspired by the spam-ip-blocker plugin by znaeff.
[Official page of DNSBL class on PHPClasses.org](http://www.phpclasses.org/package/6994-PHP-Check-spam-IP-address-in-DNS-black-lists.html "DNSBL class on PHPClasses.org")

== Installation ==

1. Install folder `botnet-blocker` to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. In your template, theme, or plugin, do something similar to the following:

`<?php
  global $wp_plugin_bnblocker;
	if ( method_exists( $wp_plugin_bnblocker, 'is_botnet' ) ) {
		if ( $wp_plugin_bnblocker->is_botnet() ) {
      /* bot detected, do something */
    }
  }
?>`

== Frequently Asked Questions ==

= Why do I need one more anti-botnet plugin? =

Because I haven't found any decent free plugins that uses spam blocking lists that present a decent API.
This plugin is designed to give you a quick and easy way to check the spam lists and do something creative
without locking you into a "block all" scheme.  It's there if you want it, but it's not required.

== Upgrade Notice ==

= 1.2.3 =
No longer throws extra warnings; fixes error when using Block on Page Load

= 1.2.2 =
Added commenting in lists, now respects the Block on Page Load setting

= 1.2.1 =
Fixed preg_match errors in DNS matching

= 1.2.0 =
Allows ignoring all RBLs

= 1.1.0 =
Adds DNS-based lists and an early-load blocking option

== Screenshots ==

1. The admin interface.

== Changelog ==

= 1.2.3 =
* Plugin_BNBlocker::netmatch no longer throws warnings when error level is high
* Reworked Plugin_BNBlocker::netmatch to reduce computation a bit
* Fixes error when using Block on Page Load

= 1.2.2 =
* Block on Page Load setting now retrieved properly
* All lists support commenting via # (hash)

= 1.2.1 =
* Fixed preg_match errors in DNS matching

= 1.2.0 =
* Added "none" option for the RBLs (so you can use white/black lists but ignore the RBLs)
* Added checks to improve performance where possible
* Fixed the readme, added screenshot

= 1.1.0 =
* Added DNS-based white and blacklists as an option
* Added option to block bots during the plugins_loaded timeframe
* Corrected the main blocked() function to use 404 instead of 406
* Reversed order of changelog in the readme

= 1.0.1 =
* Refactored to allow for support for language packs

= 1.0.0 =
* Complete refactor of the Plugin
* Now has an admin section for modifying white/black/skip lists within the UI
* Allows choosing which RBL in the UI
* Revised logic to improve speed
* Now uses CIDR-formatted netmasks for better maintenance
* Removed hard-coded proxy network lists - use the whitelist instead
* BREAKING CHANGE: Global object has been renamed from $BOTNETBLOCKER_OBJ to $wp_plugin_bnblocker

= 0.2.0 =
* Added extensive URL-based debugging and reply headers when in debug mode
* Added a hard coded white/black/skip list system
* Added timing checks for debugging speed issues
* Added Sucuri network addresses to skip list

= 0.1.1 =
* Fixed issue where DNSBL class used a short opening tag (broke some installations)

= 0.1.0 =
* First version.

