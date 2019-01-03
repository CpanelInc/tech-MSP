# MSP - Mail Status Probe
## MSP is currently a commandline function that provides basic information about the cPanel mail server.
##### This project was formmaly known under SSE; however, SSE is now confused with Server-Sevent Events. As the project has been rewritten from scratch, the name SSE has been repurposed, and to avoid breakage(sse.pl is still included but not maintained), the name MSP has been taken.
-------------
```
# /usr/local/cpanel/3rdparty/bin/perl <(curl -s "https://raw.githubusercontent.com/CpanelInc/tech-SSE/master/msp.pl") --help
[MSP-2.0] Mail Status Probe: Mail authentication statistics and configuration checker
Usage: ./msp.pl --auth --rotated --rude
       ./msp.pl --conf --rbl [all|bl.spamcop.net,zen.spamhaus.org]

	--help          print this help message
	--auth          print mail authentication statistics
	--conf          print mail configuration info (e.g. require_secure_auth, smtpmailgidonly, etc.)
	--limit         limit statistics checks to n results (defaults to 10, set to 0 for no limit)
	--logdir        specify an alternative logging directory, (defaults to /var/log)
	--rbl           check IP's against provided blacklists(comma delimited)
	--rbllist       list available RBL's
	--rotated       check rotated exim logs
	--rude          forgo nice/ionice settings
	--threshold     limit statistics output to n threshold(defaults to 1)
	--verbose       display all information
```
### --auth
The `--auth` argument is useful for checking for sources of spam. It aggregates authentication statistics from pasword authentication, local SMTP(authenticated_local_user), and via sendmail. As well, it provides a list of the most common subjects. By default, the check is performed with nice/ionice to ensure the server is not overloaded by the scan; however, this can be overridden with `--rude`.

The `--auth` argument can check rotated logs with `--rotated`, but has a hardcoded limit of 5 logs for now, as some users have tens or hundreds logs, and running the scan against too many could be intensive. If you have a seperate log directory or a custom one, you can use the `--logdir` argument to point MSP there.

The `--auth` argument also takes the `--limit` and `--threshold` arguments to limit output, which only prints the top *n* authentication hits or hits which have triggered over *n* times.

### --conf
The `--conf` argument checks Exim, Dovecot, and WHM > Tweak Settings for common configuration settings which should generally be disabled/enabled. By default, it only prints settings which are typically concerning; however, with the use of `--verbose` all checked settings will be displayed.

### --rbl and --rbllist
The `--rbllist` simply prints the available hardcoded RBL's which are triggered when passing `all`.

The `--rbl` flag requires comma delimited input. If a preferred RBL is not in the hardcoded list, you can simply pass the DNSRBL(s) here.

------------
## Begin legacy sse.pl README:
SSE
================

Exim email information utility for cPanel servers

Usage
--------------

**# perl <(curl -s https://raw.githubusercontent.com/CpanelInc/tech-SSE/master/sse.pl) [options]**


**Current Checks Impliemented:**

- Print current exim queue.
- Check for custom /etc/mailips, /etc/mailhelo, and /etc/reversedns.
- Check if port 26 is enabled.
- Check if mail IPs are blacklisted
- Show reverse DNS for mail IPs
- Check for SPF and DKIM records
- Check if nobody user is prevented from sending mail.
- Check server's PHP handler (PHP5 only at this time.)

**[With --domain or -d option]**

- Check if domain exists on the server.
- Check if the user account is suspended.
- Check if domain is identical to hostname.
- Check if domain is in remote or local domains.
- Check if domain resolves locally to server.
- Check if domain has any virtual filters.

**[With --email or -e option]**

- Check if e-mail exists on server.
- Check if e-mail has forwarders.
- Check if e-mail has an autoresponder enabled.
- Check if mailbox has filters.

**[With -s option]**

- View summary of email that has been sent from the server

**[With -b option]**

- Check Main IP and IPs in /etc/ips for blacklistings

