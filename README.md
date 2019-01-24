# MSP - Mail Status Probe
## MSP is currently a commandline function that provides basic information about the cPanel mail server.
###### This project was formmaly known under SSE; however, SSE is now confused with Server-Sent Events. As the project has been rewritten from scratch, the name SSE has been repurposed, and to avoid breakage(sse.pl is still included but not maintained), the name MSP has been taken.
-------------
## Usage
To run the script, execute the following:

```/usr/local/cpanel/3rdparty/bin/perl <(curl -s "https://raw.githubusercontent.com/CpanelInc/tech-SSE/master/msp.pl")```

## Parameters

### --help
![--help](https://user-images.githubusercontent.com/25645218/50696777-09b1b480-1006-11e9-9469-21c1cbb0b2f0.png)

### --auth
![--auth](https://user-images.githubusercontent.com/25645218/50691072-33161480-0ff5-11e9-884d-325d5f124e92.png)
The `--auth` argument is useful for checking for sources of spam. It aggregates authentication statistics from pasword authentication, local SMTP(authenticated_local_user), and via sendmail. As well, it provides a list of the most common subjects. By default, the check is performed with nice/ionice to ensure the server is not overloaded by the scan; however, this can be overridden with `--rude`.

The `--auth` argument can check rotated logs with `--rotated`, but has a hardcoded limit of 5 logs for now, as some users have tens or hundreds logs, and running the scan against too many could be intensive. If you have a seperate log directory or a custom one, you can use the `--logdir` argument to point MSP there.

The `--auth` argument also takes the `--limit` and `--threshold` arguments to limit output, which only prints the top *n* authentication hits or hits which have triggered over *n* times, respectively.

### --conf
![--conf](https://user-images.githubusercontent.com/25645218/50690982-ff3aef00-0ff4-11e9-9f87-8647fac8608c.png)
The `--conf` argument checks Exim, Dovecot, and WHM > Tweak Settings for common configuration settings which should generally be disabled/enabled. By default, it only prints settings which are typically concerning; however, with the use of `--verbose` all checked settings will be displayed.

### --rbl and --rbllist
![--rbl all](https://user-images.githubusercontent.com/25645218/50691357-0f9f9980-0ff6-11e9-922b-9748095a4d62.png)
The `--rbllist` simply prints the available hardcoded RBL's which are triggered when passing `all`.

The `--rbl` flag requires comma delimited input. If a preferred RBL is not in the hardcoded list, you can simply pass the DNSRBL(s) here. It currently checks all IP's bound to the server(if NAT is in use, just the public IP's).

------------
## Begin legacy(unmaintained) sse.pl README:
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

