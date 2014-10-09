SSE
================

For (most of) your super cPanel w/ Exim server needs.

Usage
--------------

**# wget https://raw.githubusercontent.com/cPanelTechs/SSE/master/sse.pl; chmod +x sse.pl**

**# ./sse.pl [OPTIONS]**

**Current Checks Impliemented:**

- Print current exim queue.
- Check for custom /etc/mailips, /etc/mailhelo, and /etc/reversedns.
- Check if port 26 is enabled.
- Check if mail IPs are blacklisted
- Show reverse DNS for mail IPs
- Check for SPF and DKIM records

**[With --domain option]**

- Check if domain exists on the server.
- Check if the user account is suspended.
- Check if domain is identical to hostname.
- Check if domain is in remote or local domains.
- Check if domain resolves locally to server.

**[With -s option]**

- View summary of email that has been sent from the server

**COMING SOON(ish):**

*Next push should aim to have:*

- *At LEAST* the e-mail option built in with, Iunno, one check?  Two maybe?
- IPTables chex.

*And then ...:*

- IMPLIMENT COLORS (Readability).
- Probably start trying to switch to IPC::Run instead of that gigantor and likely unneccesary run() sub I ganked from SSP.
