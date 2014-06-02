liffy
=====

Liffy is a tool to exploit local file inclusion vulnerability using the built-in wrappers php://input, data://, and a process control extension called 'expect'.

* Updates * Now comes with ability to use poisoned Apache access logs, and php://filter for code execution and arbitrary file reads


Install
=======

Liffy requires the following libraries: requests, argparse, blessings, urlparse

In order to host the payload you may use Node's HTTP server: https://github.com/nodeapps/http-server

Or you can simply spawn python's SimpleHTTPServer in /tmp on port 8000.  Further development of the tool will eventually include spawning a built-in web server in order to download, for now you can adjust the location and port in the source code for your needs.  These can be changed in core.py under the execute functions.


Example Usage 
==============

./liffy --url http://target/pdfs/vulnerable.php?= --data
