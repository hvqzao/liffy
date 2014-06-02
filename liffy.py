#!/usr/bin/python


import argparse
import sys
import requests
import urlparse
import time
import core
from blessings import Terminal


def main():
    # Terminal Colors
    t = Terminal()

    def banner():
        print(t.green("""

    # Authored: Benjamin Watson


    .____    .__  _____  _____
    |    |   |__|/ ____\/ ____\__.__.
    |    |   |  \   __\   __<   |  |
    |    |___|  ||  |   |  |  \___  |
    |_______ \__||__|   |__|  / ____|
        \/                \/

"""))

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

    banner()  # Run the banner!

    if not len(sys.argv):
        print((t.red(" [*] ") + "Not Enough Arguments!"))
        print((t.red(" [*] ") + "Example: ./liffy.py --url http://target/files.php?file= --data\n"))
        sys.exit(0)

    # Setup arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="target url")
    parser.add_argument("--data", help="data technique", action="store_true")
    parser.add_argument("--input", help="input technique", action="store_true")
    parser.add_argument("--expect", help="expect technique", action="store_true")
    parser.add_argument("--access", help="access logs technique", action="store_true")
    parser.add_argument("--filter", help="filter technique", action="store_true")
    parser.add_argument("--location", help="access logs location")
    #parser.add_argument("--cookies", help="session cookies")
    args = parser.parse_args()

    # Assign argument values
    url = args.url
    #cookies = args.cookies

    print(t.green(" [*] ") + "Checking Target: " + url)
    parsed = urlparse.urlsplit(url)
    domain = parsed.scheme + "://" + parsed.netloc
    progressbar()

    try:
        r = requests.get(domain)
        if r.status_code != 200:
            print(t.red(" [!] ") + "Did Not Receive Correct Response From Target URL!")
        else:
            print(t.red(" [!] ") + "Target URL Looks Good!")
            if args.data:
                print(t.red(" [!] ") + "Data Technique Selected!")
                d = core.Data(url)
                d.execute_data()
            elif args.input:
                print(t.red(" [!] ") + "Input Technique Selected!")
                i = core.Input(url)
                i.execute_input()
            elif args.expect:
                print(t.red(" [!] ") + "Expect Technique Selected!")
                e = core.Expect(url)
                e.execute_expect()
            elif args.access:
                if not args.location:
                    print(t.red(" [!] ") + "Log Location Not Provided!")
                else:
                    l = args.location
                    a = core.Logs(url, l)
                    a.execute_logs()
            elif args.filter:
                print(t.red(" [!] ") + "Filter Technique Selected!")
                f = core.Filter(url)
                f.execute_filter()
            else:
                print(t.red(" [!] ") + "Technique Not Selected!")
                sys.exit(0)

    except requests.exceptions.RequestException as e:
        print(t.red(" [*] HTTP Error ") + str(e))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(" [*] You hit Ctrl+C ")
        pass

