#!/usr/bin/python
import urllib.request
from urllib import request as urlrequest
from urllib.error import URLError
import urllib.error
import http
import os
import threading
import hashlib
import queue
import logging
from optparse import OptionParser
import pyodbc
import socket
import struct
import time
import re
lock = threading.Lock()
UA = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0'
sentinel = object()
loaded=processed=qsize_now=success=failure=0

driver_names = [x for x in pyodbc.drivers() if 'MySQL' in x]
if driver_names:
    driver_name = driver_names[0]
    try:
        cnxn = pyodbc.connect(
            'DRIVER={' + driver_name + '};SERVER=127.0.0.1;PORT=3306;DATABASE=proxy;USER=root;PASSWORD=somepassword')
        cnxn.setdecoding(pyodbc.SQL_WCHAR, encoding='utf-8')
        cnxn.setencoding('utf-8')
    except Exception as ex:
        exit("Please check the DB connection string: " + str(ex))
else:
    exit('No suitable driver found. Cannot connect.')

def ip2int(addr):
    return str(struct.unpack("!I", socket.inet_aton(addr))[0])

def int2ip(addr):
    return str(socket.inet_ntoa(struct.pack("!I", addr)))

def update_db_result(proxy, reason):
    try:
        cursor = cnxn.cursor()
        ip, port = proxy.split(":")
        cursor.execute("INSERT INTO proxies (ipv4,port,reason) VALUES ('" + ip2int(ip) + "','" + port + "','" + reason + "')")
        cnxn.commit()
    except Exception as ex:
        logging.exception(ex)

def already_in_db(proxy):
    try:
        ip, port = proxy.split(":")
        cursor = cnxn.cursor()
        cursor.execute("SELECT ID FROM proxies where ipv4 ='" + ip2int(ip) + "' and port = '" + port + "'")
        row_count = cursor.rowcount
        if row_count == 0:
            return False
        else:
            return True
    except Exception as ex:
        logging.exception(ex)

def parse_results(file, inq,sizeq):
    lock.acquire()
    global loaded
    logging.info("Reading " + file)
    f = open(file, "r")
    for x in f:
        if "#" not in x:
            y = x.split()
            if len(y) == 5:
                port = y[2]
                ip = y[3]
                if not already_in_db(ip + ":" + port):
                    inq.put(ip + ":" + port)
                    loaded+=1
                    if lock.locked(): lock.release()
    if lock.locked(): lock.release()
    inq.put(sentinel)
    logging.debug(str(loaded) + " proxies loaded from file")
    return

def fingerprint(website, TIMEOUT):
    try:
        req = urlrequest.Request(website)
        req.add_header('User-Agent', UA)
        content = urlrequest.urlopen(req, timeout=TIMEOUT).read()
        match = re.search('<title>(.*?)</title>', str(content))
        page_snippet = match.group(1)[:60] if match else 'No title found'
        MD5_SUM= hashlib.md5(content).hexdigest()
        logging.info("Hash value of the content of " + website + " : " + MD5_SUM)
        return MD5_SUM,page_snippet
    except Exception as e:
        logging.error(e)
        logging.error("Cannot fetch the website used to compare integrity!")
        exit(0)

def test_proxy(proxy, website, TIMEOUT, ignore,MD5_SUM,page_snippet):
   try:
        req = urlrequest.Request(website)
        req.add_header('User-Agent', UA)
        req.set_proxy(proxy, 'http')
        response = urlrequest.urlopen(req, timeout=TIMEOUT)
   except ConnectionRefusedError:
       return False, "ConnectionRefusedError"
   except ConnectionResetError:
       return False, "Connection reset"
   except http.client.BadStatusLine:
       return False, "Bad status"
   except IOError as a:
       if hasattr(a, 'code'):
           return False, str(a.code)
       if hasattr(a, 'reason'):
           return False, str(a.reason)
       else:
           return False, str(a)
   except socket.error as socketerror:
       return False, str(socketerror)
   except urllib.error.URLError as z:
       if hasattr(z, 'code'):
           return False, str(z.code)
       if hasattr(z, 'reason'):
           return False, str(z.reason)
       else:
           return False, str(z)
   else:
       if ignore is not None:
           return True, str(response.getcode())

       content = response.read()
       m= hashlib.md5(content).hexdigest()

       if m != MD5_SUM:
           logging.debug("Content of the page doesn't match MD5 SUM")

           if page_snippet.encode('utf-8') in content:
               return True, str(response.getcode()) + " Content altered"
           elif "login".encode() in content or "authorization".encode() in content:
               return False, str(response.getcode()) + " Login required"
           else:
               match = re.search('<title>(.*?)</title>', str(content))
               page_snippet = match.group(1)[:60] if match else 'No title found'
               return False, str(response.getcode()) + " Content unknown. "+ page_snippet
       else:
           logging.debug("Content of the page match MD5 SUM")
           return True, str(response.getcode()) + " Integrity check OK"


def process_inq(inq, website, timeout, ignore,MD5_SUM,page_snippet):
    while True:
        if not lock.locked():
            global qsize_now,processed,success,failure
            for x in iter(inq.get, sentinel):
                qsize_now = inq.qsize()
                Status, Result = test_proxy(x, website, timeout, ignore,MD5_SUM,page_snippet)
                update_db_result(x, Result.decode("utf8"))
                processed += 1
                logging.debug(Result)
                if Status:
                    success+=1
                else:
                    failure+=1
            return
        else:
            time.sleep(2)

def graph(sizeq):
    while True:
        logging.info(str(loaded) + " items loaded and " + str(processed) + " items processed. Queue size: " + str(qsize_now) + "/" + str(sizeq))
        if processed==loaded and not lock.locked():
            logging.warning("Done. " + str(success)+ " valid proxies found and " + str(failure) + " invalid.")
            return
        time.sleep(20)

def main():
    parser = OptionParser(usage="usage: %prog [options]")

    parser.add_option("-m", "--masscan",
                      default="/root/masscan/data/out.txt", action="store", type="string", dest="masscan_results",
                      nargs=1,
                      help="Specify the file containing Masscan's results. Default: /root/masscan/data/out.txt")
    parser.add_option("-w", "--website",
                      default="http://www.perdu.com", action="store", type="string", dest="website", nargs=1,
                      help="(Optional) Specify the website used to test the proxies. Default: http://perdu.com")
    parser.add_option("-p", "--thread",
                      default=15, action="store", type="int", dest="THREADS", nargs=1,
                      help="(Optional) Specify the number of threads used to test the proxies. Default: 10")
    parser.add_option("-t", "--timeout",
                      default=6, action="store", type="int", dest="timeout", nargs=1,
                      help="(Optional) Specify the timeout period when testing a proxy. Default: 6")
    parser.add_option("-q", "--queue",
                      default=1000, action="store", type="int", dest="QUEUE_SIZE", nargs=1,
                      help="(Optional) Specify the size of the queue. Default: 10000")
    parser.add_option("-i", "--ignore",
                      dest="ignore", nargs=0,
                      help="(Optional) Ignore integrity validation of returned content")
    parser.add_option("-v", "--verbose", nargs=0, dest="verbosity",
                      help="(Optional) Set the level of logging to DEBUG. Default: INFO")

    (options, args) = parser.parse_args()

    if options.verbosity is None:
        # INFO
        options.verbosity=20
    else:
        # DEBUG
        options.verbosity=10

    logging.basicConfig(format='%(asctime)s - %(message)s', level=options.verbosity)

    if not os.path.isfile(options.masscan_results):
        logging.error("Masscan results cannot be read!")
        parser.print_help()
        exit(0)

    if options.ignore is None:
        MD5_SUM,page_snippet = fingerprint(options.website, options.timeout)
    else:
        logging.info("Skipping integrity validation")

    inq = queue.Queue(maxsize=options.QUEUE_SIZE)
    threading.Thread(target=parse_results, args=(options.masscan_results, inq,options.QUEUE_SIZE)).start()
    threading.Thread(target=graph, args=(options.QUEUE_SIZE,)).start()

    logging.warning("Starting " + str(options.THREADS) + " threads for processing")
    for i in range(options.THREADS):
        threading.Thread(target=process_inq, args=(inq, options.website, options.timeout, options.ignore,MD5_SUM,page_snippet)).start()

if __name__ == '__main__':
    main()
