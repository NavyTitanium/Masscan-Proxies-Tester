#!/usr/bin/python
# -*- coding: utf-8 -*-

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
from progressbar import *

lock = threading.Lock()
finish= threading.Lock()
UA = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0'
sentinel = object()
loaded=processed=qsize_now=success=failure=skipped=0
SQL_ATTR_CONNECTION_TIMEOUT = 113
db_connection_timeout = 5
db_login_timeout = 5

# Looks for ODBC drivers that have 'MySQL' in the name
driver_names = [x for x in pyodbc.drivers() if 'MySQL' in x]
if driver_names:
    driver_name = driver_names[0]
    try:
        cnxn = pyodbc.connect(
            'DRIVER={' + driver_name + '};SERVER=127.0.0.1;PORT=3306;DATABASE=proxy;USER=root;PASSWORD=somepassword',
            timeout = db_login_timeout,
            attrs_before={SQL_ATTR_CONNECTION_TIMEOUT : db_connection_timeout})
        cnxn.setdecoding(pyodbc.SQL_WCHAR, encoding='utf-8')
        cnxn.setencoding('utf-8')
    except Exception as ex:
        exit("Please check the DB connection string: " + str(ex))
else:
    exit('No suitable driver found. Cannot connect.')

def ip2int(addr):
    return int(struct.unpack("!I", socket.inet_aton(addr))[0])

def int2ip(addr):
    return str(socket.inet_ntoa(struct.pack("!I", addr)))

# Insert the proxy and the reason into the DB
def update_db_result(proxy, reason):
    try:
        cursor = cnxn.cursor()
        ip, port = proxy.split(":")
        cursor.execute("INSERT INTO proxies (ipv4,port,reason) VALUES (%d, %d, '%s')" % (ip2int(ip),int(port),reason.replace("'", "").replace("\\","")))
        cnxn.commit()
        cursor.close()
    except Exception as ex:
        cursor.rollback()
        cursor.close()
        logging.exception(ex)

# Return True or False depending if the proxy is already present in the DB
def already_in_db(proxy):
    try:
        ip, port = proxy.split(":")
        cursor = cnxn.cursor()
        cursor.execute("SELECT count(ipv4) FROM proxies where ipv4 =%d and port =%d" % (ip2int(ip),int(port)))
        result=cursor.fetchone()
        cursor.close()
        if result[0] == 0:
            return False
        else:
            return True
    except Exception as ex:
        cursor.rollback()
        cursor.close()
        if lock.locked(): lock.release()
        finish.release()
        logging.exception(ex)
        exit(0)

# Read the result file returned from Masscan (output generated with -oL)
def parse_results(file, inq):
    lock.acquire()
    finish.acquire()
    global loaded,skipped
    logging.info("Reading " + file)

    with open(file) as f:
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
                    else:
                        skipped+=1
    if lock.locked(): lock.release()
    finish.release()
    inq.put(sentinel)
    logging.info("\n" + str(loaded) + " proxies loaded from file")
    return


# Read a file in reverse
def filerev(somefile, buffer=0x20000):
    somefile.seek(0, os.SEEK_END)
    size = somefile.tell()
    lines = ['']
    rem = size % buffer
    pos = max(0, (size // buffer - 1) * buffer)
    while pos >= 0:
        somefile.seek(pos, os.SEEK_SET)
        data = somefile.read(rem + buffer) + lines[0]
        rem = 0
        lines = re.findall('[^\n]*\n?', data)
        ix = len(lines) - 2
        while ix > 0:
            yield lines[ix]
            ix -= 1
        pos -= buffer
    else:
        yield lines[0]

# Read the result file returned from Masscan in reverse
def parse_results_reverse(file, inq,):
    lock.acquire()
    finish.acquire()
    global loaded,skipped
    logging.info("Reading in reverse " + file )
    with open(file) as f:
        for x in filerev(f):
            if "#" not in x:
                y = x.split()
                if len(y) == 5:
                    port = y[2]
                    ip = y[3]
                    if not already_in_db(ip + ":" + port):
                        inq.put(ip + ":" + port)
                        loaded += 1
                        if lock.locked(): lock.release()
                    else:
                        skipped+=1
    if lock.locked(): lock.release()
    finish.release()
    inq.put(sentinel)
    logging.info(str(loaded) + " proxies loaded from file")
    return

# Return the title and the MD5 sum of the content of the specified website
def fingerprint(website, TIMEOUT):
    try:
        req = urlrequest.Request(website)
        req.add_header('User-Agent', UA)
        content = urlrequest.urlopen(req, timeout=TIMEOUT).read()
        match = re.search('<title>(.*?)</title>', str(content))
        page_snippet = match.group(1)[:60].strip() if match else 'No title found'
        MD5_SUM= hashlib.md5(content).hexdigest()
        logging.info("Hash value of the content of " + website + " : " + MD5_SUM)
        return MD5_SUM,page_snippet
    except Exception as e:
        logging.error(e)
        logging.error("Cannot fetch the website used to compare integrity!")
        exit(0)

''' 
 Try to connect to the specified website with the specified proxy.
 Should be able to handle most errors and return the status of the connection.
'''
def test_proxy(proxy, website, TIMEOUT, ignore,MD5_SUM,page_snippet):
    try:
        # Prepare the request and fetch a website with the proxy
        socket.setdefaulttimeout(TIMEOUT)
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
    except Exception as e:
        return False, str(e)

    # If -i or --ignore is specified, we don't check the content of the page returned.
    if ignore is not None:
        return True, str(response.getcode())

    stream=['audio','mpeg','video','stream']
    if response.info()['content-type'] not in stream:
        try:
            content = response.read()
            response.close()
        except Exception as e:
            return False, str(e)
    else:
        return False,"Is a stream"

    m = hashlib.md5(content).hexdigest()

    if m != MD5_SUM:
        logging.debug("Content of the page doesn't match MD5 SUM")

        # Check if part of the page (the title) is in the returned content
        if page_snippet.encode('utf-8') in content:
            return True, str(response.getcode()) + " Content altered"

        # Check if the words 'login' or 'authorization' is in the content
        elif "login".encode() in content or "authorization".encode() in content:
            return False, str(response.getcode()) + " Login required"
        else:
            # The content returned is unknown. We try to get the title of the page.
            match = re.search('<title>(.*?)</title>', str(content))
            page_snippet = match.group(1)[:60].strip() if match else 'No title found'
            return False, str(response.getcode()) + " Content unknown. " + page_snippet
    else:
        logging.debug("Content of the page match MD5 SUM")
        return True, str(response.getcode()) + " Integrity check OK"

# Consume the queue and call test_proxy(). Results are passed to update_db_result().
def process_inq(inq, website, timeout, ignore,MD5_SUM,page_snippet):
    # Waiting for parse_results() to fill the queue
    time.sleep(1)
    while True:
        # parse_results() unlocked, meaning the there's stuff in the queue (or the file is empty)
        if not lock.locked():
            global qsize_now,processed,success,failure

            # For elements in the queue
            for x in iter(inq.get, sentinel):
                qsize_now = inq.qsize()
                Status, Result = test_proxy(x, website, timeout, ignore,MD5_SUM,page_snippet)
                update_db_result(x, Result)
                processed += 1
                logging.debug(x + " - "  + Result)
                if Status:
                    success+=1
                else:
                    failure+=1

            # Queue is empty, but data is being read by parse_results()
            if finish.locked():
                pass
            else:
                return
        else:
            # Let's wait a little more for parse_results()
            time.sleep(2)

# Print the status of the processing with global variables loaded,processed,qsize_now,success and failure
def status(sizeq,lines):
    status_queue = FormatCustomText(
        'Queue size: %(size)d/%(capacity)d',
        dict(size=qsize_now,capacity=sizeq,),)

    status_overall= FormatCustomText(
        '%(done)d/%(total)d (%(successful)d Successful %(fail)d Invalid)',
        dict(done=processed+skipped,total=lines,successful=success,fail=failure,),)

    widgets = ['Total processed: ', Percentage(), ' ', Bar(marker='#', left='[', right=']'), ' ', status_overall, ' - ', status_queue, ' | ',
             ETA(), ' | ', Timer() ]

    pbar = ProgressBar(widgets=widgets, maxval=lines,term_width=150)
    pbar.start()

    while True:
        status_queue.update_mapping(size=qsize_now)
        status_overall.update_mapping(done=processed+skipped,successful=success,fail=failure)
        pbar.update(processed+skipped)
        if processed == loaded and not finish.locked():
            pbar.finish()
            logging.warning("Done. " + str(success) + " valid proxies found and " + str(failure) + " were invalid. " + str(skipped) + " were skipped.")
            return
        time.sleep(0.5)

def get_number_lines(file):
    def blocks(files, size=65536):
        while True:
            b = files.read(size)
            if not b: break
            yield b

    with open(file, "r", encoding="utf-8", errors='ignore') as f:
        return (sum(bl.count("\n") for bl in blocks(f)))

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
    parser.add_option("-r", "--reverse", nargs=0, dest="reverse",
                      help="(Optional) Start reading the results file from the end. Useful when you want to restart the script from a large file that has been already partially processed. Default: In order")

    (options, args) = parser.parse_args()

    if options.verbosity is None:
        options.verbosity=20  # INFO
    else:
        options.verbosity=10  # DEBUG

    logging.basicConfig(format='%(asctime)s - %(message)s', level=options.verbosity)

    if not os.path.isfile(options.masscan_results):
        logging.error("Masscan results cannot be found!")
        parser.print_help()
        exit(0)

    if options.ignore is None:
        MD5_SUM,page_snippet = fingerprint(options.website, options.timeout)
    else:
        logging.info("Skipping integrity validation")

    inq = queue.Queue(maxsize=options.QUEUE_SIZE)

    if options.reverse is None:
        threading.Thread(target=parse_results, args=(options.masscan_results, inq)).start()
    else:
        logging.info("Parsing the file in reverse")
        threading.Thread(target=parse_results_reverse, args=(options.masscan_results, inq)).start()

    logging.warning("Starting " + str(options.THREADS) + " threads for processing")
    for i in range(options.THREADS):
        threading.Thread(target=process_inq, args=(inq, options.website, options.timeout, options.ignore,MD5_SUM,page_snippet)).start()

    status(options.QUEUE_SIZE,get_number_lines(options.masscan_results)+1)

if __name__ == '__main__':
    main()
