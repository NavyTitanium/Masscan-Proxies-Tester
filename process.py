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
import progressbar
import time
from tqdm import *

cnxn = pyodbc.connect('DRIVER={MySQL ODBC 8.0 Unicode Driver};SERVER=127.0.0.1;PORT=3306;DATABASE=proxy;USER=root;PASSWORD=somepassword')
cnxn.setdecoding(pyodbc.SQL_WCHAR, encoding='utf-8')
cnxn.setencoding('utf-8')

UA = 'User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0'
MD5_SUM = ""
page_body=""
sentinel = object()


def ip2int(addr):
    return str(struct.unpack("!I", socket.inet_aton(addr))[0])


def int2ip(addr):
    return str(socket.inet_ntoa(struct.pack("!I", addr)))


def update_db_result(proxy, reason):
    try:
        cursor = cnxn.cursor()
        ip, port = proxy.split(":")
        cursor.execute(
            "INSERT INTO proxies (ipv4,port,reason) VALUES ('" + ip2int(ip) + "','" + port + "','" + reason + "')")
        #print("INSERT INTO proxies (ipv4,port,reason) VALUES ('" + ip2int(ip) + "','" + port + "','" + reason + "')")
        cnxn.commit()
        # cursor.execute("UPDATE proxies SET reason='"+ reason +"' where ipv4 ='" + ip2int(ip) + "' and port = '" + port + "'")
    except Exception as ex:
        logging.exception(ex)

def already_in_db(proxy):
    try:
        ip, port = proxy.split(":")
        cursor = cnxn.cursor()
        #        print("SELECT ID FROM proxies where ipv4 ='" + ip2int(ip) + "' and port = '" + port + "'")
        cursor.execute("SELECT ID FROM proxies where ipv4 ='" + ip2int(ip) + "' and port = '" + port + "'")
        row_count = cursor.rowcount
        if row_count == 0:
            #			cursor.execute("INSERT INTO proxies (ipv4,port) VALUES ('"+ ip2int(ip) +"','"+ port +"')")
            #			cnxn.commit()
            return False
        else:
            return True
    except Exception as ex:
        logging.exception(ex)


def parse_results(file, inq,sizeq):
    #pbar = tqdm(total=sizeq, desc='Processing queue')
    #bar = progressbar.ProgressBar(max_value=sizeq, prefix='Queue size: ')
    #pbar2 = tqdm(total=sizeq)
    bar = progressbar.ProgressBar(max_value=sizeq, prefix='Elements in queue: ',total=50000000).start()
    logging.info("Reading " + file)
    f = open(file, "r")
    nb_proxies = 0;
    for x in f:
        if "#" not in x:
            y = x.split()
            if len(y) == 5:
                port = y[2]
                ip = y[3]
                if not already_in_db(ip + ":" + port):
                    inq.put(ip + ":" + port)
                    nb_proxies += 1
                    #pbar.update(nb_proxies)
                    bar.update(inq.qsize())


    inq.put(sentinel)
    logging.info(str(nb_proxies) + " proxies loaded from file")
    return

def fingerprint(website, TIMEOUT):
    try:
        req = urlrequest.Request(website)
        req.addheaders = [(UA)]
        response = urlrequest.urlopen(req, timeout=TIMEOUT)
        m = hashlib.md5()
        content = response.read()
        page_body=content
        m.update(content)
        md5_hash = m.hexdigest()
        logging.WARNING("Hash value of the content of " + website + " : " + md5_hash)
        return md5_hash
    except Exception as e:
        logging.error(e)
        logging.error("Cannot fetch the website used to compare integrity!")
        exit(0)


def test_proxies(proxy, website, TIMEOUT, ignore):
    time.sleep(0.02)
    return False, "test"
    try:
        req = urlrequest.Request(website)
        req.set_proxy(proxy, 'http')
        req.addheaders = [(UA)]
        response = urlrequest.urlopen(req, timeout=TIMEOUT)
    except ConnectionRefusedError:
        return False, "ConnectionRefusedError"
    except ConnectionResetError:
        return False, "Connection reset"
    except http.client.BadStatusLine:
        return False, "Bad status"
    except IOError as a:
        if hasattr(a, 'code'):
            return False, a.code
        if hasattr(a, 'reason'):
            return False, a.reason
        else:
            return False, a
    except urllib.error.URLError as z:
        if hasattr(z, 'code'):
            return False, z.code
        if hasattr(z, 'reason'):
            return False, z.reason
        else:
            return False, z
    else:
        if ignore is None:
            return True, str(response.getcode())

        m = hashlib.md5()
        content = response.read()
        m.update(content)
        if m.hexdigest() != MD5_SUM:
            if page_body in content:
                return True, str(response.getcode()) + " Content altered"
            elif "login".encode() in content or "authorization".encode() in content:
                return False, str(response.getcode()) + " Login required"
            else:
                return False, str(response.getcode()) + " Content unknown"
        else:
            return True, str(response.getcode()) + " Integrity check OK"


def process_inq(inq, website, timeout, ignore):
    for x in iter(inq.get, sentinel):
        Status, Result = test_proxies(x, website, timeout, ignore)
        result = str(Result)
        update_db_result(x, result)
        if (Status):
            logging.warning(x + " -- " + result)
        else:
            logging.info(x + " -- " + result)

    logging.warning("Processing queue empty!")


def main():
    parser = OptionParser(usage="usage: %prog [options]")

    parser.add_option("-m", "--masscan",
                      default="/root/masscan/data/out.txt", action="store", type="string", dest="masscan_results",
                      nargs=1,
                      help="Specify the file containing Masscan's results. Default: /root/masscan/data/out.txt")
    parser.add_option("-w", "--website",
                      default="http://perdu.com", action="store", type="string", dest="website", nargs=1,
                      help="(Optional) Specify the website used to test the proxies. Default: http://perdu.com")
    parser.add_option("-p", "--thread",
                      default=10, action="store", type="int", dest="THREADS", nargs=1,
                      help="(Optional) Specify the number of threads used to test the proxies. Default: 10")
    parser.add_option("-t", "--timeout",
                      default=6, action="store", type="int", dest="timeout", nargs=1,
                      help="(Optional) Specify the timeout period when testing a proxy. Default: 6")
    parser.add_option("-q", "--queue",
                      default=10000, action="store", type="int", dest="QUEUE_SIZE", nargs=1,
                      help="(Optional) Specify the size of the queue. Default: 10000")
    parser.add_option("-i", "--ignore",
                      dest="ignore", nargs=0,
                      help="(Optional) Ignore integrity validation of returned content")

    (options, args) = parser.parse_args()

    logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

    if not os.path.isfile(options.masscan_results):
        logging.error("Masscan results cannot be read!")
        parser.print_help()
        exit(0)

    if options.website is None:
        options.website = "http://perdu.com"

    if options.ignore is None:
        MD5_SUM = fingerprint(options.website, options.timeout)
    else:
        logging.info("Skipping integrity validation")

    inq = queue.Queue(maxsize=options.QUEUE_SIZE)
    threading.Thread(target=parse_results, args=(options.masscan_results, inq,options.QUEUE_SIZE)).start()

    logging.warning("Starting " + str(options.THREADS) + " threads for processing\n "
                                                         "**********************************************")
    for i in range(options.THREADS):
        threading.Thread(target=process_inq, args=(inq, options.website, options.timeout, options.ignore)).start()

  #  pbar = tqdm(total=options.QUEUE_SIZE, desc='Processing queue')
  #  while True:
   #     time.sleep(0.01)
    #    pbar.update(inq.qsize())
 #   with tqdm(total=options.QUEUE_SIZE) as pbar:
  #      while True:
   #         cur_perc = inq.qsize()
    #        pbar.update(inq.qsize()-pbar.n)  # here we update the bar of increase of cur_perc
     #       if cur_perc == options.QUEUE_SIZE:
      #          break
   # bar = progressbar.ProgressBar(max_value=options.QUEUE_SIZE)
    #while True:
     #   time.sleep(0.1)
      #  bar.update(inq.qsize())

if __name__ == '__main__':
    main()
