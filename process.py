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
lock = threading.Lock()

UA='User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0'
MD5_SUM=""
sentinel = object()

def parse_results(file):
	logging.info("Reading " + file)
	f = open(file, "r")
	z=[]
	for x in f:
		if "#" not in x:
			y=x.split( )
			if len(y) == 5:
				port=y[2]
				ip=y[3]
				timestamp=y[4]
				dict={"ip":ip,"port":port,"scanned_time":timestamp}
				z.append(dict)

	logging.info(str(len(z)) +" proxies loaded from file")
	return z

def fingerprint(website,TIMEOUT):
	try:
		req = urlrequest.Request(website)
		req.addheaders = [(UA)]
		response = urlrequest.urlopen(req, timeout=TIMEOUT)
		m = hashlib.md5()
		m.update(response.read())
		md5_hash=m.hexdigest()
		logging.info("Hash value of the content of " + website + " : " + md5_hash)
		return md5_hash
	except Exception as e:
		logging.error(e)
		logging.error("Cannot fetch the website used to compare integrity!")
		exit(0)

def test_proxies(proxy,website,TIMEOUT,ignore):
	try:
		req = urlrequest.Request(website)
		req.set_proxy(proxy, 'http')
		req.addheaders=[(UA)]
		response = urlrequest.urlopen(req,timeout=TIMEOUT)
	except ConnectionRefusedError:
		return False, "ConnectionRefusedError"
	except ConnectionResetError:
		return False, "Connection reset"
	except http.client.BadStatusLine:
		return False, "Bad status"
	except IOError as a:
		if hasattr(a,'code'):
			return False,a.code
		if hasattr(a,'reason'):
			return False,a.reason
		else:
			return False, a
	except urllib.error.URLError as z:
		if hasattr(z,'code'):
			return False,z.code
		if hasattr(z,'reason'):
			return False, z.reason
		else:
			return False,z
	else:
		if ignore:
			return True, str(response.getcode())

		m = hashlib.md5()
		content=response.read()
		m.update(content)
		if m.hexdigest() != MD5_SUM:
			if "login".encode() in content:
				return False, str(response.getcode()) +" Login required?"
			else:
				return False, str(response.getcode()) + " Content altered"
		else:
			return True, str(response.getcode()) + " Integrity check OK"

def save(line,file):
	lock.acquire()
	mode = 'a' if os.path.exists(file) else 'w'
	with open(file, mode) as f:
		f.write(line+'\n')
	lock.release()

def load_and_remove_dupp(inq,proxies,output_good,output_bad):
	z = []
	if os.path.exists(output_good):
		f1 = open(output_good, "r")
		for x1 in f1:
			z.append(x1.split("--")[0])
		f1.close()
		logging.info("Loading " + str(len(z)) + " good elements already tested")

	if os.path.exists(output_bad):
		oldsize= len(z)
		f2 = open(output_bad, "r")
		for x2 in f2:
			z.append(x2.split("--")[0])
		f2.close()
		logging.info("Loading " +  str(len(z)-oldsize) + " bad elements already tested")

	for elem in proxies:
		if (elem["ip"]+":"+elem["port"]) not in z:
			inq.put(elem["ip"]+":"+elem["port"])
	inq.put(sentinel)

def process_inq(inq,website,timeout,output_good,output_bad,ignore):
	for x in iter(inq.get, sentinel):
		Status, Result = test_proxies(x,website,timeout,ignore)
		result=str(Result)
		if(Status):
			logging.warning(x + " -- " + result)
			save(x +"--" + result,output_good)
		else:
			if "Login required" in result or "Content altered" in result:
				logging.warning(x + " -- " + result)
			else:
				logging.info(x + " -- " + result)
			save(x +"--" + result,output_bad)

	logging.warning("Processing queue empty!")

def read(proxies_uniq,inq):
	for x in proxies_uniq:
		inq.put(x["ip"]+":"+x["port"])
	inq.put(sentinel)

def main():
	output_good = os.path.join(os.path.dirname(os.path.abspath(__file__)),"good.txt")
	output_bad =  os.path.join(os.path.dirname(os.path.abspath(__file__)),"bad.txt")
	parser = OptionParser(usage="usage: %prog [options]")

	parser.add_option("-m", "--masscan",
					  default="/root/masscan/data/out.txt",action="store", type="string", dest="masscan_results",
					  help="Specify the file containing Masscan's results. Default: /root/masscan/data/out.txt")
	parser.add_option("-b", "--bad",
					  action="store", type="string", dest="output_bad",
					  help="(Optional) Specify the output file for the proxies that aren't working. Default: "+ output_bad)
	parser.add_option("-g", "--good",
					  action="store", type="string", dest="output_good",
					  help="(Optional) Specify the output file for the working proxies. Default: " +output_good)
	parser.add_option("-w", "--website",
					  default="http://perdu.com",action="store", type="string", dest="website",
					  help="(Optional) Specify the website used to test the proxies. Default: http://perdu.com")
	parser.add_option("-p", "--thread",
					  default=10,action="store", type="int", dest="THREADS",
					  help="(Optional) Specify the number of threads used to test the proxies. Default: 10")
	parser.add_option("-t", "--timeout",
					  default=6,action="store", type="int", dest="timeout",
					  help="(Optional) Specify the timeout period when testing a proxy. Default: 6")
	parser.add_option("-q", "--queue",
					  default=10000,action="store", type="int", dest="QUEUE_SIZE",
					  help="(Optional) Specify the size of the queue. Default: 10000")
	parser.add_option("-i", "--ignore",
					  default=False,action="store", dest="ignore",
					  help="(Optional) Ignore integrity validation of returned content")

	(options, args) = parser.parse_args()

	logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

	if not os.path.isfile(options.masscan_results):
		logging.error("Masscan results cannot be read!")
		parser.print_help()
		exit(0)
	else:
		proxies = parse_results(options.masscan_results)

	if options.website is None:
		options.website="http://perdu.com"

	if options.output_bad is not None:
		logging.info("Setting output file for not working proxy to: " + options.output_bad)
		output_bad=options.output_bad
	else:
		logging.info("Default output file for bad proxies selected: " + output_bad)

	if options.output_good is not None:
		logging.info("Setting output file for working proxy to: " + options.output_good)
		output_good=options.output_good
	else:
		logging.info("Default output file for good proxies selected: " + output_good)

	if not options.ignore:
		MD5_SUM=fingerprint(options.website,options.timeout)
	else:
		logging.info("Skipping integrity validation")

	inq = queue.Queue(maxsize=options.QUEUE_SIZE)
	threading.Thread(target=load_and_remove_dupp, args=(inq,proxies,output_good,output_bad)).start()

	logging.warning("Starting " + str(options.THREADS) + " threads for processing\n "
														 "**********************************************")
	for i in range(options.THREADS):
		threading.Thread(target=process_inq, args=(inq,options.website,options.timeout,output_good,output_bad,options.ignore)).start()

if __name__ == '__main__':
	main()