Parse the output file of a [Masscan](https://github.com/robertdavidgraham/masscan) scan and try to connect to a website with IPs:Port as the proxy. The script fills a queue with the proxies and use multiple threads to consume it. 
The format expected is produced by Masscan with the **-oL** parameter. However, it should be easy to adjust the script to support other formats.

To keep track of the proxies tested, the script try to detect the ODBC driver and connects to the local MySQL database with it. Don't forget to change your password in the connection string!

### Installation
RHEL / CentOS:
```
# yum install unixODBC
# yum install unixODBC-devel
```
Ubuntu :
```
# apt-get install python3-dev
# apt-get install unixodbc-dev
```
Then:
```
# pip3.7 install -r requirements.txt
```
### Usage
```
# python3.7 process.py --help
Usage: process.py [options]

Options:
  -h, --help            show this help message and exit
  -m MASSCAN_RESULTS, --masscan=MASSCAN_RESULTS
                        Specify the file containing Masscan's results.
                        Default: /root/masscan/data/out.txt
  -w WEBSITE, --website=WEBSITE
                        (Optional) Specify the website used to test the
                        proxies. Default: http://perdu.com
  -p THREADS, --thread=THREADS
                        (Optional) Specify the number of threads used to test
                        the proxies. Default: 10
  -t TIMEOUT, --timeout=TIMEOUT
                        (Optional) Specify the timeout period when testing a
                        proxy. Default: 6
  -q QUEUE_SIZE, --queue=QUEUE_SIZE
                        (Optional) Specify the size of the queue. Default:
                        10000
  -i IGNORE, --ignore=IGNORE
                        (Optional) Ignore integrity validation of returned
                        content
```

### Masscan usage example
```
# masscan 0.0.0.0/0 -p 3128,8080,5555,8000 --excludefile exclude.conf -oL out.txt
```

### Masscan-Proxies-Tester usage example
```
# python3.7 process.py -p 50
2019-01-11 00:06:19,250 - Reading /root/masscan/data/out.txt
2019-01-11 00:06:19,640 - 282782 proxies loaded from file
2019-01-11 00:06:19,640 - Default output file for bad proxies selected: /root/bad.txt
2019-01-11 00:06:19,641 - Default output file for good proxies selected: /root/good.txt
2019-01-11 00:06:19,641 - Starting 50 threads for processing
 **********************************************
2019-01-11 00:06:19,644 - Loading 143 good elements already tested
2019-01-11 00:06:19,646 - Loading 4517 bad elements already tested
2019-01-11 00:06:25,872 - <IP#1>:8000 -- timed out
2019-01-11 00:06:25,873 - <IP#2>:8000 -- timed out
2019-01-11 00:06:35,869 - <IP#3>:3128 -- 403
2019-01-11 00:06:35,904 - <IP#4>:8000 -- 404
2019-01-11 00:06:48,006 - <IP#5>:8000 -- Connection reset
2019-01-11 00:06:49,242 - <IP#6>:8080 -- 503
2019-01-11 00:06:51,699 - <IP#7>:8000 -- 200 Content altered
2019-01-11 00:06:53,234 - <IP#8>:8000 -- Bad status
...
```

### Integrity validation

Specifying **-i** or **--ignore** override this validation.

By default, the content of the page returned by a proxy (when the connection returned status code 200) will be verified for integrity by comparing the MD5 hash of the content. If the hash doesn't match, we look for:
 * The presence of the title of the website used to test the integrity
 * The words 'login' or 'authorization' to detect a potential login page
 
If this fail to recognized the page, we simply save the title of the page.