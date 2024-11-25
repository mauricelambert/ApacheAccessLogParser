# ApacheAccessLogParser

## Context

> This tool has been written in lab:

### Questions

1. List the super-set of all HTTP request methods present in the logs. `Counter({b'GET': 9952, b'HEAD': 42, b'POST': 5, b'OPTIONS': 1})`
2. How many requests were made using protocol defined in RFC 1945 ? `Counter({b'1.1': 9300, b'1.0': 700})`
3. How many requests were originated from Android devices ? `187`
4. How many POST requests were made for "/administrator/index.php" page ? `0`
5. Which browser was used to make GET requests to the server using IP address 5.255.72.168 ? `Counter({b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:21.0) Gecko/20100101 Firefox/21.0': 2})`
6. How many request were made by Google's crawling bots ? `543`
7. Which image was fetched from the server second most time ? `[(b'/favicon.ico', 807), (b'/images/jordan-80.png', 533), (b'/images/web/2009/banner.png', 516)]`
