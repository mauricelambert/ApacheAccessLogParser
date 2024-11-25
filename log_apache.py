#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool parses access logs using python (with named group in regex). 
#    Copyright (C) 2024  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

from collections import Counter, defaultdict
from urllib.request import urlopen
from re import match

counters = defaultdict(Counter)

for line in urlopen("https://raw.githubusercontent.com/linuxacademy/content-elastic-log-samples/refs/heads/master/access.log"):
#for line in open("access.log", "rb"):
    parsing = match(rb"""(?xs)
        (?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))
        (\s+-){2}\s+
        \[(?P<datetime>\d{2}/\w+/\d{4}(:\d{2}){3}\s+\+\d{4})\]\s+"
        (?P<method>\w+)\s+
        (?P<url>[^\s]+)\s+
        HTTP/(?P<version>\d\.\d)"\s+
        (?P<status>\d+)\s+
        (?P<size>(\d+|-))\s+"
        (?P<referrer>[^"]+)"\s+"
        (?P<user_agent>[^"]+)"?\s*
    """, line)
    if not parsing:
        print(line)
        continue
    counters["ip"][parsing["ip"]] += 1
    counters["method"][parsing["method"]] += 1
    counters["url"][parsing["url"]] += 1
    counters["version"][parsing["version"]] += 1
    counters["status"][parsing["status"]] += 1
    counters["user_agent"][parsing["user_agent"]] += 1

    if parsing["method"].decode().casefold() == "POST".casefold() and parsing["url"].decode().casefold() == "/administrator/index.php".casefold():
        counters[b"POST-admin-index"]["count"] += 1

    if parsing["method"].decode().casefold() == "GET".casefold() and parsing["ip"] == b"5.255.72.168":
        counters[b"5.255.72.168-agent"][parsing["user_agent"]] += 1

    if any(parsing["url"].decode().casefold().endswith(x.casefold()) for x in (".png", ".jpg", ".gif", ".ico", ".jpeg")):
        counters[b"images"][parsing["url"]] += 1

print(counters["method"])
print(counters["version"])
print(sum([x for y, x in counters["user_agent"].items() if b"Android" in y]))
print(counters[b"POST-admin-index"]["count"])
print(counters[b"5.255.72.168-agent"])
print(sum([x for y, x in counters["user_agent"].items() if b"Googlebot" in y]))
print(counters[b"images"].most_common(3))

'''
Counter({b'GET': 9952, b'HEAD': 42, b'POST': 5, b'OPTIONS': 1})
Counter({b'1.1': 9300, b'1.0': 700})
187
0
Counter({b'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:21.0) Gecko/20100101 Firefox/21.0': 2})
543
[(b'/favicon.ico', 807), (b'/images/jordan-80.png', 533), (b'/images/web/2009/banner.png', 516)]
'''