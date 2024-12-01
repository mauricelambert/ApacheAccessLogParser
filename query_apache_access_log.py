#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script parses and implements a syntax to query and filter apache access logs,
#    easiest and faster way to find your logs in incident response.
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

from ipaddress import ip_address, IPv4Address
from sys import argv, stderr, exit
from datetime import datetime
from fnmatch import fnmatch
from os.path import isfile
from re import match

class ConditionalParser:
    def __init__(self):
        self.pos = 0
        self.tokens = []

    def tokenize(self, input_string):
        operators = ['&', '|', '~', '=', '>', '>=', '<', '<=', '(', ')']
        self.tokens = []
        current_token = ''
        next_parsed = False
        for i, char in enumerate(input_string):
            if next_parsed:
                next_parsed = False
                continue
            if char.isspace():
                if current_token:
                    self.tokens.append(current_token)
                    current_token = ''
            elif char in operators:
                if char in ('>' or '<') and input_string[i + 1] == "=":
                    next_parsed = True
                    char += "="
                if current_token:
                    self.tokens.append(current_token)
                    current_token = ''
                self.tokens.append(char)
            else:
                if char == "\\" and (input_string[i + 1].isspace() ):
                    char = input_string[i + 1]
                    next_parsed = True
                current_token += char
        if current_token:
            self.tokens.append(current_token)
        return self.tokens

    def parse(self, input_string):
        self.tokenize(input_string)
        self.pos = 0
        return self.parse_expression()

    def parse_expression(self):
        left = self.parse_term()
        while self.pos < len(self.tokens) and self.tokens[self.pos] in ['and', 'or', '&', '|']:
            op = self.tokens[self.pos]
            self.pos += 1
            right = self.parse_term()
            left = {'op': 'and' if op in ['and', '&'] else 'or', 'left': left, 'right': right}
        return left

    def parse_term(self):
        if self.tokens[self.pos] == '(':
            self.pos += 1
            expr = self.parse_expression()
            if self.pos < len(self.tokens) and self.tokens[self.pos] == ')':
                self.pos += 1
                return expr
            else:
                raise ValueError("Missing closing parenthesis")
        else:
            return self.parse_condition()

    def parse_condition(self):
        if self.pos + 2 < len(self.tokens):
            field = self.tokens[self.pos]
            op = self.tokens[self.pos + 1]
            value = self.tokens[self.pos + 2]
            if op in ['~', '=', '>', '>=', '<', '<=']:
                self.pos += 3
                return {'field': field, 'op': op, 'value': value}
        raise ValueError("Invalid condition at position " + str(self.pos))

def compare(ask, op, value):
    if op != '~':
        if isinstance(value, int):
            ask = int(ask)
        elif isinstance(value, float):
            ask = float(ask)
        elif isinstance(value, datetime):
            ask = datetime.fromisoformat(ask)
        elif isinstance(value, IPv4Address):
            ask = ip_address(ask)
        elif isinstance(value, str):
            ask = ask.casefold()
            value = value.casefold()

    if op == '~':
        return fnmatch(str(value), ask)
    elif op == '=':
        return ask == value
    elif op == '>':
        return value > ask
    elif op == '>=':
        return value >= ask
    elif op == '<':
        return value < ask
    elif op == '<=':
        return value <= ask

def evaluate(parsed_expr, data):
    if 'left' in parsed_expr and 'right' in parsed_expr:
        if parsed_expr['op'] == 'and':
            return evaluate(parsed_expr['left'], data) and evaluate(parsed_expr['right'], data)
        elif parsed_expr['op'] == 'or':
            return evaluate(parsed_expr['left'], data) or evaluate(parsed_expr['right'], data)
    else:
        field = parsed_expr['field'].lower()
        op = parsed_expr['op']
        value = parsed_expr['value']
        
        if field not in data:
            raise ValueError("Invalid field name " + repr(field))

        return compare(value, op, data[field])
    
    return False

if len(argv) < 3:
    print("USAGES: python3 query_apache_access_log.py <log_path> <requests>...", file=stderr)
    print("\tRequest example: method = POST", file=stderr)
    print("\tRequest example: status ~ 50?", file=stderr)
    print("\tRequest example: size >= 60000000", file=stderr)
    print("\tRequest example: user_agent ~ *Version/6.0\\ Mobile* and ip = 66.249.73.135", file=stderr)
    print("\tRequest example: (METHOD = post or url ~ *admin*) & (ip > 91.0.0.0 | referrer ~ *://*)", file=stderr)
    print("\tField names: ip, datetime, method, url, version, status, size, referrer, user_agent", file=stderr)
    print("\tOperators: = (equal case insensitive), ~ (match glob syntax), >, <, >=, <=", file=stderr)
    print("\tInter expression: and (& works too), or (| works too)", file=stderr)
    print("\tParenthesis can be use to prioritize expression, default priority: left to right", file=stderr)
    print("\tEscape character: \\, it's working only with space and operators.", file=stderr)
    exit(1)

file = argv[1]

if not isfile(file):
    print("Invalid filename:", repr(file))
    exit(2)

for query in argv[2:]:
    parser = ConditionalParser()
    parsed_expr = parser.parse(query)

    for line in open(file):
        parsing = match(r"""(?xs)
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

        values = parsing.groupdict()
        values['ip'] = ip_address(values['ip'])
        values['datetime'] = datetime.strptime(values['datetime'], "%d/%b/%Y:%H:%M:%S %z")
        values['version'] = float(values['version'])
        values['status'] = int(values['status'])
        values['size'] = int(values['size']) if values['size'] != '-' else 0

        if evaluate(parsed_expr, values):
            print(line.strip())

exit(0)
