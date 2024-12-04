#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This script extracts, filters and parses combined log format (apache
#    and nginx default access.log format) with a easy and fast language
#    syntax
#    Copyright (C) 2024  QueryCombinedLogFormat

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

"""
This script extracts, filters and parses combined log format (apache
and nginx default access.log format) with a easy and fast language
syntax
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This script extracts, filters and parses combined log format (apache
and nginx default access.log format) with a easy and fast language
syntax
"""
__url__ = "https://github.com/mauricelambert/QueryCombinedLogFormat"

# __all__ = []

__license__ = "GPL-3.0 License"
__copyright__ = """
QueryCombinedLogFormat  Copyright (C) 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

print(copyright)

from ipaddress import ip_address, IPv4Address
from csv import writer, DictReader, QUOTE_ALL
from collections import Counter, defaultdict
from typing import List, Dict, Callable
from json import dumps, JSONEncoder
from sys import argv, stderr, exit
from re import compile as regex
from _io import TextIOWrapper
from datetime import datetime
from fnmatch import fnmatch
from gzip import GzipFile
from glob import iglob

regex_parser = regex(
    r"""(?xs)
    (?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s+
    "?(?P<client_identity>(\\"|[^"])*?)"?\s+
    "?(?P<user_id>(\\"|[^"])*?)"?\s+
    \[(?P<datetime>\d{2}/\w+/\d{4}(:\d{2}){3}\s+[+-]\d{4})\]\s+"
    (?P<method>[^\s]+)\s+
    (?P<url>(\\"|[^"])+)\s+
    HTTP/(?P<version>\d\.\d)"\s+
    (?P<status>\d+)\s+
    (?P<size>(\d+|-))\s+"
    (?P<referrer>(\\"|[^"])*?)"\s+"
    (?P<user_agent>(\\"|[^"])*?)"\s*
"""
)


class ConditionalParser:
    def __init__(self):
        self.pos = 0
        self.tokens = []

    def tokenize(self, input_string):
        operators = ["&", "|", "~", "=", ">", ">=", "<", "<=", "(", ")", "!"]
        self.tokens = []
        current_token = ""
        next_parsed = False
        for i, char in enumerate(input_string):
            if next_parsed:
                next_parsed = False
                continue
            if char.isspace():
                if current_token:
                    self.tokens.append(current_token)
                    current_token = ""
            elif char in operators:
                if char in (">" or "<") and input_string[i + 1] == "=":
                    next_parsed = True
                    char += "="
                if current_token:
                    self.tokens.append(current_token)
                    current_token = ""
                self.tokens.append(char)
            else:
                if char == "\\" and (input_string[i + 1].isspace()):
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
        while self.pos < len(self.tokens) and self.tokens[self.pos] in [
            "and",
            "or",
            "&",
            "|",
        ]:
            op = self.tokens[self.pos]
            self.pos += 1
            right = self.parse_term()
            left = {
                "op": "and" if op in ["and", "&"] else "or",
                "left": left,
                "right": right,
            }
        return left

    def parse_term(self):
        if self.tokens[self.pos] == "(":
            self.pos += 1
            expr = self.parse_expression()
            if self.pos < len(self.tokens) and self.tokens[self.pos] == ")":
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
            if op in ["~", "=", ">", ">=", "<", "<=", "!"]:
                self.pos += 3
                return {"field": field, "op": op, "value": value}
        raise ValueError("Invalid condition at position " + str(self.pos))


class Dumper(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, IPv4Address):
            return str(obj)
        return super().default(obj)


def compare(ask, op, value):
    if op != "~":
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

    if op == "~":
        return fnmatch(str(value), ask)
    elif op == "=":
        return ask == value
    elif op == ">":
        return value > ask
    elif op == ">=":
        return value >= ask
    elif op == "<":
        return value < ask
    elif op == "<=":
        return value <= ask
    elif op == "!":
        return value != ask


def evaluate(parsed_expr, data):
    if "left" in parsed_expr and "right" in parsed_expr:
        if parsed_expr["op"] == "and":
            return evaluate(parsed_expr["left"], data) and evaluate(
                parsed_expr["right"], data
            )
        elif parsed_expr["op"] == "or":
            return evaluate(parsed_expr["left"], data) or evaluate(
                parsed_expr["right"], data
            )
    else:
        field = parsed_expr["field"].lower()
        op = parsed_expr["op"]
        value = parsed_expr["value"]

        if field not in data:
            raise ValueError("Invalid field name " + repr(field))

        return compare(value, op, data[field])

    return False


def get_file(filename):
    file = base_file = open(filename, "rb")
    magic = file.read(2)
    file.seek(0)
    if magic == b"\x1f\x8b":
        return GzipFile(fileobj=file), base_file, False
    elif magic == b'"i':
        file.close()
        file = base_file = open(filename, "r")
        return DictReader(file, quoting=QUOTE_ALL), base_file, True
    return file, base_file, False


def print_help():
    print(
        "USAGES: QueryCombinedLogFormat [-s|--statistics] [-d|--to-db] <log_path> <queries>...",
        file=stderr,
    )
    print("\tRequest example: method = POST", file=stderr)
    print("\tRequest example: status ~ 50?", file=stderr)
    print("\tRequest example: size >= 60000000", file=stderr)
    print(
        "\tRequest example: user_agent ~ *Version/6.0\\ Mobile* and ip = 66.249.73.135",
        file=stderr,
    )
    print(
        "\tRequest example: (METHOD = post or url ~ *admin*) & (ip > 91.0.0.0 | referrer ~ *://*)",
        file=stderr,
    )
    print(
        "\tField names: ip, client_identity, user_id, datetime, method, url, version, status, size, referrer, user_agent",
        file=stderr,
    )
    print(
        "\tOperators: = (equal case insensitive), ~ (match glob syntax), ! (not equal), >, <, >=, <=",
        file=stderr,
    )
    print(
        "\tInter expression: and (& works too), or (| works too)", file=stderr
    )
    print(
        "\tParenthesis can be use to prioritize expression, default priority: left to right",
        file=stderr,
    )
    print(
        "\tEscape character: \\, it's working only with space and operators.",
        file=stderr,
    )
    print("\tlog_path can be a glob syntax: ", file=stderr)


def get_line(globsyntax: str):
    for filename in iglob(globsyntax, recursive=True):
        file, base_file, text = get_file(filename)
        for line in file:
            yield line if text else line.decode("latin-1")
        base_file.close()


def parse_line(line: str):
    if isinstance(line, str):
        values = regex_parser.fullmatch(line).groupdict()
        values["datetime"] = datetime.strptime(
            values["datetime"], "%d/%b/%Y:%H:%M:%S %z"
        )
    else:
        values = line
        values["datetime"] = datetime.fromisoformat(values["datetime"])
    values["ip"] = ip_address(values["ip"])
    values["version"] = float(values["version"])
    values["status"] = int(values["status"])
    values["size"] = int(values["size"]) if values["size"] != "-" else 0
    return values


def parse_command_line():
    statistics = False
    if "-s" in argv:
        argv.remove("-s")
        statistics = True
    elif "--statistics" in argv:
        argv.remove("--statistics")
        statistics = True

    to_db = False
    if "-d" in argv:
        argv.remove("-d")
        to_db = True
    elif "--to-db" in argv:
        argv.remove("--to-db")
        to_db = True

    if len(argv) < 3 or (len(argv) < 2 and (statistics or to_db)):
        print_help()
        return None, None, None, None

    return statistics, to_db, argv[1], argv[2:]


def build_query_parsers(queries: List[str]):
    query_parser = {}
    for index, query in enumerate(queries):
        index += 1
        parser = ConditionalParser()
        query_parser[index] = parser.parse(query)
    return query_parser


def prepare(queries: List[str], to_db: bool):
    query_parser = build_query_parsers(queries)
    statistics_counters = defaultdict(Counter)

    if not query_parser:
        query_parser["*"] = "*"
        evaluate = lambda *x: True
    else:
        evaluate = globals()["evaluate"]

    file = csvfile = None
    if to_db:
        file = open(
            "access_log_db_"
            + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".csv",
            "w",
            newline="",
        )
        csvfile = writer(file, quoting=QUOTE_ALL)
        csvfile.writerow(
            [
                "ip",
                "client_identity",
                "user_id",
                "datetime",
                "method",
                "url",
                "version",
                "status",
                "size",
                "referrer",
                "user_agent",
            ]
        )

    return (
        evaluate,
        parse_line,
        statistics_counters,
        query_parser,
        file,
        csvfile,
    )


def terminate(
    statistics_counters: Dict[str, Dict[str, int]], dbfile: TextIOWrapper
):
    if dbfile:
        dbfile.close()

    if statistics_counters:
        print("LABEL".rjust(16), "|", "COUNT".rjust(9), "|", "VALUE")
    for label, counter in statistics_counters.items():
        for value, count in counter.most_common():
            print(label.rjust(16), "|", str(count).rjust(9), "|", value)


def mainloop(
    globsyntax: str,
    query_parser: Dict[int, str],
    statistics_counters: Dict[str, Dict[str, int]],
    evaluate: Callable,
    parse_line: Callable,
    to_db: bool,
    statistics: bool,
    csvfile: TextIOWrapper,
):
    for line in get_line(globsyntax):
        values = parse_line(line)
        for index, parsed_expr in query_parser.items():
            if evaluate(parsed_expr, values):
                if statistics:
                    for key, value in values.items():
                        statistics_counters[key][value] += 1
                else:
                    print(
                        line.strip()
                        if isinstance(line, str)
                        else dumps(line, cls=Dumper)
                    )
                if to_db:
                    csvfile.writerow(list(values.values()))


def main():
    statistics, to_db, globsyntax, queries = parse_command_line()
    if not globsyntax or (not queries and not (statistics or to_db)):
        return 1

    (
        evaluate,
        parse_line,
        statistics_counters,
        query_parser,
        dbfile,
        csvfile,
    ) = prepare(queries, to_db)
    mainloop(
        globsyntax,
        query_parser,
        statistics_counters,
        evaluate,
        parse_line,
        to_db,
        statistics,
        csvfile,
    )
    terminate(statistics_counters, dbfile)

    return 0


if __name__ == "__main__":
    exit(main())
