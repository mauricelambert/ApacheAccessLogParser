![QueryCombinedLogFormat Logo](https://mauricelambert.github.io/info/python/security/QueryCombinedLogFormat_small.png "QueryCombinedLogFormat logo")

# QueryCombinedLogFormat

## Description

This tool extracts, filters and parses combined log format (apache and nginx default access.log format) with a easy and fast language syntax.

> This tool has been written in forensic lessons and challenges for certification. It's a little tool to reduce time for analysis.
>> - This tool implements a basic and permissive syntax to query combined log files (apache and nginx default access.log format) with details and typing.
>> - This tool can parses multiples logs files using glob syntax and parses Gzip compressed logs files. If you have configured the logs rotation and gzip compression you can use this tool to analyze all of your logs with a simple command line.
>> - With this tool you can extract logs in a CSV and mJSON format to analyse it faster when you start this script multiple times on the same logs (in incident response). You can use the CSV file in excel with filtered logs for analyze or retex.
>> - To identify faster suspicious logs, this script implements a statistics option to make a CLI table with values and counters.

## Requirements

This package require:
 - python3
 - python3 Standard Library

## Installation

### Pip

```bash
python3 -m pip install QueryCombinedLogFormat
```

### Git

```bash
git clone "https://github.com/mauricelambert/QueryCombinedLogFormat.git"
cd "QueryCombinedLogFormat"
python3 -m pip install .
```

### Wget

```bash
wget https://github.com/mauricelambert/QueryCombinedLogFormat/archive/refs/heads/main.zip
unzip main.zip
cd QueryCombinedLogFormat-main
python3 -m pip install .
```

### cURL

```bash
curl -O https://github.com/mauricelambert/QueryCombinedLogFormat/archive/refs/heads/main.zip
unzip main.zip
cd QueryCombinedLogFormat-main
python3 -m pip install .
```

## Usages

### Command line

```bash
QueryCombinedLogFormat              # Using CLI package executable
python3 -m QueryCombinedLogFormat   # Using python module
python3 QueryCombinedLogFormat.pyz  # Using python executable
QueryCombinedLogFormat.exe          # Using python Windows executable

QueryCombinedLogFormat [-s|--statistics] [-d|--to-db] <glob_syntax_log_files> <queries>...

QueryCombinedLogFormat -d 'access.log*' "method = POST" 'status ~ 5??' # print logs and generate a DB file with POST method or server error (http status 5XX)
QueryCombinedLogFormat -s 'access_log_db_*.csv' '(METHOD = post or url ~ *admin*) & (ip > 91.0.0.0 | referrer ~ *://*)' # use the precedent generated DB to get statistics for POST request or admin URL for all IP address greater than 91.0.0.0 or with a url referrer
```

### Query syntax

#### Examples

1. Query all requests with the *method* POST: `method = POST`
2. Query all requests with a *status code* starting by 5 (server error): `status ~ 5??`
3. Query all requests with response size greater or equal than 60000000: `size >= 60000000`
4. Query all requests with a specific match on *User-Agent* and a specific IP address: `user_agent ~ *Version/6.0\ Mobile* and ip = 66.249.73.135`
5. Query all requests with the *method* POST or `admin` in URL if IP address is greater than `91.0.0.0` and referrer is not empty (contains URL instead of `-`): `(METHOD = post or url ~ *admin*) & (ip > 91.0.0.0 | referrer ~ *://*)`

### Fields

1. `ip` (IPv4Address)
2. `datetime` (datetime)
3. `method` (string)
4. `url` (string)
5. `version` (float)
6. `status` (int)
7. `size` (int)
8. `referrer` (string)
9. `user_agent` (string)

### Operators

1. `=`
2. `~`
3. `>`
4. `<`
5. `>=`
6. `<=`
7. `!`

### Inter expression

1. `and`
2. `&`
3. `or`
4. `|`

### Priority

1. Parenthesis
2. Left to right

### Escape character

`\` works only before a *spaces* or *operators* characters else is the `\` character.

## Links

 - [Pypi](https://pypi.org/project/QueryCombinedLogFormat)
 - [Github](https://github.com/mauricelambert/QueryCombinedLogFormat)
 - [Documentation](https://mauricelambert.github.io/info/python/security/QueryCombinedLogFormat.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/QueryCombinedLogFormat.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/QueryCombinedLogFormat.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
