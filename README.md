![QueryApacheAccessLog Logo](https://mauricelambert.github.io/info/python/security/QueryApacheAccessLog_small.png "QueryApacheAccessLog logo")

# QueryApacheAccessLog

## Description

This script parses and implements a syntax to query and filter apache access logs, easiest and faster way to find your logs in incident response.

> This script has been written in forensic lessons and challenges for certification. It's a little script to reduce time for analysis.
>> This script implements a basic and permissive syntax to query logs with details and typing.

## Requirements

This package require:
 - python3
 - python3 Standard Library

## Installation

### Git

```bash
git clone "https://github.com/mauricelambert/QueryApacheAccessLog.git"
cd "QueryApacheAccessLog"
```

### Wget

```bash
wget https://github.com/mauricelambert/QueryApacheAccessLog/archive/refs/heads/main.zip
unzip main.zip
cd QueryApacheAccessLog-main
```

## Usages

### Command line

```bash
python3 query_apache_access_log.py <glob_syntax_log_files> <queries>...

python3 query_apache_access_log.py access.log* "method = POST" 'status ~ 5??'
python3 query_apache_access_log.py access.log* '(METHOD = post or url ~ *admin*) & (ip > 91.0.0.0 | referrer ~ *://*)'
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

 - [Github](https://github.com/mauricelambert/QueryApacheAccessLog)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
