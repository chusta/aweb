# aweb
a tiny asyncio web server

## Table of Contents
* [Overview](#overview)
* [Build](#build)
* [Install](#install)
* [Usage](#usage)
  * [HTTP GET](#http-get)
  * [HTTP PUT](#http-put)
  * [SSL/TLS](#ssltls)
  * [Base64](#base64)
* [Test](#test)


## Overview
* Serve data by piping from stdout or as a script argument
* Base64 decode HTTP GET query strings (/?b=)
* Supports SSL/TLS through self-signed certificates

## Build
```
$ make setup
$ make build
```

## Install
```
$ make install
```

## Usage
```
$ aweb -h
usage: aweb [-h] [-f FILE] [-d DATA] [-a ADDR] [-p PORT] [--ssl]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  input file
  -d DATA, --data DATA  input data
  -a ADDR, --addr ADDR
  -p PORT, --port PORT
  --ssl
```

### HTTP GET
The file (-f) or data (-d) are served regardless of path name.

* Serving a file
```
$ aweb -f /bin/ls
```

* Serving data (argument)
```
$ aweb -d $(cat /bin/ls)
```

* Serving data (stdin)
```
$ cat /bin/ls | aweb
```


### HTTP PUT
Filename is saved as basename.md5sum
```
$ curl -T /bin/ls http://aweb:8080/filename

$ aweb
http://0.0.0.0:8080
[+] 127.0.0.1:54756 - PUT /filename
[PUT] filename.8b494b5505a60834341be6d8154a2420
```

### SSL/TLS
```
$ aweb --ssl -d "TEST"

$ curl -s -k https://aweb:8080
```

### Base64
Transfer data to webserver using Base64
```
$ aweb
http://0.0.0.0:8080
[+] 127.0.0.1:49262 - GET /?b=VEVTVA==
[B64] TEST

$ curl -s "localhost:8080/?b=$(echo -en TEST|base64)"
```

## Test
```
$ make setup-dev
$ make test
```
