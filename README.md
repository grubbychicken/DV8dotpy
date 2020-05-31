# Author

Ben Millar
@grubbychicken

# Installation
```
pip install -r requirements.txt
```

# Change Log

[v1.0 BETA 31-05-2020]
Modes Implemented:
* Revolver
* Shotgun
* Trident
* Nuke

# Modes
**Revolver**
Revolver mode will take 1 set of payloads and multiple payload positions.  It will iterate through each payload placing it in each payload position in turn. E.g. Request 1 = payload 1 in position 1.  Request 2 = payload 1 in position 2. Request 3 = payload 1 in posiion 3.  Request 4 = payload 2 in position 1. Request 5 = payload 2 in position2 and so on.

**Shotgun**
Shotgun mode will take 1 set of payloads and multiple payload positions.  It will iterate through each payload placing it in each payload position simultaneously.  E.g. Request 1 = payload 1 in position 1, 2 and 3.  Request 2 = payload 2 in position 1, 2 and 3. Request 3 = pyload 3 in position 1, 2 and 3 and so on.

**Trident**
Trident mode will take multiple payload files (up to 5) and multiple payload positions.  It will take each payload in each file in parallel and place them in their respective position. E.g. Request 1 = file1payload1 in position 1 and file2payload1 in position 2.  Request 2 = file1payload2 in position 1 and file2payload2 in position 2 and so on.

**Nuke**
Nuke mode will take multiple payload files (up to 5) and multiple payload positions.  It will take the first payload in the first payload file placing it in position 1 and then iterate through all payloads in payload file 2 placing it in position 2 for that 1 payload in payload file 1. E.g. Request 1 = file1payload1 in position 1 and file2payload1 in position 2. Request 2 = file1payload1 in position 1 and file2payload2 in position2. Request 3 = file1payload1 in position 1 and file2payload3 in position 2 and so on.

# Request File Format
You can generate a valid request file from Burp by following these steps:
1. Locate the request you wish to use
2. Right Click > Copy to file
3. Chose a filename to save the request

This is the same format that SQLmap and other tools use.

# Specifying Payload Positions
You can use two section characters (§value§) to specify a payload position.  Any value between two § characters will become a payload position.  The § characters will be removed and the payload inserted in their place. Take for example, this post data of a request:

username=§user1%40acmecorp.net§&password=§Password123§&AuthMethod=password

Here we have specified 2 payload positions.  Depending on the mode specified, this may become the following after processing:

(Trident Mode)
Request1: username=user1%40acmecorp.net&password=Password123&AuthMethod=password
Request2: username=user2%40acmecorp.net&password=Password321&AuthMethod=password
Request3: username=user3%40acmecorp.net&password=Welcome123&AuthMethod=password
Request4: username=user4%40acmecorp.net&password=Letmein123&AuthMethod=password
Request5: username=user5%40acmecorp.net&password=Monday1&AuthMethod=password


# Usage

```
██████╗░██╗░░░██╗░█████╗░██████╗░░█████╗░████████╗██████╗░██╗░░░██╗
██╔══██╗██║░░░██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗╚██╗░██╔╝
██║░░██║╚██╗░██╔╝╚█████╔╝██║░░██║██║░░██║░░░██║░░░██████╔╝░╚████╔╝░
██║░░██║░╚████╔╝░██╔══██╗██║░░██║██║░░██║░░░██║░░░██╔═══╝░░░╚██╔╝░░
██████╔╝░░╚██╔╝░░╚█████╔╝██████╔╝╚█████╔╝░░░██║░░░██║░░░░░░░░██║░░░
╚═════╝░░░░╚═╝░░░░╚════╝░╚═════╝░░╚════╝░░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░

Helping you identify deviations in HTTP responses.
Author: Ben Millar (@grubbychicken)
usage: DV8.py [-h] [--version] -f <Path to Request file> -p
              [<Path to Payload file> [<Path to Payload file> ...]] [-v]
              [-t <Threads>] [-r] [-q <Timeout>] [-k] [-x <Proxy>] -d
              <Deviator> [-c <HTTP Status Code>] -m <Attack Mode>
              [-S <Sensitivity>] [-o <Path to Dir>]

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -f <Path to Request file>
                        Supply the path to the HTTP request.
  -p [<Path to Payload file> [<Path to Payload file> ...]]
                        Supply the path to a list of payloads (One per-line).
                        Multiple files can be provided for the following
                        modes: trident(5), nuke
  -v                    Be verbose, i.e. Display response length and response
                        code for each request.
  -t <Threads>          Set number of threads, 1-20. (Default=5)
  -r                    Follow redirects. (Default=False)
  -q <Timeout>          Set request timeout in seconds, 1-60. (Default=10)
  -k                    Insecure mode i.e. check certificate validity.
                        (Default=True)
  -x <Proxy>            Proxy (scheme://ipaddress:port)
  -d <Deviator>         Response attribute to analyse for deviation.(Options:
                        code,cookie,clength,all)
  -c <HTTP Status Code>
                        Set expected status code. Any responses with different
                        codes will be treated as deviations.
  -m <Attack Mode>      Attack Mode i.e. how and where to inject payloads.
                        (Options: revolver,shotgun,trident,nuke)
  -S <Sensitivity>      Set Content Length analysis sensitivity, from 1-30
                        (Lower number = more sensitive, [more false
                        positives]. Vice versa.). (Default=25)
  -o <Path to Dir>      Supply the path to store the requests that produced
                        deviated responses. Format: payload.deviator or
                        position_payload.deviator if multiple payload
                        positions specified.
```

# Example

```
$ python3 -m shotgun -f request_o365.txt -p user-list.txt passwords.txt -d code -c 200 -x http://127.0.0.1:8080 -k

██████╗░██╗░░░██╗░█████╗░██████╗░░█████╗░████████╗██████╗░██╗░░░██╗
██╔══██╗██║░░░██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗╚██╗░██╔╝
██║░░██║╚██╗░██╔╝╚█████╔╝██║░░██║██║░░██║░░░██║░░░██████╔╝░╚████╔╝░
██║░░██║░╚████╔╝░██╔══██╗██║░░██║██║░░██║░░░██║░░░██╔═══╝░░░╚██╔╝░░
██████╔╝░░╚██╔╝░░╚█████╔╝██████╔╝╚█████╔╝░░░██║░░░██║░░░░░░░░██║░░░
╚═════╝░░░░╚═╝░░░░╚════╝░╚═════╝░░╚════╝░░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░

Helping you identify deviations in HTTP responses.
Author: Ben Millar (@grubbychicken)

===============================================================================
Attack Mode:  nuke
Threads: 5
Timeout: 10
Follow Redirects: False
Check Certificate: False
Proxy: http://127.0.0.1:8080
Analyse:  Status Code
CLength Sensitivity:  25
===============================================================================
Progress: |██████████████████████████████████████████████████| 100.0% Complete |
===============================================================================
Woohoo! 2 deviations found!
Time taken: 3.0842599868774414
===============================================================================
########## Status Code Deviations ##########
Position: 1, Payload: user1@acmecorp.net
Position: 2, Payload: Password123
###
Position: 1, Payload: user2@acmecorp.net
Position: 2, Payload: Password1234
###
===============================================================================
```

# To-Do List

* Stop bening lazy - Implement classes! Get rid of global vars!
* Add grep deviator - i.e. grep response for keyword/phrase
* Error checking!  Be better! 
* Check inside referer header for payload position.  Just another urllib.parse.... 
* Add "append extension" and "append slash" feature for file brute-forcing
* Could do with more testing.