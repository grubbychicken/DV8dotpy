# DV8dotpy
DV8dotpy helps you identify deviations in HTTP responses.  It has a whole plethora of applications.  It can be used to bruteforce directories, files, valid cfedentials and so on.  You specify what a deviation looks like and it will tell you if any deviations are found in the responses.  It uses multithreading so can be pretty quick.

For example; you're trying to brute force credentials on a companies federated Office 365 portal.  You know that an invalid logon response doesn't set any cookies, but a successful logon does. Use the "cookie" deviator and DV8dotpy will let you know which of your payloads resulted in a successful logon.  You could also use the content length ("clength") deviator in this example because the content length of a successful logon is sufficiently different from the content length of an invalid logon.  Using "clength", DV8dotpy is clever enough to work out what the norm is and identifies any responses that deviate form it.  

Or another example; you're trying to brute force a file on a web server.  You know that an invalid filename results in a 404 but a valid filename results in a 200.  Use the "code" deviator with -c 404 and DV8dotpy will look for any responses that deviate from it.

There are 4 modes available: revolver, shotgun, trident and nuke.  Each one handles the payloads and payload positions slightly differently.  See "Modes" below for a description.

It is by no means perfect and is still BETA.  I still have quite a bit of testing to do.  And I also need to refactor everything and implement classes.  But hopefully it still comes in useful for some people.  If you have any feature requests or any suggestions then let me know.  Also, feel free to raise issues on GitHub.

# Example Use Cases
**Red Team Engagements**
Credential Stuffing - You have created a list of username/password pairs from password leaks/breaches for the company you're testing.  You can use trident mode against any of their public facing services that allow you to authenticate, such as OWA or Office365.  Both OWA and Office365 set cookies upon a successful login, use the cookie deviator and DV8dotpy will let you know which logins were successful.  

Password Brute Forcing - You have enumerated a list of email addresses from LinkedIn or other open sources.  You want to attempt to log in to a public facing service such as OWA or Office365 using each email address and a list of x passwords.  Use nuke mode. DV8dotpy will let you know which logins were successful.

**Web App Pentest**
In a scenario where you have to update multiple request values with the same payload in the same request, such as a username in an email address feild and a cookie - use shotgun mode.

In a scenario where you want to enumerate a list of valid user IDs or usernames for example, use revolver mode to place a payload in one or more positions on after the other.

# Author

Ben Millar
@grubbychicken

# Installation
```
pip3 install -r requirements.txt
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
```
username=§user1%40acmecorp.net§&password=§Password123§&AuthMethod=password
```
Here we have specified 2 payload positions.  Depending on the mode specified, this may become the following after processing:

(Trident Mode)
```
Request1: username=user1%40acmecorp.net&password=Password123&AuthMethod=password
Request2: username=user2%40acmecorp.net&password=Password321&AuthMethod=password
Request3: username=user3%40acmecorp.net&password=Welcome123&AuthMethod=password
Request4: username=user4%40acmecorp.net&password=Letmein123&AuthMethod=password
Request5: username=user5%40acmecorp.net&password=Monday1&AuthMethod=password
```

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
              [-a [<String to append> [<String to append> ...]]]

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
  -t <Threads>          Set number of threads, 1-50. (Default=5)
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
  -a [<String to append> [<String to append> ...]]
                        Supply any string(s) you wish to append to the payload
                        i.e. ".txt", ".php", "/". You can supply more than
                        one.
```

# Example

```
python3 DV8.py -m shotgun -f magic.req -p test_dirs -d all -c 404 -S 1 -x http://127.0.0.1:8080 -k -a .txt .php /

██████╗░██╗░░░██╗░█████╗░██████╗░░█████╗░████████╗██████╗░██╗░░░██╗
██╔══██╗██║░░░██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗╚██╗░██╔╝
██║░░██║╚██╗░██╔╝╚█████╔╝██║░░██║██║░░██║░░░██║░░░██████╔╝░╚████╔╝░
██║░░██║░╚████╔╝░██╔══██╗██║░░██║██║░░██║░░░██║░░░██╔═══╝░░░╚██╔╝░░
██████╔╝░░╚██╔╝░░╚█████╔╝██████╔╝╚█████╔╝░░░██║░░░██║░░░░░░░░██║░░░
╚═════╝░░░░╚═╝░░░░╚════╝░╚═════╝░░╚════╝░░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░

Helping you identify deviations in HTTP responses.
Author: Ben Millar (@grubbychicken)

===============================================================================
Attack Mode:  shotgun
Threads: 5
Timeout: 10
Follow Redirects: False
Check Certificate: False
Proxy: http://127.0.0.1:8080
Analyse:  Cookie, Status Code and Content Length
CLength Sensitivity:  1
===============================================================================
Progress: |██████████████████████████████████████████████████| 100.0% Complete |
===============================================================================
Woohoo! 19 deviations found!
Time taken: 0.9599368572235107
===============================================================================
########## Status Code Deviations ##########
images/
images
upload.php
assets/
assets
.php
/

tmp/
tmp
########## Content Length Deviations ##########
images/
images
upload.php
assets
.php
/

tmp
########## Cookie Deviations ##########
upload.php
===============================================================================
```

# To-Do List

* Update all modes to work with parameters not just parameter values.
* Stop being lazy - Implement classes! Get rid of global vars!
* Add grep deviator - i.e. grep response for keyword/phrase
* Error checking!  Be better! 
* Check inside referer header for payload position.  Just another urllib.parse.... 
* Add "append extension" and "append slash" feature for file brute-forcing
* Could do with more testing.
* Extend to accommodate more HTTP methods