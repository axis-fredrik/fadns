# fadns

Simple and stupid DNS server

Example -



```fredan@M-C02CFE9KMD6M ~ % dig @localhost www.google.se     

; <<>> DiG 9.10.6 <<>> @localhost www.google.se
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49319
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.google.se.			IN	A

;; ANSWER SECTION:
www.google.se.		600	IN	A	192.168.0.1

;; Query time: 1 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Wed Oct 28 00:30:29 CET 2020
;; MSG SIZE  rcvd: 60```
