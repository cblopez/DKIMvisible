$TTL    604800
@       IN      SOA     ns1.test.com. root.test.com. (
                  3       ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
             604800 )   ; Negative Cache TTL
;
; name servers - NS records
     IN      NS      ns1.test.com.

; name servers - A records
ns1.test.com.          IN      A      172.20.0.2

host1.test.com.        IN      A      172.20.0.3
host2.test.com.        IN      A      172.20.0.4

; TXT records
host1.test.com.		IN	TXT	"Este es el servidor 1"
host2.test.com.		IN	TXT	"Este es el servidor 2"	
