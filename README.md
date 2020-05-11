# DKIMvisible
Stego algorithm for sending and recieving command across a C2 infrastructure.

### Motivation 
Detecting hidden C2 clients is one the most challenging objectives for cyberdefense nowadays. This project demonstrates 
how to use a commonly used protocol for establishing a hidden communication channel without rising suspicions, by using
the public key supplied within the DKIM protocol response.

### Why DNS and DKIM?  

- Do you known how many companies **do not use DNS?** Almost none of them.  
- Most common communication channels from C2 infrastructures use HTTPs for obvious reasons, but many cyberdef software developers
(i.e. Palo Alto NGFW) are implementing different techniques for decrypting SSL. This technique does not require encryption to work
 or remain stealthy.  
- The DKIM protocol specification allows us to extend the functionality of the algorithm by implementing "fake" DKIM selectors. Imagine 
that your C2 server is behind the `antivirus.update.avaast.com`. Using a selector like `algorithm_modifier._domainkeys.antivirus.update.avaast.com` 
may seem like a legitimate request and provides an "incognito" modifier for the C2 server.
- There are several fields from a DNS DKIM TXT record that can be used to hide information. This example uses the `p=` field that 
stores the public key, but other fields like `s=` for storing the signature could come in handy.  
- Since there should not be any SMTP agent involved in the communication, the legitimate DKIM processing would mostly never happen.
- These technique can be executed anywhere there is a DNS server that resolves your C2 domain.  
- Funny at it sound, the **DKIM protocol is used to provide security**.
  
### Resources  
- [DNS protocol - RFC 1035](https://tools.ietf.org/html/rfc1035)  
- [DKIM protocol - RFC 6376 (new)](https://tools.ietf.org/html/rfc6376)

### Algorithm  
The public key `p` field is a 1024-bit key encoded in base64, as described on [RFC 6376 - 3.6.1](https://tools.ietf.org/html/rfc6376#section-3.6.1), notice 
the length of the key is variable, real DKIM records should have a minimum recommended 1024-bit length so we will make it that way to add more "stealthiness".  
The message hidden inside the DKIM value must contain the following information interpretable by the C2 client:
- Function to execute
- Separator
- Length of the evaluable message
- Params
- Key
  
With that being said, we can now use `128 characters` to hide our message (`1024 bits`). *Note that we are going to be using ASCII characters, which means that 
1 char = 1 byte* By looking back into the needs of the communication between the clients 
and the server, we will divide those 128 characters into different sections by executing the following steps:

#### Encode
1) Choose a function to execute, get its number, convert it to hex and reverse it. **Why do a simple reverse?** Imagine that you send functions 2, 5 and 9: The first characters from each DKIM's public key would be
`0`, so doing a simple reverse makes the public key start with `2`, `5` and `9` respectively, hence making the keys visually more randomized. If we choose to execute function number `27`, the first two characters 
of the PK would be `reversed(hex(27))`. **Always represent the number by a two-length hex** i.e. `reversed(hex(5))` is still `5`, so add a `0` before the number and the execute the reversing: `reverse(05)`.
2) Check how many separators are needed for the arguments. This is `evaluable_length = number_of_arguments - 1`.
3) Calculate a separator: A random ASCII character that **is not contained inside the parameters**. i..e **h** is not a valid separator if we have `"hello"` as a parameter.
4) The separator must not go in "cliear text", that why the third and fourth characters of the PK are going to be two characters `x` and `y` so that `ascii_value(x) + ascii_value(y) = ascii_value(separator)`
5) The fifth and sixth characters of the PK are going to be two characters `x` and `y` so that `ascii_value(x) + ascii_value(y) = evaluable_length`.
6) Concatenate the already calculated 6 characters to the parameters separated by the `separator`. i.e. If we have two params `param1` and `param2` with `k` as a separator, we concat `param1kparam2`.
8) The rest of the characters until the `128 chars` limit are a series of random ASCII characters. (`key`)
9) XOR the params concatenated by the separators with the just created `key`.  
  - If `len(key) > len(params)` we take `key[0:len(params)]` as `key`
  - If `len(key) < len(params)` we take `key * len(params) // len(key) + key[0:len(params) % len(key)]` as `key`
  - If `len(key) = len(params)` we take `key`  
  - When done, XOR char per char
  - Encode **everything** in base64  
  
That makes the PK that is going to be set inside the `p=` DKIM record.  


#### Decode
1) Decode from base64
2) The first two characters are a **reversed hex function numeration** to execute. Imagine that we would like to execute the function number 27, the first two characters of the PK would be `B1`; `reversed(B1) = 1B`; `1B = hex(27)`.So `27`.   
3) The next two characters make the separator character by adding their both ascii value. These characters do not have to be 
hex, but ASCII representable characters. Example: if the third and forth characters are `\x0e\x18`, then `ASCII(\x0e)=14 - ASCII(\x18)=24 = 38`, `ASCII(38) = &`. So `&` is the separator character. 
4) Get the next 2 characters until you reach the separator character, in this case `&`. Add the `ASCII` values from those two and you will get the interpretable message length. If the  
letters were `+0` then `ASCII(+) + ASCII(0) = 43 + 48 = 91 # avaluable characters`.
5) **Optionally**, check if the 7th character is the separator character just calculated in step 2. 
5) Get the next evaluable characters, `91` in this case.  and use the remaining characters `128 - 2(function) - 2(separator definition) - 2(message_length) - 91 (evaluable characters) =  31 characters` for XORing the evaluable characters, a.k.a. use as key.  
  - If `len(key) > len(evaluable_characters)` get `key[0:len(evaluable_characters)]` and apply the XOR.
  - If `len(evaluable_characters) > len(key)` get `len(evaluable_characters) // len(key) = X`, then take `key * X + key[0:(len(evaluable_characters) - (len(key) * X))]`, then XOR.  
  - If lengths are equal, XOR them directly
6) Take the result, split by the separator character, and those should be the function parameters.

### Implementation 
- The `server.py` file contains the Encoding algorithm and communication with a bind9 DNS server.
- The `client.py` file contains the Decoding algorithm and implements DNS requests.
- The `main.py` file executes an encoding from the server and a decoding from the client, so you can check how the message is passed from one to another.


## Install the requirements
```python
pip install -r requirements.txt
```

## Run the docker container with the DNS server

**You can just run setup.sh and forget about all of this**

1. Create a docker network, if not we cannot give static IP addresses
```
sudo docker network create --subnet=172.20.0.0/16 test-net
```

2. Build the docker image
```
sudo docker build -t bind9 .
```

3. Run a container in the background for the dns server
```
sudo docker run -d --rm --name=dns-server --net=test-net --ip=172.20.0.2 bind9
```

4. Start the bind9 daemon
```
sudo docker exec -d dns-server /etc/init.d/bind9 start
```

5. Run the hosts in the same network
```
sudo docker run -d --rm --name=host1 --net=test-net --ip=172.20.0.3 --dns=172.20.0.2 bind9
sudo docker run -d --rm --name=host2 --net=test-net --ip=172.20.0.4 --dns=172.20.0.2 bind9
```

6. Connect to one of them to see if everything is OK

```
sudo docker exec -it host1 bash
```

The output of a `ping` should be the following

```
root@0d29a2941b8c:/# ping host2.test.com
PING host2.test.com (172.20.0.4) 56(84) bytes of data.
64 bytes from host2.test-net (172.20.0.4): icmp_seq=1 ttl=64 time=0.113 ms
64 bytes from host2.test-net (172.20.0.4): icmp_seq=2 ttl=64 time=0.155 ms
64 bytes from host2.test-net (172.20.0.4): icmp_seq=3 ttl=64 time=0.178 ms
64 bytes from host2.test-net (172.20.0.4): icmp_seq=4 ttl=64 time=0.142 ms
64 bytes from host2.test-net (172.20.0.4): icmp_seq=5 ttl=64 time=0.150 ms
64 bytes from host2.test-net (172.20.0.4): icmp_seq=6 ttl=64 time=0.167 ms
64 bytes from host2.test-net (172.20.0.4): icmp_seq=7 ttl=64 time=0.140 ms
64 bytes from host2.test-net (172.20.0.4): icmp_seq=8 ttl=64 time=0.139 ms
^C
--- host2.test.com ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 7153ms
rtt min/avg/max/mdev = 0.113/0.148/0.178/0.018 ms
```

## Client usage  
Start the client and set the DNS server IP. For this demonstration leave the default arguments as such.
```python
python3 client.py <DNS-server-IP>
# The client will stay on infinite loop and will request DKIM records every 6-8 seconds
```

## Server usage
Start the server. For this demonstration leave the default arguments as such.
```python
python3 server.py

# The server will ask which client you want to talk to. Say "alice"
[?] C2 client key name: alice

# Choose one of the functions
Choose a function to execute on client
	1) Print
	2) Reverse shell
	3) Sleep
Option: 1

# Look at the parameters, in this example the print funciton takes an number of arguments (each argument separated by a black space)
[*] Parameters for "Print" function
	[*] Param name: *args
	[*] Param type: list
	[*] Param description: Any number of strings to print
Value: multi argument remote function execution

# Prints the operations and updates the DNS
[*] Selected divider: O(79 ASCII). 5 + 74 = 79
[+] Info util: 'multiOargumentOremoteOfunctionOexecution' (length = 40) 
 [+] Key util: "&=etJ@i<e+6H7%-N|/&`hiymXqL*5 >u5%KS/N<&y\t!Sw$GMG;s[LJp{\x0cY'|PZ]>vj@x/s8h^6,+#OQ&-S" (length = 82)
[+] Encrypted data: "KH\t\x00#\x0f\x08N\x02^[-YQb<\x19BI\x14\r&\x1f\x186\x128CZNq\x10M@(&['SH"
[+] Final PK non(B64): '10\x05J\x06"KH\t\x00#\x0f\x08N\x02^[-YQb<\x19BI\x14\r&\x1f\x186\x128CZNq\x10M@(&[\'SH&=etJ@i<e+6H7%-N|/&`hiymXqL*5 >u5%KS/N<&y\t!Sw$GMG;s[LJp{\x0cY\'|PZ]>vj@x/s8h^6,+#OQ&-S'(128 characters with 1024 bits)
[+] Final PK: 'MTAFSgYiS0gJACMPCE4CXlstWVFiPBlCSRQNJh8YNhI4Q1pOcRBNQCgmWydTSCY9ZXRKQGk8ZSs2SDclLU58LyZgaGl5bVhxTCo1ID51NSVLUy9OPCZ5CSFTdyRHTUc7c1tMSnB7DFknfFBaXT52akB4L3M4aF42LCsjT1EmLVM='(172 characters with 1376 bits)
```
### Additional notes  

- This example is fairly simple and is not functional, it could even become more complicated by adding the DKIM selectors or even applying AES encryption with a key providaded by the signature DKIM field. 
- The given implementation only supports the `print(*args)`, `reverse_shell(port, ip)` and `sleep(seconds)` functions.
- Function storage with its corresponding number, description, etc... should be object-oriented, but a `dict` is used here.  
