# DKIMvisible
Stego algorithm for sending and recieving command across a C2 infrastructure.

### Motivation 
Detecting hidden C2 clients is one the most challenging objectives for cyberdefense nowadays. This project demonstrates 
how to use a commonly used protocol for establishing a hidden communication channel without rising suspicions, by using
the public key supplied within the DKIM protocol response.

### Why DNS and DKIM?  

- Do you known how many companies **do not use DNS?** Almost none of them.  
- Most common communicaiton channels from C2 infrastructures use HTTPs for obvious reasons, but many cyberdef software developers
(i.e. Palo Alto NGFW) are implementing different techniques for decrypting SSL. This technique does not require encryption to work
 or remain stealthy.  
- The DKIM protocol specification allows us to extend the functionality of the algorithm by implementing "fake" DKIM selectors. Imagine 
that your C2 server is behind the `antivirus.update.avaast.com`. Using a selector like `algorithm_modifier._domainkeys.antivirus.update.avaast.com` 
may seem like a legitimate request and provides an "incognito" modifier for the C2 server.
- There are several fields from a DNS DKIM TXT record that can be used to hide inforaation. This example uses the `p=` field that 
stores the public key, but other fields like `s=` for storing the signature could come in handy.  
- Since there should not be any SMTP agent involed in the communication, the legitimate DKIM processing would mostly never happen.
- These technique can be executed anywhere there is a DNS server that resolves your C2 domain.  
  
### Resources  
- [DNS protocol - RFC 1035](https://tools.ietf.org/html/rfc1035)  
- [DKIM protocol - RFC 6376 (new)](https://tools.ietf.org/html/rfc6376)

### Algorithm  
The public key `p` field is a 1024-bit key encoded in base64, as described on [RFC 6376 - 3.6.1](https://tools.ietf.org/html/rfc6376#section-3.6.1), notice 
the length of the key is variable, real DKIM records should have a minimum recommended 1024-bit length so we will make it that way to add more "stealthiness".  
The message hidden inside the DKIM value must contain the following information interpretabled by the C2 client:
- Function to execute
- Separator
- Length of the evaluable message
- Params
  
With that being said, we can now use `216 characters` to hide our message (`1024 bits`). By looking back into the needs of the communication between the clients 
and the server, we will divide those 216 characters into different sections by executing the following steps:
1) Decode from base64
2) The first two characters are a **reversed hex function numeration** to execute. Imagine that we would like to execute the function number 27; `hex(27) = 1B`; `reversed(1B) = B1`.So `B1` 
basically means "Execute function 27". **Why do a simple reverse?** Imagine that you send functions 2, 5 and 9: The first characters from each DKIM's public key would be
`0`, so doing a simple reverse makes the public key start with `2`, `5` and `9`, hence making the keys visually more randomized.  
3) The next two characters make the separator character by substracting the first chracters to the second one, and if the result is negative, it truncates. These characters do not have to be 
hex, but ASCII representable characters. Example: if the thrid and forth characters are `9t`, then `ASCII(t)=116 - ASCII(9)=9 = 107`, `ASCII(107) = k`. So `k` is the separator character. 
4) Get the next `n` characters until you reach the separator chracter, in this case `k`. Add the `ASCII` values from those chracters and you will get the interpretable message length. If the  
letters were `+0` then `ASCII(+) + ASCII(0) = 43 + 48 = 91 # avaluable characters`.
5) Get the next evaluable characters, `91` in this case.  and use the remaining characters `216 - 2(function) - 2(separator definition) - 2(message_length) - 1 (separator) - 91 (evaluable characters) =  120 characters` for 
XORing the evauable characters, a.k.a. use as key.  
  - If `len(key) > len(evaluable_characters)` get `key[0:len(evaluable_characters)]` and apply the XOR.
  - If `len(evaluable_characters) > len(key)` get `len(evaluable_characters) // len(key) = X`, then take `key * X + key[0:(len(evaluable_characters) - (len(key) * X))]`, then XOR.  
  - If lengths are equal, XOR them directly
6) Take the result, split by the separator character, and those should be the function parameters.

### Additional notes
This example is fairly simple, it could even become more complicated by adding the DKIM selectors or even applying AES encryption with a key providaded by the signature DKIM field.
