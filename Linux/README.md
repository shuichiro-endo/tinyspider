# tinyspider (Linux)

socks5 proxy tunnel tool

## Installation
### Install dependencies
- gcc (c99)
- make

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/tinyspider.git
```

2. build
```
cd tinyspider/Linux
make
ls -lh tinyspider
```

> [!NOTE]
> If you want to display debug messages, please build it using the following command.
```
cd tinyspider/Linux
make debug
ls -lh tinyspider
```

3. check if it is a statically linked binary
```
file tinyspider
ldd tinyspider
```

4. run strip command (optional)
```
strip tinyspider
ls -lh tinyspider
file tinyspider
nm tinyspider
```

## Usage
### help
```
> ./tinyspider -h

 .-.  _                          _    .-.           
.' `.:_;                        :_;   : :           
`. .'.-.,-.,-..-..-. .--. .---. .-. .-' : .--. .--. 
 : : : :: ,. :: :; :`._-.': .; `: :' .; :' '_.': ..'
 :_; :_;:_;:_;`._. ;`.__.': ._.':_;`.__.'`.__.':_;  
               .-. :      : :                     🕷️
               `._.'      :_;        Linux Ver: 0.01
                              Author: Shuichiro Endo


usage   : ./tinyspider
        : [-4 spider_ipv4] [-6 spider_ipv6_global] [-u spider_ipv6_unique_local] [-l spider_ipv6_link_local]
        : [-e x(xor encryption)] [-k key(hexstring)]
        : [-e a(aes-256-cbc encryption)] [-k key(hexstring)] [-v iv(hexstring)]
        : [-s (prevent spider server startup)]
example : ./tinyspider -4 192.168.0.10
        : ./tinyspider -6 2001::xxxx:xxxx:xxxx:xxxx
        : ./tinyspider -u fd00::xxxx:xxxx:xxxx:xxxx
        : ./tinyspider -l fe80::xxxx:xxxx:xxxx:xxxx%2
        : ./tinyspider -4 192.168.0.10 -6 2001::xxxx:xxxx:xxxx:xxxx -u fd00::xxxx:xxxx:xxxx:xxxx -l fe80::xxxx:xxxx:xxxx:xxxx%2
        : ./tinyspider -4 192.168.0.10 -e x -k deadbeef
        : ./tinyspider -4 192.168.0.10 -e a -k 47a2baa1e39fa16752a2ea8e8e3e24256b3c360f382b9782e2e57d4affb19f8c -v c87114c8b36088074c7ec1398f5c168a
        : ./tinyspider -4 192.168.0.10 -s

```

### run
> [!IMPORTANT]
> This program includes a simple DNS client implementation.
> 
> This program retrieves the IP address of the DNS server from /etc/resolv.conf (for example, nameserver 1.1.1.1) at startup.
>
> It performs domain name resolution to the IP address of the DNS server obtained.
```
> ./tinyspider -4 192.168.0.7

 .-.  _                          _    .-.           
.' `.:_;                        :_;   : :           
`. .'.-.,-.,-..-..-. .--. .---. .-. .-' : .--. .--. 
 : : : :: ,. :: :; :`._-.': .; `: :' .; :' '_.': ..'
 :_; :_;:_;:_;`._. ;`.__.': ._.':_;`.__.'`.__.':_;  
               .-. :      : :                     🕷️
               `._.'      :_;        Linux Ver: 0.01
                              Author: Shuichiro Endo


---------------------------------------- tiny spider ------------------------------------------
 spider ipv4                     : 192.168.0.7
 dns server                      : 1.1.1.1
 xor encryption                  : off
 xor key hex string              : 
 aes encryption                  : off
 aes key hex string              : 
 aes iv hex string               : 
 prevent spider server startup   : off
--------------------------------------- spider command ----------------------------------------
 1: add node (spider pipe)
 2: add node (spider client)
 3: show node information
 4: show routing table
 0: exit
-----------------------------------------------------------------------------------------------

command > 
```
