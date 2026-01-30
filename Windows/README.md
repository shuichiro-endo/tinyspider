# tinyspider (Windows)

socks5 proxy tunnel tool

## Installation
### Install dependencies
- x86_64 architecture, 64bit, little endian
  - build environment: Linux
  - execution environment: Windows11 (24H2)
- x86_64-w64-mingw32-gcc (c99)
- make

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/tinyspider.git
```

2. build
```
cd tinyspider/Windows
make
ls -lh tinyspider.exe
```

> [!NOTE]
> If you want to display debug messages, please build it using the following command.
```
cd tinyspider/Windows
make debug
ls -lh tinyspider.exe
```

3. run strip command (optional)
```
strip tinyspider.exe
ls -lh tinyspider.exe
file tinyspider.exe
```

## Usage
### help
```
> tinyspider.exe -h

 .-.  _                          _    .-.
.' `.:_;                        :_;   : :
`. .'.-.,-.,-..-..-. .--. .---. .-. .-' : .--. .--.
 : : : :: ,. :: :; :`._-.': .; `: :' .; :' '_.': ..'
 :_; :_;:_;:_;`._. ;`.__.': ._.':_;`.__.'`.__.':_;
               .-. :      : :
               `._.'      :_;      Windows Ver: 0.01
                              Author: Shuichiro Endo


usage   : tinyspider.exe
        : [-4 spider_ipv4] [-6 spider_ipv6_global] [-u spider_ipv6_unique_local] [-l spider_ipv6_link_local]
        : [-e x(xor encryption)] [-k key(hexstring)]
        : [-e a(aes-256-cbc encryption)] [-k key(hexstring)] [-v iv(hexstring)]
        : [-s (prevent spider server startup)]
example : tinyspider.exe -4 192.168.0.10
        : tinyspider.exe -6 2001::xxxx:xxxx:xxxx:xxxx
        : tinyspider.exe -u fd00::xxxx:xxxx:xxxx:xxxx
        : tinyspider.exe -l fe80::xxxx:xxxx:xxxx:xxxx%2
        : tinyspider.exe -4 192.168.0.10 -6 2001::xxxx:xxxx:xxxx:xxxx -u fd00::xxxx:xxxx:xxxx:xxxx -l fe80::xxxx:xxxx:xxxx:xxxx%2
        : tinyspider.exe -4 192.168.0.10 -e x -k deadbeef
        : tinyspider.exe -4 192.168.0.10 -e a -k 47a2baa1e39fa16752a2ea8e8e3e24256b3c360f382b9782e2e57d4affb19f8c -v c87114c8b36088074c7ec1398f5c168a
        : tinyspider.exe -4 192.168.0.10 -s

```

> [!CAUTION]
> The usage is similar to [spider Linux](https://github.com/shuichiro-endo/spider/tree/main/Linux#example).
>
> However, [tinyspider](https://github.com/shuichiro-endo/tinyspider) is not compatible with [spider](https://github.com/shuichiro-endo/spider).
>
> [tinyspider](https://github.com/shuichiro-endo/tinyspider) and [spider](https://github.com/shuichiro-endo/spider) cannot be used together.

### run
> [!IMPORTANT]
> This program includes a simple DNS client implementation.
>
> It retrieves the IP address of the DNS server from HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} (for example, NameServer 1.1.1.1 or DhcpNameServer 1.1.1.1) at startup.
>
> It performs domain name resolution of socks5 connection to the IP address of the DNS server obtained.
```
> tinyspider.exe -4 192.168.0.8

 .-.  _                          _    .-.
.' `.:_;                        :_;   : :
`. .'.-.,-.,-..-..-. .--. .---. .-. .-' : .--. .--.
 : : : :: ,. :: :; :`._-.': .; `: :' .; :' '_.': ..'
 :_; :_;:_;:_;`._. ;`.__.': ._.':_;`.__.'`.__.':_;
               .-. :      : :
               `._.'      :_;      Windows Ver: 0.01
                              Author: Shuichiro Endo


---------------------------------------- tiny spider ------------------------------------------
 spider ipv4                     : 192.168.0.8
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
