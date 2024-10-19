# DNS Monitor [ISA]

### Short Information

- **Author:** Dmytro Khodarevskyi (xkhoda01)
- **Date:** 18.10.2024
- **VUT FIT 2024**

### Overview

This is a program for parsing DNS requests. It can output all necessary information extracted from the DNS package. It supports IPv4 and IPv6 communication.

Types of source information:

- **Device**
- **PCAP File**

Types of supported DNS packages:

- **A** (1) _[IPv4]_
- **AAAA** (28) _[IPv6]_
- **NS** (2) _[NameServer]_
- **MX** (15) _[Mail Exchange]_
- **SOA** (6) _[Start Of Authority]_
- **CNAME** (5) _[Canonical Name]_
- **SRV** (33) _[Service]_

Types of output _(with example)_:

- **Regular**

  ```
    1999-03-11 14:45:02 3ffe:501:4819::42 -> 3ffe:507:0:1:200:86ff:fe05:80da (R 1/6/2/5)
  ```

- **Verbose**

  ```
    Timestamp: 1999-03-11 14:45:02
    SrcIP: 3ffe:501:4819::42
    DstIP: 3ffe:507:0:1:200:86ff:fe05:80da
    SrcPort: UDP/53
    DstPort: UDP/2396
    Identifier: 0x6
    Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, AD=0, CD=0, RCODE=0

    [Question Section]
    itojun.org. IN 255 (unhandled type)

    [Answer Section]
    itojun.org. 3600 IN NS coconut.itojun.org.
    itojun.org. 3600 IN NS tiger.hiroo.oshokuji.org.
    itojun.org. 3600 IN MX 10 coconut.itojun.org.
    itojun.org. 3600 IN MX 20 kiwi.itojun.org.
    itojun.org. 3600 IN A 210.160.95.97
    itojun.org. 3600 IN SOA itojun.org. root.itojun.org. 199903080 3600 300 3600000 3600

    [Authority Section]
    itojun.org. 3600 IN NS coconut.itojun.org.
    itojun.org. 3600 IN NS tiger.hiroo.oshokuji.org.

    [Additional Section]
    coconut.itojun.org. 3600 IN A 210.160.95.97
    tiger.hiroo.oshokuji.org. 3600 IN A 210.145.33.242
    kiwi.itojun.org. 3600 IN AAAA 3ffe:501:410:0:2c0:dfff:fe47:33e
    kiwi.itojun.org. 3600 IN AAAA 3ffe:501:410:100:5254:ff:feda:48bf
    kiwi.itojun.org. 3600 IN A 210.160.95.99
    ====================
  ```

#### Domains list

Program can put domain names in specified file

_Example output:_

```
    _xmpp-client._tcp.jabber.org
    zeus.jabber.org
    zeus-v6.jabber.org
```

#### Domains list (With IPv4/IPv6 resolved addresses)

Program can put domain names with corresponding IP addresses in specified file

_Example output:_

```
    itojun.org 210.160.95.97
    coconut.itojun.org 210.160.95.97
    tiger.hiroo.oshokuji.org 210.145.33.242
    kiwi.itojun.org 3ffe:501:410:0:2c0:dfff:fe47:33e
    kiwi.itojun.org 3ffe:501:410:100:5254:ff:feda:48bf
```

### Compiling

Makefile is present, so for compiling project you can use:

```
 make
```

### Running

```
./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]
```

**Parameters:**

- _-i &lt;interface&gt;_ - the name of the interface on which the program will listen, or
- _-p &lt;pcapfile&gt;_ - the name of the PCAP file that the program will process;
- _-v_ - "verbose" mode: complete listing of DNS message details;
- _-d &lt;domainsfile&gt;_ - name of the domain name file;
- _-t &lt;translationsfile&gt;_ - name of the file with the translation of domain names to IP.

### List of files

```
makefile
main.cpp
Monitor.cpp
Monitor.hpp
ParseArgs.cpp
ParseArgs.hpp
README.md
```
