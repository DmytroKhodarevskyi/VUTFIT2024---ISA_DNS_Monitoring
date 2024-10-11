#include "Monitor.hpp"

Monitor::Monitor(const string& device) : device_(device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Could not open device " << device << ": " << errbuf << endl;
        exit(1);
    }
    handle_ = handle;

    list_interfaces_ = false;

    string filter_ = "udp port 53";

    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Could not parse filter " << filter_ << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }
    if (pcap_setfilter(handle_, &fp) == -1) {
        cerr << "Could not install filter " << filter_ << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }

    pcap_freecode(&fp);
}

Monitor::Monitor() {
    list_interfaces_ = true;
}

Monitor::~Monitor() {
    if (!list_interfaces_ && handle_ != nullptr) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void Monitor::printByte(const u_char byte) {
    // Print in decimal (default)
    std::cout << "Decimal: " << std::dec << static_cast<int>(byte) << std::endl;
    
    // Print in hexadecimal
    std::cout << "Hexadecimal: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << std::endl;
}

void Monitor::list_active_interfaces() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // Print the list
    for (device = alldevs; device != NULL; device = device->next) {
        if (device->name)
          cout << device->name << endl;
    }

    // Free the device list
    if (alldevs != NULL)
      pcap_freealldevs(alldevs);
}

Monitor::DNSHeader* Monitor::parseDNSHeader(const u_char* packet) {
    return (DNSHeader*)(packet + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr));
}

string Monitor::toUpper(string str) {
    for (int i = 0; i < str.length(); i++) {
        str[i] = toupper(str[i]);
    }
    return str;
}

void Monitor::capture() {
    callback_args data;
    data.domains_file_stream = &domains_file_stream;
    data.translation_file_stream = &translation_file_stream;
    data.verbose = verbose;  // Assuming 'verbose' is a class member

    pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char*>(&data));
}


void Monitor::parseDomainName(const u_char* &dnsPointer, const u_char* messageStart, std::string &domainName) {
    while (*dnsPointer != 0) {
        if ((*dnsPointer & 0xC0) == 0xC0) {  // Check for compression
            uint16_t offset = ntohs(*reinterpret_cast<const uint16_t*>(dnsPointer)) & 0x3FFF;
            dnsPointer = messageStart + offset;  // Follow the pointer
        } else {
            int labelLength = *dnsPointer;
            dnsPointer++;
            domainName.append(reinterpret_cast<const char*>(dnsPointer), labelLength);
            domainName.append(".");
            dnsPointer += labelLength;
        }
    }
    dnsPointer++;  // Skip the null terminator
    if (!domainName.empty() && domainName.back() == '.') {
        domainName.pop_back();  // Remove trailing dot
    }
}


void Monitor::parseResourceRecords(const u_char** dnsPayload, uint16_t rrcount, const u_char* message) {

    for (int i = 0; i < rrcount; i++) {

        const u_char* name_pointer = *dnsPayload;

        unsigned char FirstTwo = **dnsPayload & 0xC0;

        if (FirstTwo == 0xC0) {
            uint16_t offset = ntohs(*reinterpret_cast<const uint16_t*>(*dnsPayload)) & 0x3FFF;  // Extract the offset
            name_pointer = message + offset;  // Get the pointer to the compressed name
            *dnsPayload += 2;  // Move the pointer forward by 2 bytes
        } else {
            *dnsPayload += 1;
        }


        string name;

        while (*name_pointer != 0) {
            int labelLength = *name_pointer;

            name_pointer++;

            name.append(reinterpret_cast<const char*>(name_pointer), labelLength);
            name.append(".");

            name_pointer += labelLength;
        }
        name_pointer++;  // Skip the null terminator (0x00)

        uint16_t type;
        memcpy(&type, *dnsPayload, sizeof(uint16_t));
        type = ntohs(type);

        // cerr << "type: " << type << endl;
        *dnsPayload += 2;

        // Parse CLASS (next 2 bytes)
        uint16_t rclass;
        memcpy(&rclass, *dnsPayload, sizeof(uint16_t));
        rclass = ntohs(rclass);
        *dnsPayload += 2;

        // Parse TTL (next 4 bytes)
        uint32_t ttl;
        memcpy(&ttl, *dnsPayload, sizeof(uint32_t));
        ttl = ntohl(ttl);  // Convert from network to host byte order (32-bit)
        *dnsPayload += 4;

        // Parse RDLENGTH (next 2 bytes)
        uint16_t rdlength;
        memcpy(&rdlength, *dnsPayload, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        *dnsPayload += 2;

         // Parse RDATA based on TYPE
        if (type == 1 && rdlength == 4) {  // A record (IPv4 address)
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, *dnsPayload, ip, sizeof(ip));  // Convert to human-readable IPv4
            cout << name << " " << ttl << " IN A " << ip << endl;
        } else if (type == 28 && rdlength == 16) {  // AAAA record (IPv6 address)
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, *dnsPayload, ipv6, sizeof(ipv6));  // Convert to human-readable IPv6
            cout << name << " " << ttl << " IN AAAA " << ipv6 << endl;
        } else if (type == 2) {  // NS record (Name server)
            string domain;
            const u_char* ns_pointer = *dnsPayload;
            Monitor::parseDomainName(ns_pointer, message, domain);  // Function to resolve compressed names
            cout << name << " " << ttl << " IN NS " << domain << endl;
        } else if (type == 15) {  // MX record (Mail exchange)
            uint16_t preference;
            memcpy(&preference, *dnsPayload, sizeof(uint16_t));
            preference = ntohs(preference);
            *dnsPayload += 2;

            string mxDomain;
            const u_char* mx_pointer = *dnsPayload;
            Monitor::parseDomainName(mx_pointer, message, mxDomain);  // Resolve the MX domain name
            cout << name << " " << ttl << " IN MX " << preference << " " << mxDomain << endl;
        } else if (type == 41) {  // OPT record (EDNS)
            cout << name << " " << ttl << " IN OPT (EDNS)" << endl;
        } 
        
        else {
            cout << name << " " << ttl << " IN " << type << " (unhandled type)" << endl;
        }

        *dnsPayload += rdlength;  // Move pointer past the RDATA
    }

}

void Monitor::packetCallback(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    callback_args* data = reinterpret_cast<callback_args*>(args);

     // Parse the IP header
    struct ip* ipHeader = (struct ip*)(packet + sizeof(ether_header));
    char srcIp[INET_ADDRSTRLEN], dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

    // Parse UDP header (assuming UDP transport for DNS)
    struct udphdr* udpHeader = (struct udphdr*)(packet + sizeof(ether_header) + sizeof(iphdr));

    // Parse DNS header
    DNSHeader* dnsHeader = Monitor::parseDNSHeader(packet);
    dnsHeader->id = ntohs(dnsHeader->id);
    dnsHeader->flags = ntohs(dnsHeader->flags);
    dnsHeader->qdcount = ntohs(dnsHeader->qdcount);
    dnsHeader->ancount = ntohs(dnsHeader->ancount);
    dnsHeader->nscount = ntohs(dnsHeader->nscount);
    dnsHeader->arcount = ntohs(dnsHeader->arcount);

    // Convert timestamp to human-readable format
    char timestamp[64];
    
    time_t t = header->ts.tv_sec;
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&t));

    // Default mode output
    if (!data->verbose) {
        cout << timestamp << " " << srcIp << " -> " << dstIp << " ("
                  << (dnsHeader->flags & 0x8000 ? "R" : "Q") << " "
                  << dnsHeader->qdcount << "/" << dnsHeader->ancount << "/"
                  << dnsHeader->nscount << "/" << dnsHeader->arcount << ")"<< endl;
        return;
    }

    // Verbose mode output
    if (data->verbose) {
        cout << "Timestamp: " << timestamp << endl;
        cout << "SrcIP: " << srcIp << endl;
        cout << "DstIP: " << dstIp << endl;

        // Print source and destination port
        cout << "SrcPort: UDP/" << ntohs(udpHeader->uh_sport) << endl;
        cout << "DstPort: UDP/" << ntohs(udpHeader->uh_dport) << endl;

        stringstream ss;
        ss << hex << dnsHeader->id;
        // DNS details
        cout << "Identifier: " << "0x" << Monitor::toUpper(ss.str()) << endl;

        // Flags
        cout << "Flags: QR=" << ((dnsHeader->flags & 0x8000) >> 15)
                  << ", OPCODE=" << ((dnsHeader->flags & 0x7800) >> 11)
                  << ", AA=" << ((dnsHeader->flags & 0x0400) >> 10)
                  << ", TC=" << ((dnsHeader->flags & 0x0200) >> 9)
                  << ", RD=" << ((dnsHeader->flags & 0x0100) >> 8)
                  << ", RA=" << ((dnsHeader->flags & 0x0080) >> 7)
                  << ", AD=" << ((dnsHeader->flags & 0x0020) >> 5)
                  << ", CD=" << ((dnsHeader->flags & 0x0010) >> 4)
                  << ", RCODE=" << (dnsHeader->flags & 0x000F) << endl;

        // Print section counts
        const u_char* dnsHeader_p = packet + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr);
        const u_char* dnsMessage = packet + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr);

        const u_char* dnsPayload = dnsHeader_p + sizeof(DNSHeader);

        cout << endl << "[Question Section]" << endl;
        for (int i = 0; i < dnsHeader->qdcount; i++) {

            // Parse QNAME
            string qname;
            while (*dnsPayload != 0) {  // Loop until we hit the 0 byte that ends the domain name
                int labelLength = *dnsPayload;  // First byte gives the length of the label
                dnsPayload++;
                // qname.append(reinterpret_cast<char*>(ptr), labelLength);  // Append the label
                qname.append(reinterpret_cast<const char*>(dnsPayload), labelLength);  // Append the label
                qname.append(".");  // Append a dot after each label
                dnsPayload += labelLength;  // Move the pointer forward by the label length
            }
            dnsPayload++;  // Skip the null terminator (0x00)

            // Parse QTYPE (next 2 bytes)
            uint16_t qtype;
            memcpy(&qtype, dnsPayload, sizeof(uint16_t));
            qtype = ntohs(qtype);  // Convert from network to host byte order
            dnsPayload += 2;

            // Parse QCLASS (next 2 bytes)
            uint16_t qclass;
            memcpy(&qclass, dnsPayload, sizeof(uint16_t));
            qclass = ntohs(qclass);  // Convert from network to host byte order
            dnsPayload += 2;

            // Print the question in the format "example.com. IN A"
            cout << qname;
        
        // Print QCLASS
        if (qclass == 1) {  // 1 is IN (Internet)
            cout << " IN";
        } else {
            cout << " " << qclass;  // Print raw QCLASS if it's not IN
        }

        // Print QTYPE
        switch (qtype) {
            case 1:
                cout << " A";  // QTYPE 1 is A (IPv4 address)
                break;
            case 2:
                cout << " NS";  // QTYPE 2 is NS (Name server)
                break;
            case 28:
                cout << " AAAA";  // QTYPE 28 is AAAA (IPv6 address)
                break;
            case 15:
                cout << " MX";  // QTYPE 15 is MX (Mail exchange)
                break;
            default:
                cout << " " << qtype;  // Print raw QTYPE if not recognized
                break;
        }
        cout << endl;
    }

    cout << endl << "[Answer Section]" << endl;
    // Parse the Answer Section
    Monitor::parseResourceRecords(&dnsPayload, dnsHeader->ancount, dnsMessage);

    cout << endl << "[Authority Section]" << endl;
    // Parse the Answer Section
    Monitor::parseResourceRecords(&dnsPayload, dnsHeader->nscount, dnsMessage);


    cout << endl << "[Additional Section]" << endl;
    // Parse the Answer Section
    Monitor::parseResourceRecords(&dnsPayload, dnsHeader->arcount, dnsMessage);
    

    cout << "====================" << endl << endl;

    // if (data->verbose) {
    //     cout << "Packet length: " << header->len << endl;
    // }
  
    //     // Example of reading or writing from/to the file streams
    // if (data->domains_file_stream && data->domains_file_stream->is_open()) {
    //     // Perform actions with the domains file stream
    // }

    // if (data->pcap_file_stream && data->pcap_file_stream->is_open()) {
    //     // Perform actions with the pcap file stream
    // }

    // if (data->translation_file_stream && data->translation_file_stream->is_open()) {
    //     // Perform actions with the translation file stream
    // }
    }
}