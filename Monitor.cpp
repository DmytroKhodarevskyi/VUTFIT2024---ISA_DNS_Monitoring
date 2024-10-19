/**
 * @file: Monitor.cpp
 * @author: Dmytro Khodarevskyi
 * @login: xkhoda01
 * @brief: DNS Monitor body, toolset for packet capture and DNS parsing
 */

#include "Monitor.hpp"

Monitor::Monitor(const string &device) : domains_file_name(""), translation_file_name(""), device_(device)
{

    char errbuf[PCAP_ERRBUF_SIZE];

    // Check if source is a file (e.g., ends with ".pcap")
    if (device_.find(".pcap") != string::npos)
    {
        // Open PCAP file
        handle_ = pcap_open_offline(device_.c_str(), errbuf);
        if (handle_ == nullptr)
        {
            cerr << "Could not open file " << device_ << ": " << errbuf << endl;
            exit(1);
        }
    }
    else
    {
        // Open live capture device
        handle_ = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle_ == nullptr)
        {
            cerr << "Could not open device " << device_ << ": " << errbuf << endl;
            exit(1);
        }
    }

    string filter = "udp port 53";
    struct bpf_program fp;

    if (pcap_compile(handle_, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "Could not parse filter " << filter << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }

    if (pcap_setfilter(handle_, &fp) == -1)
    {
        cerr << "Could not install filter " << filter << ": " << pcap_geterr(handle_) << endl;
        exit(1);
    }

    pcap_freecode(&fp);
}

Monitor::Monitor()
{
    list_interfaces_ = true;
}

Monitor::~Monitor()
{
    if (!list_interfaces_ && handle_ != nullptr)
    {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

void Monitor::printByte(const u_char byte)
{
    std::ios oldState(nullptr);
    oldState.copyfmt(std::cerr); // Copy current formatting

    // Print to cerr with custom formatting
    std::cerr << "Ascii: " << byte << std::endl;
    std::cerr << "Decimal: " << std::dec << static_cast<int>(byte) << std::endl;
    std::cerr << "Hexadecimal: 0x" << std::hex
              << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << std::endl;

    // Restore the original formatting state of std::cerr
    std::cerr.copyfmt(oldState);
}

void Monitor::list_active_interfaces()
{
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // Print the list
    for (device = alldevs; device != NULL; device = device->next)
    {
        if (device->name)
            cout << device->name << endl;
    }

    // Free the device list
    if (alldevs != NULL)
        pcap_freealldevs(alldevs);
}

Monitor::DNSHeader *Monitor::parseDNSHeader(const u_char *packet, bool isIPv6)
{
    size_t ipHeaderSize = isIPv6 ? 40 : ((struct ip *)(packet + sizeof(ether_header)))->ip_hl * 4;
    const u_char *dnsHeader_p = packet + sizeof(ether_header) + ipHeaderSize + sizeof(udphdr);
    return (DNSHeader *)dnsHeader_p;
}

string Monitor::toUpper(string str)
{
    for (size_t i = 0; i < str.length(); i++)
    {
        str[i] = toupper(str[i]);
    }
    return str;
}

void Monitor::capture()
{
    callback_args data;
    data.domains_file_name = domains_file_name;
    data.translation_file_name = translation_file_name;
    data.verbose = verbose;

    pcap_loop(handle_, -1, packetCallback, reinterpret_cast<u_char *>(&data));
}

void Monitor::parseDomainName(const u_char **dnsPointer, const u_char *messageStart, std::string &domainName, string domains_file_name)
{
    string name;
    const u_char *name_pointer = *dnsPointer;
    bool jumped = false;

    while (true)
    {
        uint8_t length = *name_pointer;

        // Check if the label is compressed (starts with 0xC0)
        if ((length & 0xC0) == 0xC0)
        {
            uint16_t offset = ntohs(*reinterpret_cast<const uint16_t *>(name_pointer)) & 0x3FFF;
            name_pointer = messageStart + offset; // Jump to the offset location
            if (!jumped)
            {
                *dnsPointer += 2; // Only move the dnsPayload if this is the first jump
                jumped = true;
            }
        }
        else if (length == 0)
        {
            // End of the name (null terminator)
            if (!jumped)
            {
                *dnsPointer += 1; // Move past the null byte if no jump occurred
            }
            break;
        }
        else
        {
            // Regular (uncompressed) label
            name_pointer++; // Move past the length byte
            name.append(reinterpret_cast<const char *>(name_pointer), length);
            name.append(".");
            name_pointer += length; // Move forward by label length

            if (!jumped)
            {
                *dnsPointer += (length + 1); // Move the original pointer
            }
        }
    }

    domainName.append(name);

    if (domains_file_name != "")
    {
        Monitor::addEntry(domains_file_name, domainName.substr(0, domainName.size()-1));
    }

}

void Monitor::parseResourceRecords(const u_char **dnsPayload, uint16_t rrcount, const u_char *message,
                                   string domains_file_name, string translation_file_name, bool verbose)
{

    for (int i = 0; i < rrcount; i++)
    {

        string name;
        Monitor::parseDomainName(dnsPayload, message, name, domains_file_name); // Function to resolve compressed names

        // Parse TYPE (2 bytes)
        uint16_t type;
        memcpy(&type, *dnsPayload, sizeof(uint16_t));
        type = ntohs(type);
        *dnsPayload += 2;

        // Parse CLASS (next 2 bytes)
        uint16_t rclass;
        memcpy(&rclass, *dnsPayload, sizeof(uint16_t));
        rclass = ntohs(rclass);
        *dnsPayload += 2;
        string Class;
        if (rclass == 1) {
            Class = "IN";
        } else {
            Class = "(unhandled class)";
        }

        // Parse TTL (next 4 bytes)
        uint32_t ttl;
        memcpy(&ttl, *dnsPayload, sizeof(uint32_t));
        ttl = ntohl(ttl); // Convert from network to host byte order (32-bit)
        *dnsPayload += 4;

        // Parse RDLENGTH (next 2 bytes)
        uint16_t rdlength;
        memcpy(&rdlength, *dnsPayload, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        *dnsPayload += 2;

        // Parse RDATA based on TYPE
        if (type == A && rdlength == 4)
        { // A record (IPv4 address)
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, *dnsPayload, ip, sizeof(ip)); // Convert to human-readable IPv4
            if (verbose)
                cout << name << " " << ttl << " " << Class << " A " << ip << endl;

            string entry = name.substr(0, name.size() - 1) + " " + ip;
            if (translation_file_name != "")
                Monitor::addEntry(translation_file_name, entry);
        }
        else if (type == AAAA && rdlength == 16)
        { // AAAA record (IPv6 address)
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, *dnsPayload, ipv6, sizeof(ipv6)); // Convert to human-readable IPv6
            if (verbose)
                cout << name << " " << ttl << " " << Class << " AAAA " << ipv6 << endl;

            string entry = name.substr(0, name.size() - 1) + " " + ipv6;
            if (translation_file_name != "")
                Monitor::addEntry(translation_file_name, entry);
        }
        else if (type == NS)
        { // NS record (Name server)
            string domain;
            const u_char *ns_pointer = *dnsPayload;
            Monitor::parseDomainName(&ns_pointer, message, domain, domains_file_name); // Function to resolve compressed names
            if (verbose)
                cout << name << " " << ttl << " " << Class << " NS " << domain << endl;
        }
        else if (type == MX)
        { // MX record (Mail exchange)
            uint16_t preference;
            memcpy(&preference, *dnsPayload, sizeof(uint16_t));
            preference = ntohs(preference);
            *dnsPayload += 2;

            string mxDomain;
            const u_char *mx_pointer = *dnsPayload;

            Monitor::parseDomainName(&mx_pointer, message, mxDomain, domains_file_name); // Resolve the MX domain name
            if (verbose)
                cout << name << " " << ttl << " " << Class << " MX " << preference << " " << mxDomain << endl;

            *dnsPayload -= 2;
        }
        else if (type == EDNS)
        { // OPT record (EDNS)
            if (verbose)
                cout << name << " " << ttl << " " << Class << " OPT (EDNS)" << endl;
        }
        else if (type == SOA) // SOA
        {
            string mname, rname;
            const u_char *soa_pointer = *dnsPayload;
            Monitor::parseDomainName(&soa_pointer, message, mname, domains_file_name); // Resolve the MNAME domain name

            Monitor::parseDomainName(&soa_pointer, message, rname, domains_file_name); // Resolve the RNAME domain name

            uint32_t serial, refresh, retry, expire, minimum;
            memcpy(&serial, soa_pointer, sizeof(uint32_t));
            serial = ntohl(serial);
            soa_pointer += 4;
  
            memcpy(&refresh, soa_pointer, sizeof(uint32_t));
            refresh = ntohl(refresh);
            soa_pointer += 4;
  
            memcpy(&retry, soa_pointer, sizeof(uint32_t));
            retry = ntohl(retry);
            soa_pointer += 4;
  
            memcpy(&expire, soa_pointer, sizeof(uint32_t));
            expire = ntohl(expire);
            soa_pointer += 4;
  
            memcpy(&minimum, soa_pointer, sizeof(uint32_t));
            minimum = ntohl(minimum);
            soa_pointer += 4;
  
            if (verbose)
                cout << name << " " << ttl << " " << Class << " SOA " << mname << " " << rname << " " << serial << " " << refresh << " " << retry << " " << expire << " " << minimum << endl;
        }
        else if (type == CNAME)
        {

            string cname;
            const u_char *cname_pointer = *dnsPayload;

            Monitor::parseDomainName(&cname_pointer, message, cname, domains_file_name); // Resolve the MX domain name

            if (verbose)
                cout << name << " " << ttl << " " << Class << " CNAME " << cname << endl;
        }
        else if (type == SRV)
        {

            uint16_t priority;
            memcpy(&priority, *dnsPayload, sizeof(uint16_t));
            priority = ntohs(priority);
            uint16_t weight;
            memcpy(&weight, *dnsPayload, sizeof(uint16_t));
            weight = ntohs(weight);
            uint16_t port;
            memcpy(&port, *dnsPayload, sizeof(uint16_t));
            port = ntohs(port);

            string target;
            const u_char *target_pointer = *dnsPayload + 6;

            Monitor::parseDomainName(&target_pointer, message, target, domains_file_name); // Resolve the MX domain name

            if (domains_file_name != "")
            {
                if (target != "")
                    Monitor::addEntry(domains_file_name, target);
            }

            if (verbose)
                cout << name << " " << ttl << " " << Class << " SRV " << priority << " "
                     << weight << " "
                     << port << " "
                     << target << " "
                     << endl;

        }
        else
        {
            if (verbose)
                cout << name << " " << ttl << " " << Class << " " << type << " (unhandled type)" << endl;
        }

        *dnsPayload += rdlength; // Move pointer past the RDATA
    }
}

void Monitor::addEntry(const string &fileName, const string &entry)
{
    if (entry == "")
    {
        return;
    }

    fstream file_stream(fileName, ios::in | ios::out | ios::app);
    // ifstream file_stream(fileName); // Open the file in read mode to check for existing entry
    if (!file_stream.is_open())
    {
        cerr << "Could not open file: " << fileName << endl;
        return;
    }

    string line;
    bool entryExists = false;

    // Check if the entry already exists in the file
    while (getline(file_stream, line))
    {
        if (line == entry)
        {
            entryExists = true;
            break;
        }
    }

    file_stream.close(); // Close the file after reading

    // If the entry does not exist, append it to the file
    if (!entryExists)
    {
        ofstream append_file_stream(fileName, ios::app); // Open in append mode
        if (!append_file_stream.is_open())
        {
            cerr << "Could not open file for appending: " << fileName << endl;
            return;
        }

        append_file_stream << entry << endl;
        append_file_stream.close();
    }
}

void Monitor::packetCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    callback_args *data = reinterpret_cast<callback_args *>(args);

    // Determine if the packet is IPv4 or IPv6
    const struct ether_header *ethHeader = (struct ether_header *)packet;
    uint16_t ethType = ntohs(ethHeader->ether_type);

    char srcIp[INET6_ADDRSTRLEN], dstIp[INET6_ADDRSTRLEN];

    const u_char *ipPacket;
    size_t ipHeaderSize;

    if (ethType == ETHERTYPE_IP)
    { // IPv4
        const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        ipHeaderSize = ipHeader->ip_hl * 4; // Header length in bytes
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);
        ipPacket = packet + sizeof(struct ether_header) + ipHeaderSize;
    }
    else if (ethType == ETHERTYPE_IPV6)
    { // IPv6
        const struct ip6_hdr *ip6Header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        ipHeaderSize = 40; // Fixed size for IPv6 header
        inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcIp, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dstIp, INET6_ADDRSTRLEN);
        ipPacket = packet + sizeof(struct ether_header) + ipHeaderSize;
    }

    const struct udphdr *udpHeader = (struct udphdr *)ipPacket;

    bool isIPv6 = false;

    if (ethType == ETHERTYPE_IP)
        isIPv6 = false;
    else if (ethType == ETHERTYPE_IPV6)
        isIPv6 = true;

    // Parse DNS header
    DNSHeader *dnsHeader = Monitor::parseDNSHeader(packet, isIPv6);
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
    if (!data->verbose)
    {
        cout << timestamp << " " << srcIp << " -> " << dstIp << " ("
             << (dnsHeader->flags & 0x8000 ? "R" : "Q") << " "
             << dnsHeader->qdcount << "/" << dnsHeader->ancount << "/"
             << dnsHeader->nscount << "/" << dnsHeader->arcount << ")" << endl;
    }

    // Verbose mode output
    if (data->verbose)
    {
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
    }

    const u_char *dnsHeader_p;
    const u_char *dnsMessage;

    if (ethType == ETHERTYPE_IP)
    { // IPv4
        dnsHeader_p = packet + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr);
        dnsMessage = dnsHeader_p; // Point to the same location for now
    }
    else if (ethType == ETHERTYPE_IPV6)
    { // IPv6
        dnsHeader_p = packet + sizeof(ether_header) + 40 + sizeof(udphdr);
        dnsMessage = dnsHeader_p; // Point to the same location for now
    }

    const u_char *dnsPayload = dnsHeader_p + sizeof(DNSHeader);

    if (data->verbose)
        cout << endl
             << "[Question Section]" << endl;

    for (int i = 0; i < dnsHeader->qdcount; i++)
    {

        // Parse QNAME
        string qname;
        while (*dnsPayload != 0)
        {                                  // Loop until we hit the 0 byte that ends the domain name
            int labelLength = *dnsPayload; // First byte gives the length of the label
            dnsPayload++;
            // Append the label
            qname.append(reinterpret_cast<const char *>(dnsPayload), labelLength);
            // Append a dot after each label
            qname.append(".");
            // Move the pointer forward by the label length
            dnsPayload += labelLength;
        }
        dnsPayload++; // Skip the null terminator (0x00)

        // Parse QTYPE (next 2 bytes)
        uint16_t qtype;
        memcpy(&qtype, dnsPayload, sizeof(uint16_t));
        qtype = ntohs(qtype); // Convert from network to host byte order
        dnsPayload += 2;

        // Parse QCLASS (next 2 bytes)
        uint16_t qclass;
        memcpy(&qclass, dnsPayload, sizeof(uint16_t));
        qclass = ntohs(qclass); // Convert from network to host byte order
        dnsPayload += 2;

        if (data->verbose)
        {
            cout << qname;
            // Print QCLASS
            if (qclass == 1)
            { // 1 is IN (Internet)
                cout << " IN";
            }
            else
            {
                cout << " " << qclass; // Print raw QCLASS if it's not IN
            }

            // Print QTYPE
            switch (qtype)
            {
            case A:
                cout << " A";
                break;
            case NS:
                cout << " NS";
                break;
            case AAAA:
                cout << " AAAA";
                break;
            case MX:
                cout << " MX";
                break;
            case SOA:
                cout << " SOA";
                break;
            case CNAME:
                cout << " CNAME";
                break;
            default:
                cout << " " << qtype << " (unhandled type)"; // Print raw QTYPE if not recognized
                break;
            }

            cout << endl;
        }

        if (data->domains_file_name != "")
        {
            // Remove the trailing dot
            Monitor::addEntry(data->domains_file_name, qname.substr(0, qname.size() - 1));
        }
    }

    if (data->verbose)
        cout << endl
             << "[Answer Section]" << endl;
    // Parse the Answer Section
    Monitor::parseResourceRecords(&dnsPayload, dnsHeader->ancount, dnsMessage, data->domains_file_name,
                                  data->translation_file_name, data->verbose);

    if (data->verbose)
        cout << endl
             << "[Authority Section]" << endl;
    // Parse the Answer Section
    Monitor::parseResourceRecords(&dnsPayload, dnsHeader->nscount, dnsMessage, data->domains_file_name,
                                  data->translation_file_name, data->verbose);

    if (data->verbose)
        cout << endl
             << "[Additional Section]" << endl;
    // Parse the Answer Section
    Monitor::parseResourceRecords(&dnsPayload, dnsHeader->arcount, dnsMessage, data->domains_file_name,
                                  data->translation_file_name, data->verbose);

    if (data->verbose)
        cout << "====================" << endl
             << endl;
}