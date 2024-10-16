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

    // Set a filter (optional, applies for both file and live capture)
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

Monitor::DNSHeader *Monitor::parseDNSHeader(const u_char *packet)
{
    return (DNSHeader *)(packet + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr));
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
// void Monitor::parseDomainName(const u_char *&dnsPointer, const u_char *messageStart, std::string &domainName, string domains_file_name)
{
    int jump = 0;
    const u_char *start = *dnsPointer;
    // int i = 0;
    // while (*dnsPointer != 0)
    bool compression = false;
    while (**dnsPointer != 0)
    {
        // i++;

        // if ((*dnsPointer & 0xC0) == 0xC0)
        if ((**dnsPointer & 0xC0) == 0xC0)
        { // Check for compression
            compression = true;
            // uint16_t offset = ntohs(*reinterpret_cast<const uint16_t *>(dnsPointer)) & 0x3FFF;
            uint16_t offset = ntohs(*reinterpret_cast<const uint16_t *>(*dnsPointer)) & 0x3FFF;
            // dnsPointer = messageStart + offset; // Follow the pointer
            *dnsPointer = messageStart + offset; // Follow the pointer

            jump += 2;
        }
        else
        {
            // int labelLength = *dnsPointer;
            int labelLength = **dnsPointer;
            // dnsPointer++;
            (*dnsPointer)++;
            if (!compression)
                jump++;
            // domainName.append(reinterpret_cast<const char *>(dnsPointer), labelLength);
            domainName.append(reinterpret_cast<const char *>(*dnsPointer), labelLength);
            domainName.append(".");
            // dnsPointer += labelLength;
            *dnsPointer += labelLength;
            if (!compression)
                jump += labelLength;
        }
    }

    *dnsPointer = start + jump;

    if (!domainName.empty() && domainName.back() == '.')
    {
        domainName.pop_back(); // Remove trailing dot
        if (domains_file_name != "")
        {
            // Remove the trailing dot
            Monitor::addEntry(domains_file_name, domainName);
        }
    }
}

void Monitor::parseResourceRecords(const u_char **dnsPayload, uint16_t rrcount, const u_char *message,
                                   string domains_file_name, string translation_file_name, bool verbose)
{

    for (int i = 0; i < rrcount; i++)
    {

        // cerr << "ANSER N: " << i << endl;

        const u_char *name_pointer = *dnsPayload;

        // cerr << "-------------------" << endl;
        // printByte(*name_pointer);
        // printByte(*(name_pointer+1));
        // printByte(*(name_pointer+2));
        // cerr << "-------------------" << endl;

        unsigned char FirstTwo = **dnsPayload & 0xC0;

        // printByte(**dnsPayload);

        if (FirstTwo == 0xC0)
        {
            // Extract the offset
            uint16_t offset = ntohs(*reinterpret_cast<const uint16_t *>(*dnsPayload)) & 0x3FFF;
            // Get the pointer to the compressed name
            name_pointer = message + offset;
            // Move the pointer forward by 2 bytes
            *dnsPayload += 2;
        }
        else
        {
            // Move the pointer forward by 1 byte
            *dnsPayload += 1;
        }

        string name;

        while (*name_pointer != 0)
        {
            int labelLength = *name_pointer;

            name_pointer++;

            name.append(reinterpret_cast<const char *>(name_pointer), labelLength);
            name.append(".");

            name_pointer += labelLength;

            // Nested compression
            if (*name_pointer == 0xC0)
            {
                uint16_t offset = ntohs(*reinterpret_cast<const uint16_t *>(name_pointer)) & 0x3FFF;
                name_pointer = message + offset;
            }
        }

        name_pointer++; // Skip the null terminator (0x00)

        if (domains_file_name != "")
        {
            // Remove the trailing dot
            Monitor::addEntry(domains_file_name, name.substr(0, name.size() - 1));
        }

        uint16_t type;
        memcpy(&type, *dnsPayload, sizeof(uint16_t));
        type = ntohs(type);

        *dnsPayload += 2;

        // Parse CLASS (next 2 bytes)
        uint16_t rclass;
        memcpy(&rclass, *dnsPayload, sizeof(uint16_t));
        rclass = ntohs(rclass);
        *dnsPayload += 2;

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
                cout << name << " " << ttl << " IN A " << ip << endl;

            string entry = name.substr(0, name.size() - 1) + " " + ip;
            if (translation_file_name != "")
                Monitor::addEntry(translation_file_name, entry);
        }
        else if (type == AAAA && rdlength == 16)
        { // AAAA record (IPv6 address)
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, *dnsPayload, ipv6, sizeof(ipv6)); // Convert to human-readable IPv6
            if (verbose)
                cout << name << " " << ttl << " IN AAAA " << ipv6 << endl;

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
                cout << name << " " << ttl << " IN NS " << domain << endl;
        }
        else if (type == MX)
        { // MX record (Mail exchange)
            uint16_t preference;
            memcpy(&preference, *dnsPayload, sizeof(uint16_t));
            preference = ntohs(preference);
            *dnsPayload += 2;

            string mxDomain;
            const u_char *mx_pointer = *dnsPayload;

            // cerr << "-------------------" << endl;
            // printByte(*mx_pointer);
            // printByte(*(mx_pointer+1));
            // printByte(*(mx_pointer+2));
            // cerr << "-------------------" << endl;

            Monitor::parseDomainName(&mx_pointer, message, mxDomain, domains_file_name); // Resolve the MX domain name
            if (verbose)
                cout << name << " " << ttl << " IN MX " << preference << " " << mxDomain << endl;

            // (*dnsPayload)--;
            *dnsPayload -= 2;
        }
        else if (type == EDNS)
        { // OPT record (EDNS)
            if (verbose)
                cout << name << " " << ttl << " IN OPT (EDNS)" << endl;
        }
        else if (type == SOA) // SOA
        {
            string mname, rname;
            const u_char *soa_pointer = *dnsPayload;
            Monitor::parseDomainName(&soa_pointer, message, mname, domains_file_name); // Resolve the MNAME domain name
            soa_pointer += 1;

            // cerr << "first-------------------" << endl;
            // printByte(*soa_pointer);
            // printByte(*(soa_pointer+1));
            // printByte(*(soa_pointer+2));
            // cerr << "-------------------" << endl;

            Monitor::parseDomainName(&soa_pointer, message, rname, domains_file_name); // Resolve the RNAME domain name

            uint32_t serial, refresh, retry, expire, minimum;
            memcpy(&serial, soa_pointer, sizeof(uint32_t));
            serial = ntohl(serial);
            soa_pointer += 4;
            memcpy(&refresh, soa_pointer, sizeof(uint32_t));
            refresh = ntohl(refresh);
            soa_pointer += 4;
            memcpy(&retry, soa_pointer, sizeof(uint32_t));
            refresh = ntohl(retry);
            soa_pointer += 4;
            memcpy(&expire, soa_pointer, sizeof(uint32_t));
            expire = ntohl(expire);
            soa_pointer += 4;
            memcpy(&minimum, soa_pointer, sizeof(uint32_t));
            minimum = ntohl(minimum);
            soa_pointer += 4;
            if (verbose)
                cout << name << " " << ttl << " IN SOA " << mname << " " << rname << " " << serial << " " << refresh << " " << retry << " " << expire << " " << minimum << endl;
        }
        else if (type == CNAME)
        {

            string cname;
            const u_char *cname_pointer = *dnsPayload;

            Monitor::parseDomainName(&cname_pointer, message, cname, domains_file_name); // Resolve the MX domain name

            if (verbose)
                cout << name << " " << ttl << " IN CNAME " << cname << endl;
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

            if (verbose)
                cout << name << " " << ttl << " IN SRV " << priority << " "
                     << weight << " "
                     << port << " "
                     << target << " "
                     << endl;

            cerr << "-------------------" << endl;
            printByte(**dnsPayload);
            printByte(*(*dnsPayload + 1));
            printByte(*(*dnsPayload + 2));
            cerr << "-------------------" << endl;
        }
        else
        {
            if (verbose)
                cout << name << " " << ttl << " IN " << type << "(unhadled type)" << endl;
        }

        *dnsPayload += rdlength; // Move pointer past the RDATA

    }
}

void Monitor::addEntry(const string &fileName, const string &entry)
{
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

string Monitor::resolveDomainToIP(const string &domain)
{

    struct addrinfo hints, *res;
    int status;
    char ipstr[INET6_ADDRSTRLEN]; // Buffer to hold the IP string (both IPv4 and IPv6)

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET for IPv4, AF_INET6 for IPv6, AF_UNSPEC for either
    hints.ai_socktype = SOCK_STREAM;

    // Resolve the domain name to IP
    if ((status = getaddrinfo(domain.c_str(), NULL, &hints, &res)) != 0)
    {
        return "";
    }

    // Check the first result in the list
    void *addr;
    if (res->ai_family == AF_INET)
    { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
    }
    else if (res->ai_family == AF_INET6)
    { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
    }
    else
    {
        freeaddrinfo(res);
        return ""; // Unsupported address family
    }

    // Convert the IP to a string and store it in ipstr
    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);

    freeaddrinfo(res); // Free the result list

    return string(ipstr); // Return the IP address as a string
}

void Monitor::packetCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // cout << "catched a packet" << endl;
    // return;

    callback_args *data = reinterpret_cast<callback_args *>(args);

    // Parse the IP header
    struct ip *ipHeader = (struct ip *)(packet + sizeof(ether_header));
    char srcIp[INET_ADDRSTRLEN], dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

    // Parse UDP header (assuming UDP transport for DNS)
    struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(ether_header) + sizeof(iphdr));

    // Parse DNS header
    DNSHeader *dnsHeader = Monitor::parseDNSHeader(packet);
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

    // Print section counts
    const u_char *dnsHeader_p = packet + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr);
    const u_char *dnsMessage = packet + sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr);

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

        // Print the question in the format "example.com. IN A"

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
                cout << " " << qtype; // Print raw QTYPE if not recognized
                break;
            }

            cout << endl;
        }

        if (data->domains_file_name != "")
        {
            // Remove the trailing dot
            Monitor::addEntry(data->domains_file_name, qname.substr(0, qname.size() - 1));
        }

        // Only resolve A, AAAA, and MX records
        if (data->translation_file_name != "" && (qtype == 1 || qtype == 28))
        {
            string entry = qname.substr(0, qname.size() - 1) + " " + Monitor::resolveDomainToIP(qname);
            Monitor::addEntry(data->translation_file_name, entry); // Remove the trailing dot
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