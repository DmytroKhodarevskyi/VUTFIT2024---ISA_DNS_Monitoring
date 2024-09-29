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
    std::time_t t = header->ts.tv_sec;
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

    // Default mode output
    if (!data->verbose) {
        std::cout << timestamp << " " << srcIp << " -> " << dstIp << " "
                  << (dnsHeader->flags & 0x8000 ? "R" : "Q") << " "
                  << dnsHeader->qdcount << "/" << dnsHeader->ancount << "/"
                  << dnsHeader->nscount << "/" << dnsHeader->arcount << std::endl;
        return;
    }

    // Verbose mode output
    if (data->verbose) {
        std::cout << "Timestamp: " << timestamp << std::endl;
        std::cout << "SrcIP: " << srcIp << std::endl;
        std::cout << "DstIP: " << dstIp << std::endl;

        // Print source and destination port
        std::cout << "SrcPort: UDP/" << ntohs(udpHeader->uh_sport) << std::endl;
        std::cout << "DstPort: UDP/" << ntohs(udpHeader->uh_dport) << std::endl;

        stringstream ss;
        ss << std::hex << dnsHeader->id;
        // DNS details
        std::cout << "Identifier: " << "0x" << Monitor::toUpper(ss.str()) << std::endl;

        // Flags
        std::cout << "Flags: QR=" << ((dnsHeader->flags & 0x8000) >> 15)
                  << ", OPCODE=" << ((dnsHeader->flags & 0x7800) >> 11)
                  << ", AA=" << ((dnsHeader->flags & 0x0400) >> 10)
                  << ", TC=" << ((dnsHeader->flags & 0x0200) >> 9)
                  << ", RD=" << ((dnsHeader->flags & 0x0100) >> 8)
                  << ", RA=" << ((dnsHeader->flags & 0x0080) >> 7)
                  << ", AD=" << ((dnsHeader->flags & 0x0020) >> 5)
                  << ", CD=" << ((dnsHeader->flags & 0x0010) >> 4)
                  << ", RCODE=" << (dnsHeader->flags & 0x000F) << std::endl;

        // Print section counts
        std::cout << "[Question Section] (" << dnsHeader->qdcount << " records)" << std::endl;
        std::cout << "[Answer Section] (" << dnsHeader->ancount << " records)" << std::endl;
        std::cout << "[Authority Section] (" << dnsHeader->nscount << " records)" << std::endl;
        std::cout << "[Additional Section] (" << dnsHeader->arcount << " records)" << std::endl;

        std::cout << "====================" << std::endl;
    }

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