#ifndef MONITOR_H
#define MONITOR_H

#include <iostream>

#include <fstream>

#include <pcap.h>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <typeinfo>
#include <cstring>
#include <bitset>
#include <math.h>
#include <time.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

#include <iomanip>
#include <ctime>
#include <resolv.h> // For DNS headers

using namespace std;

class Monitor
{
public:
    /**
     * @brief Construct a new Sniffer object with device
     */
    Monitor(const string &device);

    // Monitor(const string& device);

    /**
     * @brief Construct a new Sniffer object (only for listing interfaces)
     */
    Monitor();

    /**
     * @brief Destroy the Sniffer object
     */
    ~Monitor();

    /**
     * @brief Capture packets
     */
    void capture();

    /**
     * @brief List active interfaces
     */
    void list_active_interfaces();

    // ifstream pcap_file_stream;
    ifstream domains_file_stream;
    ifstream translation_file_stream;

    string domains_file_name;
    string translation_file_name;

    bool verbose;

private:
    struct callback_args
    {
        string domains_file_name;
        string translation_file_name;
        bool verbose;
    };

    static void printByte(const u_char byte);

    // static void addEntry(ifstream* file_stream, string entry);
    static void addEntry(const string &fileName, const string &entry);

    struct DNSHeader
    {
        uint16_t id;      // Identification number
        uint16_t flags;   // Flags (QR, Opcode, etc.)
        uint16_t qdcount; // Number of entries in Question section
        uint16_t ancount; // Number of entries in Answer section
        uint16_t nscount; // Number of entries in Authority section
        uint16_t arcount; // Number of entries in Additional section
    };

    enum Types
    {
        A = 1,
        AAAA = 28,
        NS = 2,
        MX = 15,
        EDNS = 41,
        SOA = 6,
        CNAME = 5,
        SRV = 33
    };

    static DNSHeader *parseDNSHeader(const u_char *packet, bool isIPv6);

    static void parseResourceRecords(const u_char **dnsPayload, uint16_t rrcount, const u_char *message, string domains_file_name,
                                     string translation_file_name, bool verbose);

    // static void parseCompressedName(const u_char** ptr, const u_char* dnsPayloadStart, string& name);

    static string toUpper(string str);

    /**
     * @brief Callback function for packet capturing and processing
     * @param args Arguments
     * @param header Packet header
     * @param packet Packet
     */
    static void packetCallback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    // static void parseDomainName(const u_char *&dnsPointer, const u_char *messageStart, string &domainName, string domains_file_name);
    static void parseDomainName(const u_char **dnsPointer, const u_char *messageStart, string &domainName, string domains_file_name);

    string device_;
    pcap_t *handle_;
    bool list_interfaces_;
};

#endif // MONITOR_H