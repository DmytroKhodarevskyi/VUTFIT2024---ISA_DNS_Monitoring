/**
 * @file: ParseArgs.cpp
 * @author: Dmytro Khodarevskyi
 * @login: xkhoda01
 * @brief: Parse command line arguments and capture necessary data, exit if error
 */

#include "ParseArgs.hpp"

using namespace std;

struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"pcap-file", required_argument, 0, 'p'},
    {"translations-file", required_argument, 0, 't'},
    {"domains-file", required_argument, 0, 'd'},
    {"verbose", no_argument, 0, 'v'},
    {"verbose", no_argument, 0, 'm'},
    {0, 0, 0, 0}};

Parse::Parse(int argc, char *argv[]) : argc(argc),
                                       argv(argv),
                                       verbose(false),
                                       list_monitors(false),
                                       interface(""),
                                       pcap_file(""),
                                       domains_file(""),
                                       translation_file("")
{
}

void Parse::parseArguments()
{
    int opt;
    int option_index = 0;
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "i:p:vmd:t:", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'i':
            interface = optarg;
            break;
        case 'p':
            pcap_file = optarg;
            break;
        case 'd':
            domains_file = optarg;
            break;
        case 't':
            translation_file = optarg;
            break;
        case '?':
            break;
        case 'v':
            verbose = true;
            break;
        case 'm':
            list_monitors = true;
            break;
        default:
            fprintf(stderr, "Usage: %s [-i interface] [-p pcap-file] [-d domains-file] [-t translations-file] [-v]\n", argv[0]);
        }
    }

    if (list_monitors)
    {
        return;
    }

    if (interface == "" && pcap_file == "")
    {
        fprintf(stderr, "Usage: %s [-i interface] [-p pcap-file] [-d domains-file] [-t translations-file] [-v]\n", argv[0]);
        exit(1);
    }

    if (interface != "" && pcap_file != "")
    {
        fprintf(stderr, "Usage: %s [-i interface] [-p pcap-file] [-d domains-file] [-t translations-file] [-v]\n", argv[0]);
        exit(1);
    }
}

string Parse::getSource()
{
    if (interface != "")
    {
        return interface;
    }
    else
    {
        return pcap_file;
    }
}