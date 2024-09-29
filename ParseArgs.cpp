#include "ParseArgs.hpp"

using namespace std;

struct option long_options[] = {
    {"interface",         required_argument, 0, 'i'},
    {"pcap-file",       required_argument, 0, 'p'},
    {"translations-file",       required_argument, 0, 't'},
    {"domains-file",  required_argument, 0, 'd'},
    {"verbose",  no_argument, 0, 'v'},
    {0, 0, 0, 0}
};

Parse::Parse(int argc, char *argv[]) :
    argc(argc),
    argv(argv),
    verbose(false),
    interface(""),
    pcap_file(""),
    domains_file(""),
    translation_file("")
    {}

void Parse::parseArguments() {
  int opt;
  int option_index = 0;
  opterr = 0;
  while ((opt = getopt_long(argc, argv, "i:p:vd:t:", long_options, &option_index)) != -1) {
        switch (opt) {
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
            default:
                fprintf(stderr, "Usage: %s [-i interface] [-p pcap-file] [-d domains-file] [-t translations-file] [-v]\n", argv[0]);
        }

    }

    if (interface == "" && pcap_file == "") {
        fprintf(stderr, "Usage: %s [-i interface] [-p pcap-file] [-d domains-file] [-t translations-file] [-v]\n", argv[0]);
        exit(1);
    }

    // if (!domains_file.empty()) {
    //     domains_file_stream.open(domains_file);
    //     if (!domains_file_stream.is_open()) {
    //         cerr << "Could not open domains file: " << domains_file << endl;
    //         exit(1);
    //     }
    // }

    // if (!translation_file.empty()) {
    //     translation_file_stream.open(translation_file);
    //     if (!translation_file_stream.is_open()) {
    //         cerr << "Could not open translations file: " << translation_file << endl;
    //         exit(1);
    //     }
    // }

    // if (!pcap_file.empty()) {
    //     pcap_file_stream.open(pcap_file);
    //     if (!pcap_file_stream.is_open()) {
    //         cerr << "Could not open pcap file: " << pcap_file << endl;
    //         exit(1);
    //     }
    // }
}
