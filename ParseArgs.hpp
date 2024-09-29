#ifndef PARSE_H
#define PARSE_H

#include <iostream>
// #include <fstream>
#include <getopt.h>


using namespace std;

extern struct option long_options[];

class Parse {
    public:
        // adawdwadaw
        Parse(int argc, char *argv[]);

        void parseArguments();

        bool isVerbose() { return verbose; }
        string getInterface() { return interface; }
        string getPcapFile() { return pcap_file; }
        string getDomainsFile() { return domains_file; }
        string getTranslationFile() { return translation_file; }

    private:
        int argc;
        char **argv;
        bool verbose;
        string interface;
        string pcap_file;
        string domains_file;
        string translation_file;

        // ifstream pcap_file_stream;
        // ifstream domains_file_stream;
        // ifstream translation_file_stream;
};

#endif // PARSE_H