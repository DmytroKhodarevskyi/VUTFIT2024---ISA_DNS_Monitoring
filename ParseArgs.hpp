/**
 * @file: ParseArgs.hpp
 * @author: Dmytro Khodarevskyi
 * @login: xkhoda01
 * @brief: ParseArgs header
 */

#ifndef PARSE_H
#define PARSE_H

#include <iostream>
#include <getopt.h>

using namespace std;

extern struct option long_options[];

class Parse
{
public:
    /**
     * @brief Create Parse instance
     */
    Parse(int argc, char *argv[]);

    /**
     * @brief Parse command line arguments
     */
    void parseArguments();

    bool isVerbose() { return verbose; }

    bool isListMonitors() { return list_monitors; }

    string getSource();
    string getInterface() { return interface; }
    string getPcapFile() { return pcap_file; }
    string getDomainsFile() { return domains_file; }
    string getTranslationFile() { return translation_file; }

private:
    int argc;
    char **argv;
    bool verbose;
    bool list_monitors;
    string interface;
    string pcap_file;
    string domains_file;
    string translation_file;
};

#endif // PARSE_H