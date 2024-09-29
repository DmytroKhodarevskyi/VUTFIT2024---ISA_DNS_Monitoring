#include "ParseArgs.hpp"
#include "Monitor.hpp"

using namespace std;

int main(int argc, char *argv[]) {
    // Parse parse(argc, argv);
    Parse parse = Parse(argc, argv);
    parse.parseArguments();
    // cout << "Interface: " << parse.getInterface() << endl;
    // cout << "Pcap file: " << parse.getPcapFile() << endl;
    // cout << "Domains file: " << parse.getDomainsFile() << endl;
    // cout << "Translation file: " << parse.getTranslationFile() << endl;
    // cout << "Verbose: " << parse.isVerbose() << endl;

    Monitor monitor(parse.getInterface());

    if (parse.getTranslationFile() != "") {
        monitor.translation_file_stream.open(parse.getTranslationFile());
        if (!monitor.translation_file_stream.is_open()) {
            cerr << "Could not open translation file " << parse.getTranslationFile() << endl;
            exit(1);
        }
    }

    if (parse.getDomainsFile() != "") {
        monitor.domains_file_stream.open(parse.getDomainsFile());
        if (!monitor.domains_file_stream.is_open()) {
            cerr << "Could not open domains file " << parse.getDomainsFile() << endl;
            exit(1);
        }
    }

    if (parse.getPcapFile() != "") {
        monitor.pcap_file_stream.open(parse.getPcapFile());
        if (!monitor.pcap_file_stream.is_open()) {
            cerr << "Could not open pcap file " << parse.getPcapFile() << endl;
            exit(1);
        }
    }

    monitor.verbose = parse.isVerbose();

    // monitor.list_active_interfaces();
    monitor.capture();


    return 0;
}