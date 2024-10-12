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

    // if (parse.getInterface() != "") {
    //     Monitor monitor(parse.getInterface());
    // } else {
    //     Monitor monitor(parse.getPcapFile());
    // }

    // Monitor monitor(parse.getInterface());
    Monitor monitor(parse.getSource());

    // if (parse.getPcapFile() != "") {
    //     monitor.pcap_file_stream.open(parse.getPcapFile());
    //     if (!monitor.pcap_file_stream.is_open()) {
    //         cerr << "Could not open pcap file " << parse.getPcapFile() << endl;
    //         exit(1);
    //     }
    // }

    // if (parse.getTranslationFile() != "") {
    //     monitor.translation_file_stream.open(parse.getTranslationFile());
    //     if (!monitor.translation_file_stream.is_open()) {
    //         cerr << "Could not open translation file " << parse.getTranslationFile() << endl;
    //         exit(1);
    //     }
    // }

    // if (parse.getDomainsFile() != "") {
    //     monitor.domains_file_stream.open(parse.getDomainsFile());
    //     if (!monitor.domains_file_stream.is_open()) {
    //         cerr << "Could not open domains file " << parse.getDomainsFile() << endl;
    //         exit(1);
    //     }
    // }

    monitor.domains_file_name = parse.getDomainsFile();
    monitor.translation_file_name = parse.getTranslationFile();

    monitor.verbose = parse.isVerbose();

    // monitor.list_active_interfaces();
    monitor.capture();


    return 0;
}