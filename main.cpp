#include "ParseArgs.hpp"
#include "Monitor.hpp"

using namespace std;

int main(int argc, char *argv[])
{
    Parse parse = Parse(argc, argv);
    parse.parseArguments();

    Monitor monitor(parse.getSource());

    monitor.domains_file_name = parse.getDomainsFile();
    monitor.translation_file_name = parse.getTranslationFile();

    monitor.verbose = parse.isVerbose();

    monitor.capture();

    return 0;
}