// Disabled entry stub when nexus is built without the http-client feature.
import std;

extern "C" auto nexus_tools_fetch_entry(int, char**) -> int {
    std::cerr << "nexus tools fetch requires the http-client build feature\n";
    return 1;
}
