import std;
import hysteria2.fragments;

auto nexus_run(int argc,char** argv) -> int;

auto main(int argc,char** argv) -> int {
    if(argc!=3)return 2;
    auto& budget=hysteria2::default_udp_memory_budget();
    auto amount=budget.limit();
    if(!budget.acquire(amount))return 3;
    std::thread control([&] {
        std::string command;
        (void)std::getline(std::cin,command);
        budget.release(amount);
        std::cerr<<"budget released used="<<budget.used()<<std::endl;
    });
    auto result=nexus_run(argc,argv);
    control.join();
    if(budget.used())return 4;
    return result;
}
