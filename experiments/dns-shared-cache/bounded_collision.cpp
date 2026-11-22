#include "bounded_table.hpp"
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <thread>

namespace dns_hp_experiment {
thread_local bool pause_reader=false,pause_writer=false;
std::atomic<bool> reader_ready=false,writer_ready=false,reader_resume=false,writer_resume=false;
void before_protect_for_test() {
    if (!pause_reader) return;
    pause_reader=false; reader_ready=true;
    while (!reader_resume.load()) std::this_thread::yield();
}
void before_tag_publish_for_test() {
    if (!pause_writer) return;
    pause_writer=false; writer_ready=true;
    while (!writer_resume.load()) std::this_thread::yield();
}
}
struct CollisionHash { auto operator()(dns_hp_experiment::Key const&) const noexcept -> std::size_t { return 42; } };
int main() {
    using namespace dns_hp_experiment;
    BoundedTable<Key,Answer,CollisionHash> table(2);
    Key old{1,"old.test",1},next{1,"new.test",1};
    auto value=[](Key const& key) { return Answer{key.name,{key.name},{},1000,1}; };
    if (!table.put(old,value(old))) return 1;
    std::optional<Answer> read_result;
    std::thread reader([&] {
        auto slot=table.reader(0);
        pause_reader=true; read_result=slot.get(next);
    });
    while (!reader_ready.load()) std::this_thread::yield();
    if (!table.erase(old)) std::abort();
    std::thread writer([&] {
        pause_writer=true;
        if (!table.put(next,value(next))) std::abort();
    });
    while (!writer_ready.load()) std::this_thread::yield();
    reader_resume=true; reader.join();
    auto saw_unpublished=read_result.has_value();
    writer_resume=true; writer.join();
    auto slot=table.reader(1);
    if (saw_unpublished || !slot.get(next)) return 2;
    std::cout<<"colliding slot does not reveal an unpublished replacement\n";
}
