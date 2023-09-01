#include <boost/icl/split_interval_set.hpp>
// #include <boost/range/iterator_range.hpp>
#include <iostream>

namespace icl = boost::icl;

using Set = icl::split_interval_set< uint64_t >;
using Ival = Set::interval_type;

const uint64_t g_max_size = 2000;
bool insert_next_slot(Set& chunks, uint64_t size) {
    auto ins_ival = Ival::right_open(0, size);
    for (auto& exist_ival : chunks) {
        if (ins_ival.upper() <= exist_ival.lower()) { break; }
        ins_ival = Ival::right_open(exist_ival.upper(), exist_ival.upper() + size);
    }

    if (ins_ival.upper() > g_max_size) {
        std::cout << "Exceeded g_max_size, no more space for " << ins_ival << "\n";
        return false;
    } else {
        chunks.add(ins_ival);
        return true;
    }
}

void remove_nth_slot(Set& chunks, uint64_t nth_slot) {
    uint64_t slot{1};
    for (auto& l : chunks) {
        if (slot++ == nth_slot) {
            chunks.erase(l);
            return;
        }
    }
}

void print(Set& chunks, const std::string& hdr) {
    std::cout << "Chunks: " << hdr << "\n";
    for (auto& l : chunks) {
        std::cout << l << "\n";
    }
}

int main() {
    Set chunks;

#if 0
    auto l = [&chunk](uint64_t start, uint64_t end) {
        if (chunk.find({Ival::right_open(start, end)}) != m.end()) {
            std::cout << "Range already exists for " << start << "-" << end << "\n";
        } else {
            chunk.add({Ival::right_open(start, end)});
        }
    };
    
    l(0, 10);
    l(9, 20);
    l(30, 40);
    l(40, 50);
    l(50, 60);
#endif

    insert_next_slot(chunks, 1000);
    insert_next_slot(chunks, 500);
    insert_next_slot(chunks, 500);
    insert_next_slot(chunks, 1);
    print(chunks, "Initial insertion:1");

    chunks.erase(chunks.begin());
    print(chunks, "After free:1 first slot");

    insert_next_slot(chunks, 1);
    print(chunks, "Post free:1 insertion:2");

    insert_next_slot(chunks, 999);
    print(chunks, "Post free:1 insertion:3");

    remove_nth_slot(chunks, 4);
    print(chunks, "After free:2 4th slot");

    insert_next_slot(chunks, 400);
    print(chunks, "Post free:2 insertion:4");

    insert_next_slot(chunks, 999);
    print(chunks, "Post free:2 insertion:5 (attempted in excess)");

    remove_nth_slot(chunks, 2);
    print(chunks, "After free:3 2nd slot");

    insert_next_slot(chunks, 999);
    print(chunks, "Post free:3 insertion:6");

    insert_next_slot(chunks, 100);
    print(chunks, "Post free:3 insertion:7");

#if 0
    for (auto probe : { 23, 10, 13, 15, 34, 35 }) {
        std::cout << "\nprobe " << probe << ": ";

        auto p = m.equal_range(Ival::right_op(probe, probe));
        for (auto& it : boost::make_iterator_range(p)) {
            std::cout << it << " ";
        }
    }
#endif
}
