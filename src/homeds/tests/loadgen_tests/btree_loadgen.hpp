static uint64_t N=0;//total number of keys

static uint64_t get_io_count(int percent){
    return percent*N/100;
}
KVG kvg;

//template<typename KVG>
struct BtreeTestLoadGen : public ::testing::Test {
    KVG kvg;
    
    void do_checkpoint() {
        kvg.run_parallel([&]() {
            int batch = 50;
            for (auto i = 0u; i < get_io_count(100); i += batch) {
                kvg.range_query(KeyPattern::SEQUENTIAL, 
                        batch, true /* exclusive_access */, true, true);
            }
        });
    }

    void do_inserts() {
        // preload random 50%
        kvg.preload(KeyPattern::UNI_RANDOM, 
                ValuePattern::RANDOM_BYTES, get_io_count(50));

        //insert sequential 50%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(50); i++) {
                kvg.insert_new(KeyPattern::SEQUENTIAL, 
                        ValuePattern::RANDOM_BYTES);
            }
        });
    }

    void do_updates() {
        //update sequential 10%, from start
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.update(KeyPattern::SEQUENTIAL, 
                        ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        //update random 50%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(50); i++) {
                kvg.update(KeyPattern::UNI_RANDOM, 
                        ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        do_checkpoint();

        //update sequential 10%, trailing
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, get_io_count(90));
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.update(KeyPattern::SEQUENTIAL, 
                        ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        do_checkpoint();
    }

    void do_removes() {
        //remove sequential 10% from start
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        //remove random 30%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(30); i++) {
                kvg.remove(KeyPattern::UNI_RANDOM, true, true);
            }
        });

        //remove trailing 10%
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, get_io_count(90));
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        do_checkpoint();

        //remove all documents
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(50); i++) {
                kvg.remove(KeyPattern::UNI_RANDOM, true, true);
            }
        });
    }

    void do_negative_tests() {
        //remove from empty set, 5% random
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(5); i++) {
                kvg.remove(KeyPattern::UNI_RANDOM, false, false);
            }
        });

        //update  empty set, 5% random
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(5); i++) {
                kvg.update(KeyPattern::UNI_RANDOM, 
                        ValuePattern::RANDOM_BYTES, false, false);
            }
        });
    }

    void execute(){
        //basic serialized tests
        do_inserts();
        do_updates();
        do_removes();
        do_negative_tests();
        
        //TODO - add parallel tests
    }
};