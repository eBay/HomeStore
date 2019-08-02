#include "homeds/loadgen/loadgen_common.hpp"
namespace homeds {
    namespace loadgen {
        template < typename K, typename V, typename Store, typename Executor >
        struct BtreeLoadGen {
            std::unique_ptr<KVGenerator<K,V,Store,Executor>> kvg;
            std::atomic<int64_t> stored_keys = 0, outstanding_create = 0, outstanding_others = 0;
            int CHECKPOINT_RANGE_BATCH_SIZE = 50;
            int UPDATE_RANGE_BATCH_SIZE=64;
            int QUERY_RANGE_BATCH_SIZE=32;
            std::mutex m_mtx;
            uint64_t NIO = 0, NK = 0, NRT = 0;//total ios and total keys
            int PC = 0, PR = 0, PU = 0, PD = 0, PRU=0, PRQ=0;//total % for op 
            uint64_t PRINT_INTERVAL = 0;//print interval in seconds
            int64_t WARM_UP_KEYS = 0;
            std::condition_variable m_cv;
            Clock::time_point startTime;
            Clock::time_point print_startTime;
            
            BtreeLoadGen(uint8_t n_threads, bool verification = true){
                kvg = std::make_unique<KVGenerator<K,V,Store,Executor>>(n_threads, verification);
            }
            std::atomic<int64_t> C_NC = 0, C_NR = 0, C_NU = 0, C_ND = 0, C_NRU = 0, C_NRQ = 0;//current op issued counter

            int64_t get_warmup_key_count(int percent) {
                return percent * WARM_UP_KEYS / 100;
            }

            int64_t get_existing_key_count(int percent) {
                return percent * kvg->get_keys_count() / 100;
            }

            Executor& get_executor(){
                return kvg->get_executor();
            }
            
            void do_checkpoint() {
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < get_existing_key_count(100); i += CHECKPOINT_RANGE_BATCH_SIZE) {
                        kvg->range_query(KeyPattern::SEQUENTIAL,
                                        CHECKPOINT_RANGE_BATCH_SIZE, true /* exclusive_access */, true, true);
                    }
                });
            }

            void do_inserts() {
                // preload random 50%
                kvg->preload(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, get_warmup_key_count(50));

                //insert sequential 50%
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < get_warmup_key_count(50); i++) {
                        kvg->insert_new(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES);
                    }
                });
            }

            void do_updates() {
                auto tenPer = get_existing_key_count(10);
                auto thirtyPer = get_existing_key_count(30);

                //update sequential 10%, from start
                kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < tenPer; i++) {
                        kvg->update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
                    }
                });

                //update sequential 10%, trailing
                kvg->reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < tenPer; i++) {
                        kvg->update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
                    }
                });

                //update random 30%
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < thirtyPer; i++) {
                        kvg->update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true);
                    }
                });
            }

            void do_removes() {
                auto tenPer = get_existing_key_count(10);
                auto thirtyPer = get_existing_key_count(30);

                //remove sequential 10% from start
                kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < tenPer; i++) {
                        kvg->remove(KeyPattern::SEQUENTIAL, true, true);
                    }
                });

                //remove trailing 10%
                kvg->reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < tenPer; i++) {
                        kvg->remove(KeyPattern::SEQUENTIAL, true, true);
                    }
                });

                //remove random 30%
                kvg->run_parallel([&]() {
                    for (auto i = 0u; i < thirtyPer; i++) {
                        kvg->remove(KeyPattern::UNI_RANDOM, true, true);
                    }
                });

                do_checkpoint();
                kvg->remove_all_keys();
            }

            void do_negative_tests() {
                //remove from empty set
                kvg->run_parallel([&]() {
                    kvg->remove(KeyPattern::UNI_RANDOM, false, false, nullptr, false);
                    kvg->update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, false, false, false);
                });
            }

            void initParam(int pC, int pR, int pU, int pD,int pRU, int pRQ, int64_t nIO, int64_t nRT, int64_t nK, 
                    int64_t pI, int64_t wUK,Clock::time_point sTime, Clock::time_point print_sTime) {
                this->PC = pC;
                this->PR = pR;
                this->PU = pU;
                this->PD = pD;
                this->PRU = pRU;
                this->PRQ = pRQ;
                this->NIO = nIO;
                this->NK = nK;
                this->NRT = nRT;
                this->PRINT_INTERVAL = pI;
                this->WARM_UP_KEYS = wUK;
                this->startTime=sTime;
                this->print_startTime=print_sTime;
                kvg->set_max_keys(NK);
                kvg->init_generator();
            }

            void warmup() {
                //basic serialized tests
                do_inserts();
                do_updates();
                do_removes();
                do_negative_tests();
            }

            void join(){
                std::unique_lock<std::mutex> lk(m_mtx);
                m_cv.wait(lk,[this]{return outstanding_create+outstanding_others==0;});
                
            }
            
            void insert_success_cb(int op=1) {
                std::unique_lock<std::mutex> lk(m_mtx);
                stored_keys+=op;
                outstanding_create-=op;
                m_cv.notify_one();
            }

            void remove_success_cb(int op=1) {
                std::unique_lock<std::mutex> lk(m_mtx);
                stored_keys-=op;
                outstanding_others-=op;
                m_cv.notify_one();
            }

            void read_update_success_cb(int op=1) {
                std::unique_lock<std::mutex> lk(m_mtx);
                if(op==0){
                    //range update succes cb
                    outstanding_others-=UPDATE_RANGE_BATCH_SIZE;
                }if(op==-1){
                    //range query succes cb
                    outstanding_others-=QUERY_RANGE_BATCH_SIZE;
                }else {
                    outstanding_others -= op;
                }
                m_cv.notify_one();
            }

            uint64_t get_elapsed_time(Clock::time_point stTime) {
                std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - stTime);
                return sec.count();
            }
            
            bool increment_create(){
                std::unique_lock<std::mutex> lk(m_mtx);
                if ((uint64_t)(stored_keys + outstanding_create) >= NK)return false;//cant accomodate more
                outstanding_create++;
                return true;
            }

            bool increment_other(int op=1){
                std::unique_lock<std::mutex> lk(m_mtx);
                if (stored_keys - outstanding_others < op)return false;//cannot accomodate more
                outstanding_others+=op;
                return true;
            }
            
            bool is_storedkey_watermark_reached(int watermark){
                std::unique_lock<std::mutex> lk(m_mtx);
                if(stored_keys + outstanding_create > watermark)return true;
                else return false;
            }

            int64_t get_issued_ios() {
                return C_NC + C_NR + C_NU + C_ND + C_NRU/UPDATE_RANGE_BATCH_SIZE + C_NRQ/QUERY_RANGE_BATCH_SIZE;
            }

            void try_create() {
                if (!increment_create())return;
                kvg->insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES,
                               std::bind(&BtreeLoadGen::insert_success_cb, this,std::placeholders::_1));
                C_NC++;
                try_print();
            }

            void try_read() {
                if (!increment_other())return;
                kvg->get(KeyPattern::UNI_RANDOM, true, true, true,
                        std::bind(&BtreeLoadGen::read_update_success_cb, this,std::placeholders::_1));
                C_NR++;
                try_print();
            }

            void try_update() {
                if (!increment_other())return;
                kvg->update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true, true,
                           std::bind(&BtreeLoadGen::read_update_success_cb, this, std::placeholders::_1));
                C_NU++;
                try_print();
            }
            
            void try_range_update() {
                if(!is_storedkey_watermark_reached(UPDATE_RANGE_BATCH_SIZE*2))return;
                while (!increment_other(UPDATE_RANGE_BATCH_SIZE)){
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;//if cannot accomodate, halt issue of any new ios and wait for pending ios to finish
                }
                kvg->range_update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES,UPDATE_RANGE_BATCH_SIZE,
                        true, true, true, std::bind(&BtreeLoadGen::read_update_success_cb, this, 
                                std::placeholders::_1));
                C_NRU+=UPDATE_RANGE_BATCH_SIZE;
                try_print();
            }

            void try_range_query() {
                if(!is_storedkey_watermark_reached(QUERY_RANGE_BATCH_SIZE*2))return;
                while (!increment_other(QUERY_RANGE_BATCH_SIZE)){
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;//if cannot accomodate, halt issue of any new ios and wait for pending ios to finish
                }
                kvg->range_query(KeyPattern::UNI_RANDOM, QUERY_RANGE_BATCH_SIZE,
                                  true, true, true, std::bind(&BtreeLoadGen::read_update_success_cb, this, 
                                          std::placeholders::_1));
                
                C_NRQ+=QUERY_RANGE_BATCH_SIZE;
                try_print();
            }

            void try_delete() {
                if (!increment_other())return;
                kvg->remove(KeyPattern::UNI_RANDOM, true, true,
                           std::bind(&BtreeLoadGen::remove_success_cb, this,std::placeholders::_1));
                C_ND++;
                try_print();
            }

            void try_print() {
                if (get_elapsed_time(print_startTime) > PRINT_INTERVAL) {
                    print_startTime = Clock::now();
                    
                    LOGINFO(
                            "stored_keys:{}, outstanding_create:{},"
                            " outstanding_others:{}, creates:{}, reads:{}, updates:{}, deletes:{}, "
                            "rangeupdate:{}, rangequery:{}, total_io:{}",
                            stored_keys, outstanding_create, outstanding_others, C_NC, 
                            C_NR, C_NU, C_ND, C_NRU/UPDATE_RANGE_BATCH_SIZE, C_NRQ/QUERY_RANGE_BATCH_SIZE,
                            get_issued_ios());
                }
            }

            void regression(bool remove_allowed,bool range_update_allowed,bool range_query_allowed) {
                kvg->run_parallel([&]() {
                    while (true) {
                        auto op = select_io();

                        if (op == 1)
                            try_create();
                        else if (op == 2)
                            try_read();
                        else if (op == 3)
                            try_update();
                        else if (op == 4) {
                            if (!remove_allowed) continue;
                            try_delete();
                        }else if( op ==5){
                            if(!range_update_allowed) continue;
                            try_range_update();
                        }else if( op ==6){
                            if(!range_query_allowed) continue;
                            try_range_query();
                        }else
                            assert(0);
                        
                        if ((uint64_t)get_issued_ios() > NIO || get_elapsed_time(startTime)>NRT)
                            break;
                    }
                });
                
                if(remove_allowed) kvg->remove_all_keys();
                join();
            }

            int8_t select_io() {
                int ran = rand() % 100;
                if (ran < PC)return 1;
                else if (ran < PR)return 2;
                else if (ran < PU)return 3;
                else if (ran < PD)return 4;
                else if (ran < PRU)return 5;
                else if (ran < PRQ)return 6;
                else
                    assert(0);
                return -1;
            }

        };

    }
}
