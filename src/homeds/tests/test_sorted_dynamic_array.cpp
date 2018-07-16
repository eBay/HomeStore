/**
 * Copyright eBay Inc 2018
 */
 
#include "homeds/array/sorted_dynamic_array.h"
#include "blkalloc/blk.h"
#include <sds_logging/logging.h>

SDS_LOGGING_INIT(sorted_dynamic_array)
SDS_OPTIONS_ENABLE(logging)

#define LOAD_PERCENT 80
#define GROWTH_PERCENT 20
#define INITIAL_CAPACITY 3

static const int NO_OF_WRITES = 10000;
static const int ELEMENT_RANGE = 100000;

int main(int argc, char *argv[]) {
    
    SDS_OPTIONS_LOAD(argc, argv, logging)
    sds_logging::SetLogger(spdlog::stdout_color_mt("test_Sorted_Dynamic_Array"));
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    
    homeds::Sorted_Dynamic_Array<uint64_t ,LOAD_PERCENT,GROWTH_PERCENT> sda(INITIAL_CAPACITY);
    bool taken[ELEMENT_RANGE];
    uint64_t elements[NO_OF_WRITES];
    
    int i=0;
    while(i<NO_OF_WRITES){
        //find next element
        uint64_t to_take = rand() % ELEMENT_RANGE;
        if(taken[to_take]) continue;
        taken[to_take]=true;
       
        assert(sda.addOrUpdate(&to_take));
        elements[i] = to_take;
        
        i++;
    }

    i=0;
    while(i<NO_OF_WRITES){
        uint64_t* element = &elements[i];
        assert(sda.get(element));
        i++;
    }
    LOGINFO("Success - Test sorted dynamic array");
    
}