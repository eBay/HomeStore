/**
 * Copyright eBay Inc 2018
 */

#include "homeds/array/sorted_dynamic_array.h"
#include "blkalloc/blk.h"
#include <sds_logging/logging.h>

#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

SDS_LOGGING_INIT(sorted_dynamic_array)
SDS_OPTIONS_ENABLE(logging)

#define LOAD_PERCENT 90
#define GROWTH_PERCENT 30
#define INITIAL_CAPACITY 5

static const int NO_OF_WRITES = 1000;
static const int ELEMENT_RANGE = 100000;


int main(int argc, char *argv[]) {

    SDS_OPTIONS_LOAD(argc, argv, logging)
    sds_logging::SetLogger(spdlog::stdout_color_mt("test_Sorted_Dynamic_Array"));
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    homeds::Sorted_Dynamic_Array<uint64_t, LOAD_PERCENT, GROWTH_PERCENT> sda(INITIAL_CAPACITY);
    bool taken[ELEMENT_RANGE] = {0};
    uint64_t elements[NO_OF_WRITES];

    int i = 0;
    while (i < NO_OF_WRITES) {
        //find next element
        uint64_t to_take = rand() % ELEMENT_RANGE;
        if (taken[to_take]) { continue; }
        taken[to_take] = true;

        sda.addOrUpdate(&to_take);

        elements[i] = to_take;
        i++;
    }
    assert(sda.get_no_of_elements_filled() == 1000);

    auto func = [](homeds::Sorted_Dynamic_Array<uint64_t, LOAD_PERCENT, GROWTH_PERCENT> &sda) {
        //validate all elements are sorted
        int i = sda.get_no_of_elements_filled() - 1;
        while (i >= 1) {
            if (*sda[i] < *sda[i - 1]) {
                assert(0);
            }
            i--;
        }
    };
    func(sda);

    i = 0;
    while (i < NO_OF_WRITES) {
        uint64_t *element = &elements[i];
        assert(sda.get(element));
        i++;
    }

    i = 0;
    while (i < NO_OF_WRITES) {
        uint64_t *element = &elements[i];
        assert(sda.removeIfPresent(element));
        i++;
    }
    assert(sda.get_no_of_elements_filled() == 0);

    LOGINFO("Success - Test sorted dynamic array");

}


