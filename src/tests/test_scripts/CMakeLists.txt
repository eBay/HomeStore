file(COPY vol_test.py DESTINATION ${CMAKE_BINARY_DIR}/bin/scripts)
file(COPY home_blk_flip.py DESTINATION ${CMAKE_BINARY_DIR}/bin/scripts)
file(COPY home_blk_test.py DESTINATION ${CMAKE_BINARY_DIR}/bin/scripts)
file(COPY btree_test.py DESTINATION ${CMAKE_BINARY_DIR}/bin/scripts)
file(COPY log_meta_test.py DESTINATION ${CMAKE_BINARY_DIR}/bin/scripts)
#add_test(NAME TestVolRecovery COMMAND ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/)
#SET_TESTS_PROPERTIES(TestVolRecovery PROPERTIES DEPENDS TestVol)

#add_test(NAME PerfTestVol COMMAND perf_test_volume)
#add_test(NAME RecoveryVol COMMAND python vol_test.py)
#add_test(NAME CheckBtree COMMAND check_btree)

