#!/usr/bin/env python3
## @file btree_test.py

import subprocess
import os
import sys
import getopt
import sys
import time
import random

sys.stdout.flush()
import requests

opts, args = getopt.getopt(sys.argv[1:], 'tdlme:',
                           ['test_suits=', 'dirpath=', 'op_list=', 'log_mods=', 'threads=', 'fibers=', 'preload_size=',
                            'op_list=', 'num_entries=', 'num_iters=', 'dev_list=', 'run_time='])
test_suits = ""
dirpath = "./"
op_list = ""
log_mods = ""
threads = " --num_threads=2"
fibers = " --num_fibers=2"
preload_size = "  --preload_size=262144" # 256K
num_entries = " --num_entries=2097152" # 2M
num_iters = " --num_iters=100000000"
run_time = " --run_time=14400" # 4 hours
dev_list = ""

for opt, arg in opts:
    if opt in ('-t', '--test_suits'):
        test_suits = arg
        print("testing suits (%s)" % arg)
    if opt in ('-d', '--dirpath'):
        dirpath = arg
        print("dir path (%s)" % arg)
    if opt in ('-l', '--op_list'):
        # --op_list='query:20 put:20 remove:20 range_update:20 range_remove=10'
        op_list = arg
        print("op list (%s)" % arg)
    if opt in ('-m', '--log_mods'):
        log_mods = arg
        print("log_mods (%s)" % arg)
    if opt in ('-f', '--fibers'):
        fibers = " --num_fibers=" + arg
        print("number of fibers per thread (%s)" % arg)
    if opt in ('-p', '--preload_size'):
        preload_size = " --preload_size=" + arg
        print("preload_size = (%s)" % arg)
    if opt in ('-t', '--threads'):
        threads = " --num_threads=" + arg
        print("number of threads (%s)" % arg)
    if opt in ('-n', '--num_entries'):
        num_entries = " --num_entries=" + arg
        print("number of entries (%s)" % arg)
    if opt in ('-i', '--num_iters'):
        num_iters = " --num_iters=" + arg
        print("number of iterations (%s)" % arg)
    if opt in ('-r', '--run_time'):
        run_time = " --run_time=" + arg
        print("total run time (%s)" % arg)
    if opt in ('-v', '--dev_list'):
        dev_list = arg
        print(("device list (%s)") % (arg))

operations = ""
if bool(op_list and op_list.strip()):
    operations = ''.join([f' --operation_list={op}' for op in op_list.split()])

addln_opts = ' '
if bool(dev_list and dev_list.strip()):
    addln_opts += ' --device_list '
    addln_opts += dev_list

btree_options = num_entries + num_iters + preload_size + fibers + threads + operations + addln_opts
class TestFailedError(Exception):
    pass

def long_runnig_index(type=0):
    print("normal test started with (%s)" % (btree_options+ " " + run_time))
    # " --operation_list=query:20 --operation_list=put:20 --operation_list=remove:20"
    cmd_opts = "--gtest_filter=BtreeConcurrentTest/" + str(type) +".ConcurrentAllOps --gtest_break_on_failure " + btree_options + " "+log_mods + run_time
    subprocess.check_call(dirpath + "test_index_btree " + cmd_opts, stderr=subprocess.STDOUT, shell=True)
    print("Long running test completed")

def function_normal(runtime, cleanup_after_shutdown=False, init_device=False, type=0):
    normal_options = "--gtest_filter=BtreeConcurrentTest/" + str(type) +".ConcurrentAllOps --gtest_break_on_failure " + btree_options + " " + log_mods + " --run_time " + str(runtime)
    cmd_opts = normal_options + " --cleanup_after_shutdown=" + str(cleanup_after_shutdown) + " --init_device=" + str(init_device)
    print("normal test started with (%s)" % cmd_opts)
    try:
        subprocess.check_call(dirpath + "test_index_btree " +
                          cmd_opts, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        print("UT failed: {}".format(e))
        raise TestFailedError("UT failed for type {}".format(type))

def function_crash(runtime, cleanup_after_shutdown=False, init_device=False, type=0):
    normal_options ="   --gtest_filter=BtreeConcurrentTest/" + str(type) +".ConcurrentAllOps --gtest_break_on_failure " + btree_options + " "+log_mods +" --enable_crash"
    cmd_opts = normal_options +" --cleanup_after_shutdown=" + str(cleanup_after_shutdown) + " --init_device="+str(init_device) +" --run_time " + str(runtime)
    subprocess.check_call(dirpath + "test_index_btree " + cmd_opts, stderr=subprocess.STDOUT, shell=True)

def long_running_clean_shutdown(type=0):
    normal_run_time = 1 * 1200 # 20 minutes
    try:
        function_normal(normal_run_time, False, True, type)
        for i in range(1,3):
            function_normal(normal_run_time, False, False, type)
            print("Iteration {} completed successfully".format(i))
        function_normal(0, True, False, type) # cleanup after shutdown
        print("All iterations completed successfully for type {}".format(type))
    except TestFailedError as e:
        print("Test failed: {}".format(e))
        raise

def crash_recovery_framework():
    total_run_time = 30 * 3600
    normal_run_time = 10 * 60
    crash_run_time = 10 * 60
    crash_execution_frequency = 0

    function_normal(normal_run_time, False, True)
    elapsed_time = normal_run_time

    while elapsed_time <= total_run_time:
        start_time = time.time()
        p = random.randint(0, 100) # some distribution
        if p < crash_execution_frequency:
            function_crash(crash_run_time, False, False)
        else:
            function_normal(min(normal_run_time, total_run_time - elapsed_time), False, False)
        end_time = time.time()
        elapsed_time += end_time - start_time
    function_normal(0, True, False) #cleanup after shutdown
    print("crash recovery test completed")

def test_index_btree():
    while True:
        try:
            #TODO enable for other types when fix is available for varlen node types.
            for type in range(4):
                long_running_clean_shutdown(type)
                print("long_running_clean_shutdown completed successfully for type {}".format(type))
        except:
            print("Test failed: {}".format(e))
            break

    # wait for 1 minute before running again
    time.sleep(60)

def nightly():
    long_runnig_index(0)
    long_runnig_index(1)
    long_runnig_index(2)
    long_runnig_index(3)

    # long_running_clean_shutdown()
    test_index_btree()
    # crash_recovery_framework()

# The name of the method to be called is the var test_suits
eval(f"{test_suits}()")
