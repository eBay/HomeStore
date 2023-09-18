#!/usr/bin/env python3
## @file btree_test.py

import subprocess
import os
import sys
import getopt
import sys

sys.stdout.flush()
import requests

opts, args = getopt.getopt(sys.argv[1:], 'tdlme:',
                           ['test_suits=', 'dirpath=', 'op_list=', 'log_mods=', 'threads=', 'fibers=', 'preload_size=',
                            'op_list=', 'num_entries=', 'num_iters='])
test_suits = ""
dirpath = "./"
op_list = ""
log_mods = ""
threads = " --n_threads=10"
fibers = " --n_fibers=10"
preload_size = "  --preload_size=2000"
num_entries = " --num_entries=10000"
num_iters = " --num_iters=1000000"

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
        fibers = " --n_fibers=" + arg
        print("number of fibers per thread (%s)" % arg)
    if opt in ('-p', '--preload_size'):
        preload_size = " --preload_size=" + arg
        print("preload_size = (%s)" % arg)
    if opt in ('-t', '--threads'):
        threads = " --n_threads=" + arg
        print("number of threads (%s)" % arg)
    if opt in ('-n', '--num_entries'):
        num_entries = " --num_entries=" + arg
        print("number of entries (%s)" % arg)
    if opt in ('-i', '--num_iters'):
        num_iters = " --num_iters=" + arg
        print("number of iterations (%s)" % arg)

operations = ""
if bool(op_list and op_list.strip()):
    operations = ''.join([f' --operation_list={op}' for op in op_list.split()])

btree_options = num_entries + num_iters + preload_size + fibers + threads + operations


def normal():
    print("normal test started with (%s)" % btree_options)
    # " --operation_list=query:20 --operation_list=put:20 --operation_list=remove:20"
    cmd_opts = " --gtest_filter=BtreeConcurrentTest/*.AllTree" + btree_options + " "+log_mods
    subprocess.check_call(dirpath + "test_mem_btree " + cmd_opts, stderr=subprocess.STDOUT, shell=True)
    print("normal test completed")


def nightly():
    normal()


# The name of the method to be called is the var test_suits
eval(f"{test_suits}()")
