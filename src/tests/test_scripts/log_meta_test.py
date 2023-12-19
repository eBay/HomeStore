#!/usr/bin/env python3
## @file vol_test.py

import subprocess
import os
import sys
import getopt
import sys
from multiprocessing import Process
sys.stdout.flush()
from time import sleep
import requests
from threading import Thread

opts,args = getopt.getopt(sys.argv[1:], 'tdlme:', ['test_suits=', 'dirpath=', 'dev_list=', 'log_mods=', 'emulate_hdd=', 'http_port='] )
test_suits = ""
dirpath = "./"
dev_list = ""
log_mods = ""
http_port = ""

for opt,arg in opts:
    if opt in ('-t', '--test_suits'):
        test_suits = arg
        print(("testing suits (%s)") % (arg))
    if opt in ('-d', '--dirpath'):
        dirpath = arg
        print(("dir path (%s)") % (arg))
    if opt in ('-l', '--dev_list'):
        dev_list = arg
        print(("device list (%s)") % (arg))
    if opt in ('-m', '--log_mods'):
        log_mods = arg
        print(("log_mods (%s)") % (arg))
    if opt in ('-p', '--http_port'):
        http_port = " --http_port " + arg
        print(("http_port (%s)") % (arg))

addln_opts = ' ' 
if bool(dev_list and dev_list.strip()):
    addln_opts += ' --device_list '
    addln_opts += dev_list

if bool(log_mods and log_mods.strip()):
    addln_opts += ' --log_mods '
    addln_opts += log_mods 

addln_opts += ' '.join(map(str, args))

print("addln_opts: " + addln_opts)


def meta_svc_nightly():
    print("meta blk store test started")
    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.CompressionBackoff"
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)
    
    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.RecoveryFromBadData"
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)

    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.min_drive_size_test"
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)

    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.single_read_test"
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)
    
    cmd_opts = "--run_time=7200 --num_io=1000000"
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)
    
    cmd_opts = "--min_write_size=65536 --max_write_size=2097152 --run_time=14400 --num_io=1000000"
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)
    
    cmd_opts = "--min_write_size=10485760 --max_write_size=104857600 --bitmap=1"
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)
    
    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.write_to_full_test" # write to file instead of real disk to save time;
    subprocess.check_call(dirpath + "test_meta_blk_mgr " + cmd_opts + http_port + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("meta blk store test completed")

def logstore_nightly():
    print("log store test started")

    cmd_opts = "--iterations=10"
    subprocess.check_call(dirpath + "test_log_store " + cmd_opts + http_port, stderr=subprocess.STDOUT, shell=True)

    print("log store test completed")

def nightly():
    logstore_nightly()
    sleep(5)

    meta_svce_nightly()
    sleep(5)

# The name of the method to be called is the var test_suits
eval(f"{test_suits}()")

