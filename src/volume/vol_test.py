#!/usr/bin/env python

import subprocess
import os
import sys
import getopt
import sys
sys.stdout.flush()
from time import sleep

opts,args = getopt.getopt(sys.argv[1:], 'td:', ['test_suits=', 'dirpath=']) 
test_suits = ""
dirpath = "./"

# slack details
slackcmd = ("./slackpost "
            "https://hooks.slack.com/services/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 "
            "sds-homestore "
            "regression-bot \""
           )

def slackpost(msg):
    cmd = slackcmd + msg + "\""
    subprocess.call(cmd, shell=True)

for opt,arg in opts:
    if opt in ('-t', '--test_suits'):
        test_suits = arg
        print(("testing suits (%s)")%(arg))
    if opt in ('-d', '--dirpath'):
        dirpath = arg
        print(("dir path (%s)")%(arg))


def recovery():
    subprocess.call(dirpath + "test_volume \
    --gtest_filter=IOTest.init_abort_io_test --run_time=30 --enable_crash_handler=0", shell=True)
    
    subprocess.check_call(dirpath + "test_volume \
    --gtest_filter=IOTest.recovery_io_test --verify_hdr=0 --verify_data=0 --run_time=30 --enable_crash_handler=1", shell=True)

def normal():
    print("normal test started")
    status = subprocess.check_output(dirpath + "test_volume \
            --run_time=12000 --max_num_writes=5000000 --gtest_filter=IOTest.init_io_test --remove_file=0", shell=True)
    print("normal test completed")
    if status == False:
        sys.exit(0)

def load():
    print("load test started")
    status = subprocess.check_output(dirpath + "test_load \
            --num_io=100000000000 --num_keys=1000000 --run_time=21600 --gtest_filter=Map* ", shell=True)
    print("load test completed")
    if status == False:
        sys.exit(0)

def recovery_nightly():
    print("recovery test started")
    i = 1
    while i < 10:
        subprocess.call(dirpath + "test_volume \
        --gtest_filter=IOTest.recovery_abort_io_test --run_time=300 --enable_crash_handler=0", shell=True)
        s = "recovery test iteration" + repr(i) + "passed" 
        print(s)
        i += 1
    
    if (subprocess.check_call(dirpath + "test_volume --gtest_filter=IOTest.recovery_io_test \
            --run_time=300 --remove_file=0", shell=True)) == False:
        print("recovery test failed")
        sys.exit(0)
    print("recovery test completed")

def one_disk_replace():
    print("one disk replace test started");
    if (subprocess.check_call(dirpath + "test_volume --gtest_filter=IOTest.one_disk_replace_test \
            --run_time=300 --remove_file=0 --verify_hdr=0 --verify_data=0", shell=True)) == FALSE:
        print("recovery test with one disk replace failed")
        sys.exit(0)
    print("recovery test with one disk replace passed")

def one_disk_replace_abort():
    print("recovery abort with one disk replace started")
    subprocess.call(dirpath + "test_volume --gtest_filter=IOTest.one_disk_replace_abort_test \
          --run_time=300 --remove_file=0 --verify_hdr=0 --verify_data=0 --enable_crash_handler=0", shell=True)
    if (subprocess.check_call(dirpath + "test_volume --gtest_filter=IOTest.recovery_io_test \
           --run_time=300 --remove_file=0 --verify_hdr=0 --verify_data --expected_vol_state=2", shell=True)) == FALSE:
        print("recovery abort with one disk replace failed")
        sys.exit(0)
    print("recovery abort with one disk replace passed")

def both_disk_replace():
    print("Both disk replace started")
    if (subprocess.check_call(dirpath + "test_volume \
                    --gtest_filter=IOTest.two_disk_replace_test --run_time=300", shell=True)) == FALSE:
        print("Both disk replace failed")
        sys.exit(0)
    print("Both disk replace passed")

def one_disk_fail():
    print("one disk fail test started")
    if (subprocess.check_call(dirpath + "test_volume \
                    --gtest_filter=IOTest.one_disk_fail_test --run_time=300", shell=True)) == FALSE:
        print("Both disk replace failed")
        sys.exit(0)
    print("one disk fail test passed")

def vol_offline_test():
    print("vol offline test started")
    if (subprocess.check_call(dirpath + "test_volume \
                --gtest_filter=IOTest.vol_offline_test --run_time=300", shell=True)) == FALSE:  
        print("vol offline test failed")
        sys.exit(0)
    print("vol offline test passed")
    
    print("vol offline test recovery started")
    if (subprocess.check_call(dirpath + "test_volume \
                --gtest_filter=IOTest.recovery_io_test --run_time=300 --expected_vol_state=1", shell=True)) == FALSE:  
        print("vol offline test recovery failed")
        sys.exit(0)
    print("vol offline test recovery passed")

def vol_io_fail_test():
    print("vol io fail test started")
    
    if (subprocess.check_call(dirpath + "test_volume \
                --gtest_filter=IOTest.vol_io_fail_test --run_time=300", shell=True)) == FALSE:  
        print("vol io fail test failed")
        sys.exit(0)
    print("vol io test test passed")
    
    print("vol io fail test recovery started")
    if (subprocess.check_call(dirpath + "test_volume \
                --gtest_filter=IOTest.recovery_io_test --run_time=300", shell=True)) == FALSE:  
        print("vol io fail recevery test failed")
        sys.exit(0)
    print("vol io fail test recovery passed")

def vol_create_del_test():
    print("create del vol test started")
    if subprocess.check_call(dirpath + "test_volume \
                             --gtest_filter=IOTest.normal_vol_create_del_test --max_vols=10000", shell=True) == False:
         print("create del vol test failed")
         sys.exit(0)
    print("create del vol test passed")

def nightly():

    # load gen test
    load()
    sleep(5)

    # normal IO test
    normal()
    sleep(5)
    
    # recovery test
    recovery_nightly()
    sleep(5)

    # one disk is replaced during boot time
    one_disk_replace()
    sleep(5)

    # homestore crashed during recovery with one disk replace
    one_disk_replace_abort()
    sleep(5)
    
    # Both disks are replaced during boot time
    both_disk_replace()
    sleep(5)
    
    # One Disk failure during boot time
    one_disk_fail()
    sleep(5)

    # Move volume to offline when IOs are going on
    vol_offline_test()
    sleep(5)

    # Set IO error and verify all volumes come online after reboot and data is verified.
    vol_io_fail_test()
    sleep(5)

    # create del vol
    vol_create_del_test()
    sleep(5)
    print("nightly test passed")

if test_suits == "normal":
    normal()
    
if test_suits == "recovery":
    recovery()
    
if test_suits == "mapping":
    mapping()

if test_suits == "one_disk_replace":
    one_disk_replace()

if test_suits == "one_disk_replace_abort":
    one_disk_replace_abort()

if test_suits == "both_disk_replace":
    both_disk_replace()

if test_suits == "one_disk_fail":
    one_disk_fail()

if test_suits == "vol_offline_test":
    vol_offline_test()

if test_suits == "vol_io_fail_test":
    vol_io_fail_test()

if test_suits == "vol_create_del_test":
    vol_create_del_test()

if test_suits == "nightly":
    nightly()

if test_suits == "recovery_nightly":
    recovery_nightly()

if test_suits == "load":
    load()
