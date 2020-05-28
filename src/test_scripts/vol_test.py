#!/usr/bin/env python
## @file vol_test.py
#  Regression Tests linked to PR merge

import subprocess
import os
import sys
import getopt
import sys
from multiprocessing import Process
sys.stdout.flush()
from time import sleep

opts,args = getopt.getopt(sys.argv[1:], 'td:', ['test_suits=', 'dirpath=']) 
test_suits = ""
dirpath = "./"

for opt,arg in opts:
    if opt in ('-t', '--test_suits'):
        test_suits = arg
        print(("testing suits (%s)")%(arg))
    if opt in ('-d', '--dirpath'):
        dirpath = arg
        print(("dir path (%s)")%(arg))


def recovery():
    subprocess.check_call(dirpath + "test_volume \
    --gtest_filter=VolTest.init_io_test --run_time=30 --enable_crash_handler=0 --remove_file=0", \
    stderr=subprocess.STDOUT, shell=True)
    
    subprocess.check_call(dirpath + "test_volume \
    --gtest_filter=VolTest.recovery_io_test --verify_hdr=0 --verify_data=0 --run_time=30 --enable_crash_handler=1 \
    --remove_file=1 --delete_volume=1", stderr=subprocess.STDOUT, shell=True)
    print("recovery passed")

## @test    normal
#  @brief   Normal IO test
def normal():
    print("normal test started")
    subprocess.check_call(dirpath + "test_volume \
            --run_time=20000 --max_num_writes=5000000 --gtest_filter=VolTest.init_io_test --remove_file=0 --flip=1",\
            stderr=subprocess.STDOUT, shell=True)
    print("normal test completed")

def normal_flip():
    print("normal test started with flip = 2")
    subprocess.check_call(dirpath + "test_volume \
            --run_time=3600 --max_num_writes=5000000 --gtest_filter=VolTest.init_io_test --remove_file=0 --verify_data=0 \
            --flip=1", stderr=subprocess.STDOUT, shell=True)
    print("normal test completed with flip =  2")

## @test    load
#  @brief   Test using load generator
def load():
    print("load test started")
    subprocess.check_call(dirpath + "test_load \
            --num_io=100000000000 --num_keys=1000000 --run_time=21600 --gtest_filter=Map*", stderr=subprocess.STDOUT, shell=True)
    print("load test completed")

## @test    load
#  @brief   Test Volume using load generator
def load_volume():
    print("Volume load test started")
    subprocess.check_call(dirpath + "test_load \
            --num_io=100000000000 --num_keys=500000 --run_time=21600 --gtest_filter=*Volume*", stderr=subprocess.STDOUT, shell=True)
    print("Volume load test completed")

## @test    recovery_nightly
#  @brief   Nightly recovery test
def recovery_nightly():
    print("recovery test started")
    i = 1
    while i < 10:
        subprocess.check_call(dirpath + "test_volume \
        --gtest_filter=VolTest.recovery_io_test --run_time=300 --enable_crash_handler=0 --verify_only=1 --flip=1 \
        --remove_file=0", \
        stderr=subprocess.STDOUT, shell=True)
        
        subprocess.call(dirpath + "test_volume \
        --gtest_filter=VolTest.recovery_io_test --run_time=300 --enable_crash_handler=0 --verify_data=0 --verify_hdr=0 \
        --abort=1 --flip=1 --remove_file=0", shell=True)
        s = "recovery test iteration" + repr(i) + "passed" 
        print(s)
        i += 1
    
    subprocess.check_call(dirpath + "test_volume --gtest_filter=VolTest.recovery_io_test \
            --run_time=300 --remove_file=1 --delete_volume=1", stderr=subprocess.STDOUT, shell=True)
    print("recovery test completed")

## @test    one_disk_replace
#  @brief   One disk is replaced during boot time
def one_disk_replace():
    print("one disk replace test started");
    subprocess.check_call(dirpath + "test_volume --gtest_filter=VolTest.one_disk_replace_test \
            --run_time=300 --remove_file=0 --verify_hdr=0 --verify_data=0", stderr=subprocess.STDOUT, shell=True)
    print("recovery test with one disk replace passed")

## @test    one_disk_replace_abort
#  @brief   Homestore crashed during recovery with one disk replace
def one_disk_replace_abort():
    print("recovery abort with one disk replace started")
    subprocess.call(dirpath + "test_volume --gtest_filter=VolTest.one_disk_replace_abort_test \
          --run_time=300 --remove_file=0 --verify_hdr=0 --verify_data=0 --enable_crash_handler=0", shell=True)
    subprocess.check_call(dirpath + "test_volume --gtest_filter=VolTest.recovery_io_test \
          --run_time=300 --remove_file=0 --verify_hdr=0 --verify_data=0 --expected_vol_state=2", \
          stderr=subprocess.STDOUT, shell=True)
    print("recovery abort with one disk replace passed")

## @test    both_disk_replace
#  @brief   Both disks are replaced during boot time
def both_disk_replace():
    print("Both disk replace started")
    subprocess.check_call(dirpath + "test_volume \
                    --gtest_filter=VolTest.two_disk_replace_test --run_time=300", stderr=subprocess.STDOUT, shell=True)
    subprocess.check_call(dirpath + "test_volume \
            --run_time=300 --max_num_writes=5000000 --gtest_filter=VolTest.init_io_test --remove_file=0", \
            stderr=subprocess.STDOUT, shell=True)
    print("Both disk replace passed")

## @test    one_disk_fail
#  @brief   One Disk failure during boot time
def one_disk_fail():
    print("one disk fail test started")
    subprocess.check_call(dirpath + "test_volume \
                    --gtest_filter=VolTest.one_disk_fail_test --run_time=300", stderr=subprocess.STDOUT, shell=True)
    print("one disk fail test passed")

## @test    vol_offline_test
#  @brief   Move volume to offline when IOs are going on
def vol_offline_test():
    print("vol offline test started")
    subprocess.check_call(dirpath + "test_volume \
                --gtest_filter=VolTest.vol_offline_test --run_time=300", stderr=subprocess.STDOUT, shell=True)
    print("vol offline test passed")
    
    print("vol offline test recovery started")
    status = subprocess.check_call(dirpath + "test_volume \
                --gtest_filter=VolTest.recovery_io_test --run_time=300 --expected_vol_state=1", stderr=subprocess.STDOUT, shell=True)
    print("vol offline test recovery passed")

## @test    vol_io_fail_test
#  @brief   Set IO error and verify all volumes come online
#           after reboot and data is verified.
def vol_io_fail_test():
    print("vol io fail test started")
    
    process = Popen([dirpath + "test_volume", "--gtest_filter=VolTest.vol_io_fail_test", "--run_time=30", "--remove_file=0"])
    p_status = process.wait()
    if p_status != 0:
        print ("test failed")
        sys.exit(-1)
    print("vol io test test passed")
    
    print("vol io fail test recovery started")
    subprocess.check_call(dirpath + "test_volume \
           --gtest_filter=VolTest.recovery_io_test --run_time=300 --verify_data=0", shell=True, stderr=subprocess.STDOUT)
    print("vol io fail test recovery passed")

##  @test   vol_create_del_test
#   @brief  Create and Delete Volume
def vol_create_del_test():
    print("create del vol test started")
    subprocess.check_call(dirpath + "test_volume \
               --gtest_filter=VolTest.vol_create_del_test --max_volume=1000", shell=True, stderr=subprocess.STDOUT)
    print("create del vol test passed")

def seq_load_start():
    print("seq workload started")
    subprocess.check_call(dirpath + "test_volume \
            --run_time=24000 --max_num_writes=5000000 --gtest_filter=VolTest.init_io_test --remove_file=0 --flip=1 --load_type=2",\
            stderr=subprocess.STDOUT, shell=True)
    print("seq workload test completed")
    
def seq_vol_load():
    p = Process(target = seq_load_start())
    p.start()
    p.join()

def btree_fix_on_read_failure():
    print("btree fix failure test started")
    subprocess.check_call(dirpath + "test_volume --run_time=100 --max_num_writes=1000 --gtest_filter=VolTest.btree_fix_read_failure_test",\
            stderr=subprocess.STDOUT, shell=True)
    print("btree fix failure test completed")
 
def btree_fix():
    print("btree fix started")
    subprocess.check_call(dirpath + "test_volume --run_time=1000 --max_num_writes=100000 --gtest_filter=VolTest.btree_fix_test",\
            stderr=subprocess.STDOUT, shell=True)
    print("btree fix test completed")

def btree_fix_rerun_io():
    print("btree fix rerun io started")
    subprocess.check_call(dirpath + "test_volume --run_time=1000 --max_num_writes=100000 --gtest_filter=VolTest.btree_fix_rerun_io_test",\
            stderr=subprocess.STDOUT, shell=True)
    print("btree fix rerun io test completed")
   
def vdev_nightly():
    print("virtual dev pwrite/pread/truncate test started")
    subprocess.check_call(dirpath + "test_virtual_device \
            --truncate_watermark_percentage=80 --run_time=24000 --num_io=1000000 --min_write_size=512 --max_write_size=32768",\
            stderr=subprocess.STDOUT, shell=True)
    print("virtual dev pwrite/pread/truncate test completed")

def nightly():

    normal()
    sleep(5)

    recovery_nightly()
    sleep(5)
    
    # normal IO test
    normal_flip()
    sleep(5)

    one_disk_replace()
    sleep(5)

    one_disk_replace_abort()
    sleep(5)

    both_disk_replace()
    sleep(5)

    one_disk_fail()
    sleep(5)

    vol_offline_test()
    sleep(5)

  #  vol_io_fail_test()
    sleep(5)

    vol_create_del_test()
    sleep(5)
    print("nightly test passed")
    
    load_volume()
    sleep(5)

    load()
    sleep(5)

    btree_fix()
    sleep(5)

    btree_fix_on_read_failure()
    sleep(5)
    
    vdev_nightly()
    sleep(5)

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

if test_suits == "normal_flip":
    normal_flip()

if test_suits == "nightly":
    nightly()

if test_suits == "recovery_nightly":
    recovery_nightly()

if test_suits == "load":
    load()
 
if test_suits == "load_volume":
    load_volume()

if test_suits == "btree_fix":
    btree_fix()

if test_suits == "btree_fix_rerun_io":
    btree_fix_rerun_io()

if test_suits == "btree_fix_on_read_failure":
    btree_fix_on_read_failure()

if test_suits == "seq_workload":
    seq_vol_load()

if test_suits == "vdev_nightly":
    vdev_nightly()
