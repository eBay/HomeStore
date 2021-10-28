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
import requests
from threading import Thread

opts,args = getopt.getopt(sys.argv[1:], 'td:', ['test_suits=', 'dirpath=']) 
test_suits = ""
dirpath = "./"

for opt,arg in opts:
    if opt in ('-t', '--test_suits'):
        test_suits = arg
        print(("testing suits (%s)") % (arg))
    if opt in ('-d', '--dirpath'):
        dirpath = arg
        print(("dir path (%s)") % (arg))

addln_opts = ' '
addln_opts += ' '.join(map(str, args)) 

meta_flip_list = ["write_sb_abort", "write_with_ovf_abort", "remove_sb_abort", "update_sb_abort", "abort_before_recover_cb_sent", "abort_after_recover_cb_sent"]
vdev_flip_list = ["abort_before_update_eof_cur_chunk", "abort_after_update_eof_cur_chunk", "abort_after_update_eof_next_chunk"]

def recovery():
    cmd_opts = "--gtest_filter=VolTest.init_io_test --run_time=30 --enable_crash_handler=1 --remove_file=0"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --verify_type=3 --run_time=30 --enable_crash_handler=1 --remove_file=1 --delete_volume=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("recovery passed")

def recovery_crash():
    try:
        cmd_opts = "--gtest_filter=VolTest.init_io_test --run_time=30 --enable_crash_handler=1 --remove_file=0 --abort=1"
        subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    except:
        print("recovery_crash test aborted")
    
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --verify_type=3 --run_time=30 --enable_crash_handler=1 --remove_file=1 --delete_volume=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("recovery crash passed")

def vol_mod_test(mod_name, flip_list):
    for flip in flip_list: 
        print("testing flip point: " + flip);
        try:
            cmd_opts = "--gtest_filter=VolTest.init_io_test --run_time=30 --max_volume=5 --enable_crash_handler=1 --remove_file=0 --mod_list=" + mod_name + " " + "--" + flip + "=1"
            print(dirpath + "test_volume " + cmd_opts + addln_opts);
            subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
        except:
            print("vol_mod_test aborted: " + flip)
    
        cmd_opts = "--gtest_filter=VolTest.recovery_io_test --verify_type=3 --run_time=30 --max_volume=5 --enable_crash_handler=1 --remove_file=1 --delete_volume=1"
        subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
        print("vol_mod_test passed: " + flip)

    print("All vol_mod_test passed with mod_name: " + mod_name)

## @test normal
#  @brief Normal IO test
def normal(num_secs="20000"):
    print("normal test started")
    cmd_opts = "--run_time=" + num_secs + " --max_num_writes=5000000 --gtest_filter=VolTest.init_io_test --remove_file=0 --flip=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("normal test completed")

## @test load
#  @brief Test using load generator
def load():
    print("load test started")
    cmd_opts = "--num_io=100000000000 --num_keys=1000000 --run_time=600 --gtest_filter=Map*"
    subprocess.check_call(dirpath + "test_load " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("load test completed")

## @test load
#  @brief Test Volume using load generator
def load_volume():
    print("Volume load test started")
    cmd_opts = "--num_io=100000000000 --num_keys=500000 --run_time=21600 --gtest_filter=*Volume*" 
    subprocess.check_call(dirpath + "test_load " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("Volume load test completed")

## @test recovery_nightly
#  @brief Nightly recovery test
def recovery_nightly(num_iteration=10):
    print("recovery test started")
    i = 1
    while i < num_iteration:
        
        cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=800 --enable_crash_handler=1 --pre_init_verify=false --abort=1 --flip=1 --remove_file=0 --verify_type=2"
        subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
        
        cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=800 --enable_crash_handler=1 --pre_init_verify=false --abort=0 --flip=1 --remove_file=0 --verify_type=2"
        subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)

        s = "recovery test iteration" + repr(i) + "passed" 
        print(s)
        i += 1
    
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=300 --remove_file=0 --delete_volume=0 --verify_type=2"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("recovery test completed")

    # run same LBA work load for 2 hours;
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=3600 --max_num_writes=5000000 --load_type=1 --verify_type=2 --enable_crash_handler=1 --remove_file=0"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --verify_type=2 --run_time=300 --enable_crash_handler=1 --remove_file=1 --delete_volume=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("recovery with writing to same LBA workload passed")

def recovery_nightly_with_create_del(num_iteration=10):
    print("recovery test started")
    i = 1
    while i < num_iteration:
        
        cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=800 --enable_crash_handler=1 --verify_type=3 --abort=1 --flip=1 --remove_file=0 --create_del_with_io=true --expect_io_error=1"
        subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
        
        cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=800 --enable_crash_handler=1 --verify_type=3 --abort=0 --flip=1 --remove_file=0 --create_del_with_io=true --expect_io_error=1"
        subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)

        s = "recovery test with create delete iteration" + repr(i) + "passed" 
        print(s)
        i += 1
    
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=600 --remove_file=1 --delete_volume=1 --verify_type=2 --create_del_with_io=true --create_del_ops_interval=600 --expect_io_error=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("recovery test with create delete completed")

## @test one_disk_replace
#  @brief One disk is replaced during boot time
def one_disk_replace():
    print("one disk replace test started")
    cmd_opts = "--gtest_filter=VolTest.one_disk_replace_test --run_time=300 --remove_file=0 --verify_type=3"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("recovery test with one disk replace passed")

## @test one_disk_replace_abort
#  @brief Homestore crashed during recovery with one disk replace
def one_disk_replace_abort():
    print("recovery abort with one disk replace started")
    cmd_opts = "--gtest_filter=VolTest.one_disk_replace_abort_test --run_time=300 --remove_file=0 --verify_type=3 --enable_crash_handler=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)

    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --run_time=300 --remove_file=0 --verify_type=3 --expected_vol_state=2"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("recovery abort with one disk replace passed")

## @test both_disk_replace
#  @brief Both disks are replaced during boot time
def both_disk_replace():
    print("Both disk replace started")
    cmd_opts = "--gtest_filter=VolTest.two_disk_replace_test --run_time=300"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)

    cmd_opts = "--run_time=300 --max_num_writes=5000000 --gtest_filter=VolTest.init_io_test --remove_file=0"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("Both disk replace passed")

## @test one_disk_fail
#  @brief One Disk failure during boot time
def one_disk_fail():
    print("one disk fail test started")
    cmd_opts = "--gtest_filter=VolTest.one_disk_fail_test --run_time=300"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("one disk fail test passed")

## @test vol_offline_test
#  @brief Move volume to offline when IOs are going on
def vol_offline_test():
    print("vol offline test started")
    cmd_opts = "--gtest_filter=VolTest.vol_offline_test --run_time=300"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("vol offline test passed")
    
    print("vol offline test recovery started")
    cmd_opts = "--gtest_filter = VolTest.recovery_io_test --run_time=300 --expected_vol_state=1"
    status = subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("vol offline test recovery passed")

## @test vol_io_fail_test
#  @brief Set IO error and verify all volumes come online
#           after reboot and data is verified.
def vol_io_fail_test(num_secs="3600"):
    print("vol io fail test started")
    cmd_opts = "--run_time=" + num_secs + " --max_num_writes=5000000 --remove_file=0 --flip=2"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("vol io fail test completed")

def vol_crc_mismatch_test(num_secs="30"):
    print("vol crc mismatch test started")
    cmd_opts = "--run_time=" + num_secs + " --gtest_filter=VolTest.vol_crc_mismatch_test --remove_file=0 --expect_io_error=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("vol crc mismatch test completed")

##  @test vol_create_del_test
#   @brief Create and Delete Volume
def vol_create_del_test():
    print("create del vol test started")
    cmd_opts = "--gtest_filter=VolTest.vol_create_del_test --max_volume=1000"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("create del vol test passed")

def seq_load_start():
    print("seq workload started")
    cmd_opts = "--run_time=24000 --max_num_writes=5000000 --gtest_filter=VolTest.init_io_test --remove_file=0 --flip=1 --load_type=2"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("seq workload test completed")
    
def seq_workload():
    p = Process(target = seq_load_start())
    p.start()
    p.join()

def btree_fix_on_read_failure():
    print("btree fix failure test started")
    cmd_opts = "--run_time=100 --max_num_writes=1000 --gtest_filter=VolTest.btree_fix_read_failure_test"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("btree fix failure test completed")
 
def btree_fix():
    print("btree fix started")
    cmd_opts = "--run_time=1000 --max_num_writes=100000 --gtest_filter=VolTest.btree_fix_test"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("btree fix test completed")

def btree_fix_rerun_io():
    print("btree fix rerun io started")
    cmd_opts = "--run_time=1000 --max_num_writes=100000 --gtest_filter=VolTest.btree_fix_rerun_io_test"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("btree fix rerun io test completed")
   
def vdev_nightly():
    print("virtual dev pwrite/pread/truncate test started")
    subprocess.check_call(dirpath + "test_virtual_device \
            --truncate_watermark_percentage=80 --run_time=24000 --num_io=1000000 --min_write_size=512 --max_write_size=32768",\
            stderr=subprocess.STDOUT, shell=True)
    print("virtual dev pwrite/pread/truncate test completed")

def meta_blk_store_nightly():
    print("meta blk store test started")
    subprocess.check_call(dirpath + "test_meta_blk_mgr --gtest_filter=VMetaBlkMgrTest.min_drive_size_test", stderr=subprocess.STDOUT, shell=True)
    subprocess.check_call(dirpath + "test_meta_blk_mgr --gtest_filter=VMetaBlkMgrTest.write_to_full_test", stderr=subprocess.STDOUT, shell=True)
    subprocess.check_call(dirpath + "test_meta_blk_mgr --gtest_filter=VMetaBlkMgrTest.single_read_test", stderr=subprocess.STDOUT, shell=True)
    subprocess.check_call(dirpath + "test_meta_blk_mgr --run_time=7200 --num_io=1000000", stderr=subprocess.STDOUT, shell=True)
    subprocess.check_call(dirpath + "test_meta_blk_mgr --min_write_size=65536 --max_write_size=2097152 --run_time=14400 --num_io=1000000", stderr=subprocess.STDOUT, shell=True)
    subprocess.check_call(dirpath + "test_meta_blk_mgr --min_write_size=10485760 --max_write_size=104857600 --bitmap=1", stderr=subprocess.STDOUT, shell=True)

    print("meta blk store test completed")

def logstore_nightly():
    print("log store test started")
    subprocess.check_call(
        dirpath + "test_log_store --iterations=10", stderr=subprocess.STDOUT, shell=True)

    print("log store test completed")
    
def force_reinit():
    # test force reinit with recovery (e.g.  with complete homestore shutdown);
    cmd_opts = "--gtest_filter=VolTest.init_io_test --run_time=1 --enable_crash_handler=0 --remove_file=0"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)

    cmd_opts = "--gtest_filter=VolTest.hs_force_reinit_test --run_time=1 --enable_crash_handler=1 --remove_file=1 --delete_volume=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    print("Homestore Force Reinit passed")

def hs_svc_tool():
    cmd_opts = "--zero_boot_sb"
    subprocess.check_call(dirpath + "hs_svc_tool " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)

def vol_create_delete_test():
    # abort during first cp create
    cmd_opts = "--mod_list=\"index\" --create_del_with_io=true --gtest_filter=VolTest.init_io_test --indx_create_first_cp_abort=true --run_time=10000 --max_num_writes=1000000 --num_threads=1 --expect_io_error=1 --remove_file=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --create_del_with_io=true --delete_volume=0 --run_time=600 --create_del_ops_interval=30 --verify_type=2 --expect_io_error=1 --remove_file=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    print("homestore create first cp test completed")

    # abort during vol delete before writing meta blk
    cmd_opts = "--mod_list=\"index\" --create_del_with_io=true --gtest_filter=VolTest.init_io_test --free_blk_cnt=50 --indx_del_partial_free_data_blks_before_meta_write=true --run_time=10000 --max_num_writes=1000000 --create_del_ops_interval=30 --max_volume=3 --num_threads=1 --verify_type=3 --expect_io_error=1 --remove_file=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --create_del_with_io=true --max_volume=3 --run_time=600 --create_del_ops_interval=30 --verify_type=3 --expect_io_error=1 --remove_file=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    print("abort during vol delete before writing meta blk test compeleted")
    
    # abort during vol delete after writing meta blk
    cmd_opts = "--mod_list=\"index\" --create_del_with_io=true --gtest_filter=VolTest.init_io_test --free_blk_cnt=50 --indx_del_partial_free_data_blks_after_meta_write=true --run_time=10000 --max_num_writes=1000000 --create_del_ops_interval=30 --max_volume=3 --num_threads=1 --verify_type=3 --expect_io_error=1 --remove_file=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --create_del_with_io=true --max_volume=3 --run_time=600 --create_del_ops_interval=30 --verify_type=3 --expect_io_error=1 --remove_file=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    print("abort during vol delete after writing meta blk test compeleted")
    
    # abort during vol delete after freeing data blks
    cmd_opts = "--mod_list=\"index\" --create_del_with_io=true --gtest_filter=VolTest.init_io_test --free_blk_cnt=50 --indx_del_partial_free_indx_blks=true --run_time=10000 --max_num_writes=1000000 --create_del_ops_interval=30 --max_volume=3 --num_threads=1 --verify_type=3 --expect_io_error=1 --remove_file=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --create_del_with_io=true --max_volume=3 --run_time=600 --create_del_ops_interval=30 --verify_type=3 --expect_io_error=1 --remove_file=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    print("abort during vol delete after freeing data blks")

    # abort during vol delete after freeing btree blks
    cmd_opts = "--mod_list=\"index\" --create_del_with_io=true --gtest_filter=VolTest.init_io_test --free_blk_cnt=50 --indx_del_free_blks_completed=true --run_time=10000 --max_num_writes=1000000 --create_del_ops_interval=30 --max_volume=3 --num_threads=1 --verify_type=3 --expect_io_error=1 --remove_file=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --create_del_with_io=true --max_volume=3 --run_time=600 --create_del_ops_interval=30 --verify_type=3 --expect_io_error=1 --remove_file=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    print("abort during vol delete after freeing btree blks")

    # double crash after vol delete
    cmd_opts = "--mod_list=\"index\" --create_del_with_io=true --gtest_filter=VolTest.init_io_test --free_blk_cnt=50 --indx_del_partial_free_data_blks_before_meta_write=true --run_time=10000 --max_num_writes=1000000 --create_del_ops_interval=30 --max_volume=3 --num_threads=1 --verify_type=3 --expect_io_error=1 --remove_file=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--mod_list=\"index\" --create_del_with_io=true --gtest_filter=VolTest.recovery_io_test --free_blk_cnt=50 --indx_del_partial_free_data_blks_before_meta_write=true --run_time=10000 --max_num_writes=1000000 --create_del_ops_interval=30 --max_volume=3 --num_threads=1 --verify_type=3 --expect_io_error=1 --remove_file=0"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --create_del_with_io=true --max_volume=3 --run_time=600 --create_del_ops_interval=30 --verify_type=3 --expect_io_error=1 --remove_file=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    print("double crash of volume delete compelted")

    # run vol delete with for an hour
    cmd_opts = "--gtest_filter=VolTest.init_io_test --create_del_with_io=true --remove_file=0 --run_time=1200 --create_del_ops_interval=30 --expect_io_error=1"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    print("init completed")

    # run few iteration of vol create delete with recovery
    recovery_nightly_with_create_del()

def vol_io_flip_test():
    cmd_opts = "--gtest_filter=VolTest.init_io_test --mod_list=\"index\" --remove_file=0 --run_time=600 --cp_bitmap_abort=true --max_volume=3 --max_num_writes=1000000"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --remove_file=0 --run_time=600 --delete_volume=0 --max_volume=3"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --mod_list=\"index\" --remove_file=0 --run_time=600 --delete_volume = 0 --cp_wb_flush_abort=true --max_volume=3 --pre_init_verify=false --max_num_writes=1000000"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --remove_file=0 --run_time=600 --delete_volume=0 --max_volume=3"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --mod_list=\"index\" --remove_file=0 --run_time=600 --delete_volume=0 --cp_logstore_truncate_abort=true --max_volume=3 --pre_init_verify=false --max_num_writes=1000000"
    subprocess.call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)
    cmd_opts = "--gtest_filter=VolTest.recovery_io_test --remove_file=0 --run_time=600 --delete_volume=0 --max_volume=3"
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, shell=True)

def meta_mod_abort():
    vol_mod_test("meta", meta_flip_list)

def vdev_mod_abort():
    vol_mod_test("vdev", vdev_flip_list)

def http_sanity_routine(success):
    sleep(20)
    get_api_list = ['version', 'getObjLife', 'getLogLevel', 'verifyHS', 'mallocStats', 'getConfig', 'getStatus'""", 'verifyBitmap'"""]
    endpoint = "127.0.0.1:12345"
    # homestore takes variable time to init. Retry brfore failing.
    retry_limit = 10
    for api in get_api_list:
        url = f"http://{endpoint}/api/v1/{api}"
        response = None
        while retry_limit > 0:
            try:
                response = requests.post(url)
                break
            except requests.exceptions.RequestException as e:
                retry_limit = retry_limit - 1
                sleep(1)
        if not response:
            print(f"error: max retries exceeded for url {url}")
            success.append(False)
            return
        if not response.ok:
            print(f"error: url {url} failed, what: {response.text}")
            success.append(False)
            return
        sleep(1)
    success.append(True)

def http_sanity_test():
    print("http_sanity_test test started")
    cmd_opts = "--run_time=45 --max_volume=1 --num_threads=1 --gtest_filter=VolTest.vol_create_del_test --hb_stats_port=12345"
    success = []
    thread = Thread(target=http_sanity_routine, args=[success,])
    thread.start()
    subprocess.check_call(dirpath + "test_volume " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)
    thread.join()
    if (not success) or (not success[0]) :
        print("http_sanity_test FAILED")
        sys.exit(1)
    print("http_sanity_test test completed")

# It is subset of nightly which should be completed in an hour
def hourly():
    normal("10 * 60")
    sleep(5)
    recovery_nightly(2)
    sleep(5)

def nightly():
    normal()
    sleep(5)

    recovery_nightly()
    sleep(5)
    
    #load()
    sleep(5)

    vol_create_delete_test()
    sleep(5)
    
    # metablkstore IO test
    meta_blk_store_nightly()
    sleep(5)
    
    logstore_nightly()
    sleep(5)
    
    vol_mod_test("meta", meta_flip_list)
    sleep(5)

    vol_mod_test("vdev", vdev_flip_list)
    sleep(5)

    vol_io_fail_test()
    sleep(5)
    
    #vol_crc_mismatch_test()   # turn back on if fault_containment doesn't do assert failure;
    #sleep(5)

    #one_disk_replace()
    #sleep(5)

    #one_disk_replace_abort()
    #sleep(5)

    #both_disk_replace()
    #sleep(5)

    #one_disk_fail()
    #sleep(5)

    #vol_offline_test()
    #sleep(5)


    #vol_create_del_test()
    #sleep(5)
    print("nightly test passed")
    
    #load_volume()
    #sleep(5)


    #btree_fix()
    #sleep(5)

    #btree_fix_on_read_failure()
    #sleep(5)
    
    #vdev_nightly()
    #sleep(5)
    
# The name of the method to be called is the var test_suits
eval(f"{test_suits}()")
