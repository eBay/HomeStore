#!/usr/bin/env python3
## @file log_meta_test.py

import subprocess
import os
import sys
import getopt
import sys
from multiprocessing import Process

sys.stdout.flush()
from time import sleep
import argparse
from threading import Thread


def parse_arguments():
    # Create the parser
    parser = argparse.ArgumentParser(description='Process command line options.')

    # Define the expected command-line arguments
    parser.add_argument('-t', '--test_suits', help='Test suits to run', default='')
    parser.add_argument('-d', '--dirpath', help='Directory path', default='bin/')
    parser.add_argument('-l', '--dev_list', help='Device list', default='')
    parser.add_argument('-m', '--log_mods', help='Log modules', default='')
    parser.add_argument('-e', '--emulate_hdd', help='Emulate HDD', default='')
    parser.add_argument('-p', '--http_port', help='HTTP port', default=5000)

    # Parse the known arguments and ignore any unknown arguments
    args, unknown = parser.parse_known_args()

    # Print the values if they are provided
    if args.test_suits:
        print(f"testing suits ({args.test_suits})")
    if args.dirpath:
        print(f"dir path ({args.dirpath})")
    if args.dev_list:
        print(f"device list ({args.dev_list})")
    if args.log_mods:
        print(f"log_mods ({args.log_mods})")
    if args.http_port:
        print(f"http_port ({args.http_port})")

    # Construct additional options string
    addln_opts = ''
    if args.dev_list:
        addln_opts += f' --device_list {args.dev_list}'
    if args.log_mods:
        addln_opts += f' --log_mods {args.log_mods}'
    if args.http_port:
        addln_opts += f' --http_port {args.http_port}'
    if args.dev_list:
        args.dev_list = f' --device_list={args.dev_list}'
    # Return the parsed arguments and additional options
    return args, addln_opts


def meta_nightly(options, addln_opts):
    print("meta blk store test started")
    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.CompressionBackoff"
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)

    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.RecoveryFromBadData"
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)

    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.min_drive_size_test"
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)

    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.single_read_test"
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)

    cmd_opts = "--run_time=7200 --num_io=1000000"
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)

    cmd_opts = "--min_write_size=65536 --max_write_size=2097152 --run_time=14400 --num_io=1000000"
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)

    cmd_opts = "--min_write_size=10485760 --max_write_size=104857600 --bitmap=1"
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)

    cmd_opts = "--gtest_filter=VMetaBlkMgrTest.write_to_full_test"  # write to file instead of real disk to save time;
    subprocess.check_call(options.dirpath + "test_meta_blk_mgr " + cmd_opts + addln_opts, stderr=subprocess.STDOUT,
                          shell=True)
    print("meta blk store test completed")


def logstore_nightly(options, addln_opts):
    print("log store test started")
    cmd_opts = "--run_time=86400"
    subprocess.check_call(options.dirpath + "test_log_store_long_run " + cmd_opts + addln_opts, stderr=subprocess.STDOUT, shell=True)

    print("log store test completed")


def logstore_long_running(*args):
    options, addln_opts = parse_arguments()
    print(f"Running logstore_long_running with options: {options} and additional options: {addln_opts}")
    logstore_nightly(options, addln_opts)


def meta_long_running(*args):
    options, addln_opts = parse_arguments()
    print(f"Running meta_long_running with options: {options} and additional options: {addln_opts}")
    meta_nightly(options, addln_opts)


def main():
    options, addln_opts = parse_arguments()
    test_suite_name = options.test_suits
    try:
        # Retrieve the function based on the name provided in options.test_suits
        test_suite_function = globals().get(test_suite_name)
        if callable(test_suite_function):
            print(f"Running {test_suite_name} with options: {options}")
            test_suite_function(options, addln_opts)
        else:
            print(f"Test suite '{test_suite_name}' is not a callable function.")
    except KeyError:
        print(f"Test suite '{test_suite_name}' not found.")


if __name__ == "__main__":
    main()
