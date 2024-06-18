#!/usr/bin/env python3
## @file data_test.py

import subprocess
import sys

sys.stdout.flush()
import argparse


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


def data_nightly(options, addln_opts):
    print("Data service test started")
    cmd_opts = "--num_io=999999"
    subprocess.check_call(
        options.dirpath + "test_data_service --gtest_filter=*TestRandMixIOLoad* " + cmd_opts + addln_opts,
        stderr=subprocess.STDOUT, shell=True)

    print("Data service test completed")


def long_running(*args):
    options, addln_opts = parse_arguments()
    print(f"Running data_long_running with options: {options} and additional options: {addln_opts}")
    data_nightly(options, addln_opts)


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
