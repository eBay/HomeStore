#!/usr/bin/env python3
## @file index_test.py
import subprocess
import sys
import getopt
import argparse


class TestFailedError(Exception):
    pass


def run_test(options, type):
    cmd_opts = f"--gtest_filter=BtreeConcurrentTest/{type}.ConcurrentAllOps --gtest_break_on_failure --cleanup_after_shutdown={options['cleanup_after_shutdown']} --init_device={options['init_device']}  --preload_size={options['preload_size']} {options['log_mods']} --run_time={options['run_time']} --num_iters={options['num_iters']} --num_entries={options['num_entries']} --num_threads={options['threads']} --num_fibers={options['fibers']} {options['dev_list']} {options['op_list']}"
    # print(f"Running test with options: {cmd_opts}")
    try:
        subprocess.check_call(f"{options['dirpath']}test_index_btree {cmd_opts}", stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Test failed: {e}")
        raise TestFailedError(f"Test failed for type {type}")
    print("Test completed")


def run_crash_test(options, crash_type='put', type=0):
    cmd_opts = f"--gtest_filter=IndexCrashTest/{type}.long_running_{crash_type}_crash --gtest_break_on_failure --min_keys_in_node={options['min_keys_in_node']} --max_keys_in_node={options['max_keys_in_node']} --num_entries_per_rounds={options['num_entries_per_rounds']} --init_device={options['init_device']} {options['log_mods']} --run_time={options['run_time']} --num_entries={options['num_entries']} --num_rounds={options['num_rounds']} {options['dev_list']} "
    # print(f"Running test with options: {cmd_opts}")
    try:
        subprocess.check_call(f"{options['dirpath']}test_index_crash_recovery {cmd_opts}", stderr=subprocess.STDOUT,
                              shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Test failed: {e}")
        raise TestFailedError(f"Test failed for type {type}")
    print("Crash Test completed")


def parse_arguments():
    # Create the parser
    parser = argparse.ArgumentParser(description='Parse command line options.')

    # Add arguments with default values
    parser.add_argument('--test_suits', help='Test suits to run', default='')
    parser.add_argument('--dirpath', help='Directory path', default='bin/')
    parser.add_argument('--op_list', help='List of operations', default='')
    parser.add_argument('--log_mods', help='Log modules', default='')
    parser.add_argument('--threads', help='Number of threads', type=int, default=2)
    parser.add_argument('--fibers', help='Number of fibers', type=int, default=2)
    parser.add_argument('--preload_size', help='Preload size', type=int, default=262144)  # 256K
    parser.add_argument('--num_entries', help='Number of entries', type=int, default=2097152)  # 2M
    parser.add_argument('--num_iters', help='Number of iterations', type=int, default=100000000)
    parser.add_argument('--run_time', help='Run time in seconds', type=int, default=14400)  # 4 hours
    parser.add_argument('--dev_list', help='Device list', default='')
    parser.add_argument('--cleanup_after_shutdown', help='Cleanup after shutdown', type=bool, default=False)
    parser.add_argument('--init_device', help='Initialize device', type=bool, default=True)
    parser.add_argument('--max_keys_in_node', help='Maximum num of keys in btree nodes', type=int, default=10)
    parser.add_argument('--min_keys_in_node', help='Minimum num of keys in btree nodes', type=int, default=2)
    parser.add_argument('--num_rounds', help='number of rounds for crash test', type=int, default=1000)
    parser.add_argument('--num_entries_per_rounds', help='number of rounds for crash test', type=int, default=100)

    # Parse the known arguments and ignore any unknown arguments
    args, unknown = parser.parse_known_args()

    if args.op_list:
        args.op_list = ''.join([f' --operation_list={op}' for op in args.op_list.split()])
    if args.dev_list:
        args.dev_list = f' --device_list={args.dev_list}'

    options = vars(args)

    return options


def long_runnig_index(options, type=0):
    print("Long running test started")
    print(f"options: {options}")
    run_test(options, type)
    print("Long running test completed")


def long_running_clean_shutdown(options, type=0):
    print("Long running clean shutdown started")
    options['run_time'] =  options['run_time'] // 10
    try:
        run_test(options, type)
        options['init_device'] = False
        print("Iteration 0 (aka init) completed successfully")
        for i in range(1, 10):
            run_test(options, type)
            print("Iteration {} clean shutdown completed successfully".format(i))
    except TestFailedError as e:
        print(f"Test failed: {e}")
        raise
    print("Long running clean shutdown completed")


def long_running_crash_put(options):
    print("Long running crash put started")
    options['num_entries'] = 1310720  # 1280K
    options['init_device'] = True
    options['run_time'] = 14400  # 4 hours
    options['preload_size'] = 1024
    print(f"options: {options}")
    run_crash_test(options, 'put', 0)
    print("Long running crash put completed")

def long_running_crash_remove(options):
    print("Long running crash remove started")
    options['num_entries'] = 1000
    options['init_device'] = True
    options['run_time'] = 14400  # 4 hours
    options['num_entries_per_rounds'] = 100
    options['min_keys_in_node'] = 2
    options['max_keys_in_node'] = 10
    print(f"options: {options}")
    run_crash_test(options, 'remove', 0)
    print("Long running crash put completed")

def long_running_crash_put_remove(options):
    print("Long running crash put_remove started")
    options['num_entries'] = 2000  # 1280K
    options['init_device'] = True
    options['run_time'] = 14400  # 4 hours
    options['preload_size'] = 1024
    options['min_keys_in_node'] = 3
    options['max_keys_in_node'] = 10
    print(f"options: {options}")
    run_crash_test(options, 'put_remove', 0)
    print("Long running crash put_remove completed")


def main():
    options = parse_arguments()
    test_suite_name = options['test_suits']
    try:
        # Retrieve the function based on the name provided in options['test_suits']
        test_suite_function = globals().get(test_suite_name)
        if callable(test_suite_function):
            print(f"Running {test_suite_name} with options: {options}")
            test_suite_function(options)
        else:
            print(f"Test suite '{test_suite_name}' is not a callable function.")
    except KeyError:
        print(f"Test suite '{test_suite_name}' not found.")


def long_running(*args):
    options = parse_arguments()
    long_runnig_index(options, 0)
    long_running_clean_shutdown(options, 0)
    long_runnig_index(options, 1)
    long_running_clean_shutdown(options, 1)
    for i in range(20):
        print(f"Iteration {i + 1}")
        long_running_crash_put_remove(options)
    for i in range(50):
        print(f"Iteration {i + 1}")
        long_running_crash_remove(options)
    for i in range(5):
        print(f"Iteration {i + 1}")
        long_running_crash_put(options)
    long_runnig_index(options)
    long_running_clean_shutdown(options)


if __name__ == "__main__":
    main()
