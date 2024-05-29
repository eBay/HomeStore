#!/usr/bin/env python3
## @file long_running.py
#

import sys
import argparse
import index_test
import log_meta_test


def parse_arguments():
    parser = argparse.ArgumentParser(description='Run long-running tests.')
    parser.add_argument('-t', '--test_suits', help='Test suits to run', default='')
    args, service_args = parser.parse_known_args()
    return args, service_args


def index_long_running(*args):
    index_test.long_running(*args)


def logstore_long_running(*args):
    log_meta_test.logstore_long_running(*args)


def meta_long_running(*args):
    log_meta_test.meta_long_running(*args)

# def data_long_running(*args):
#     data.long_running(*args)


def main():
    args, service_args = parse_arguments()

    # Check if the test_suits argument is provided and is valid
    if args.test_suits:
        if args.test_suits == 'index_long_running':
            index_long_running(service_args)
        elif args.test_suits == 'logstore_long_running':
            logstore_long_running(service_args)
        elif args.test_suits == 'meta_long_running':
            meta_long_running(service_args)
        # elif args.test_suits == 'data_long_running':
        #     data_long_running(service_args)
        else:
            print(f"Unknown test suite: {args.test_suits}")
            sys.exit(1)
    else:
        print("No test suite specified. Use the --test_suits option.")
        sys.exit(1)


if __name__ == "__main__":
    main()