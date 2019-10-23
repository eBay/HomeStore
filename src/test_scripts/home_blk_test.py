# 
# This script can be run with
#    python3.7 home_blk_test.py -m "file1","file2" -a "localhost" -d "../"
# This script inject different type of errors when IOs are happening and verify the data after error is injected. It 
# uses different tools to inject errors like flip , randomly reboot the AM.
# When error happens, it depends on file system to be in read only mode to verify the data. So it can work only with
# ext4 filesystem.
# After each test client POD need to be remounted to bring back the file system to read/write mode.
#

import sys
import getopt
import array
import random
import datetime
from subprocess import Popen
from time import sleep
from home_blk_flip import *

opts,args = getopt.getopt(sys.argv[1:], 't:m:a:d:', ['test_type=', 'mnt_points=', 'am_ip_addrs=', 'dirpath='])
dirpath = "./"
test_type = "io_error_tests"

# parse arguments
for opt,arg in opts:

    if opt in ('-m', '--mnt_points'):
        mnt_point = arg

    if opt in ('-t', '--test_type'):
        test_type = arg
        if (test_type != "io_error_tests" and test_type != "panic_tests" and test_type != "drive_fatal_tests" 
            and test_type != "reboot_one_am_tests" and test_type != reboot_all_am_tests):
            print("expected test type : io_error_tests, panic_tests, drive_fatal_tests, reboot_one_am_tests, reboot_all_am_tests")
            sys.exit(-1)
    if opt in ('-a', '--am_ip_addrs'):
        ip_addrs = arg
        ip_addr_list = list(ip_addrs.split(",")) 
    if opt in ('-d', '--dirpath'):
        dirpath = arg

# Print arguements
print ("mnt_points:", mnt_point)
print ("ip addresses:", ip_addr_list)
print("dir path:", dirpath )

# Start IO process
file_args = "--input-files=" + mnt_point
process = Popen([dirpath + "test_load", "--gtest_filter=*File*", file_args, "--run_time=1800"])

# Inject error after 900 seconds
sleep(900)

# Select AM to inject error
random.seed(datetime.datetime.now())
x = random.randrange(0, len(ip_addr_list))

# Inject error
if test_type == "io_error_tests" and test_type == "panic_tests":
    set_flip(ip_addr_list[x], test_type)

if test_type == "drive_fatal_tests":
    set_flip(ip_addr_list[x], test_type)
    # reboot AM after few minutes

if test_type == "reboot_one_am_tests":
    print("invalid test")
    # reboot any one AM

if test_type == "reboot_all_am_tests":
    # reboot all AMs
    print("invalid test")

p_status = process.wait()
if p_status != 0:
    print ("test failed")
    sys.exit(-1)
sys.exit(0)
