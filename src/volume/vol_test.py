#!/usr/bin/env python

import subprocess
import os
import sys
import getopt

opts,args = getopt.getopt(sys.argv[1:], 't', ['test_suits=']) 

test_suits = ""
for opt,arg in opts:
    if opt in ('-t', '--test_suits'):
        test_suits = arg
        print(("testing suits (%s)")%(arg))

def normal():
    status = subprocess.check_output("./test_volume --run_time=12000", shell=True)
    f = open( '/home/homestore/log_normal.txt', 'w+' )
    f.write(status)
    f.close()
    return '[  PASSED  ] 1 test' in status

def vol_delete():
    status = subprocess.check_output("./test_volume --gtest_filter=*vol_del*", shell=True)
    f = open( '/home/homestore/log_delete.txt', 'w+' )
    f.write(status)
    f.close()
    return '[  PASSED  ] 1 test' in status

def recovery():
    status = subprocess.check_output("./test_volume \
            --gtest_filter=*normal_abort_random* --run_time=300 --install_crash=0", shell=True)
    f = open( '/home/homestore/log_abort.txt', 'w+')
    f.write(status)
    f.close()
    for x in range(1, 50):
        status = subprocess.call("./test_volume \
                --gtest_filter=*recovery_abort* --run_time=300 --install_crash=0", shell=True)
        f = open( '/home/homestore/log_recovery.txt', 'a+' )
        f.write(status)
        f.close()

def mapping():
    status = subprocess.check_output("./test_mapping --num_ios=10000000", shell=True)
    f = open( '/home/homestore/log_mapping.txt', 'w+' )
    f.write(status)
    f.close()
    return '[  PASSED  ] 1 test' in status

def sequence():
    if normal() == False:
        sys.exit(0)
    if mapping() == False:
        sys.exit(0)

if test_suits == "normal":
    normal()
    
if test_suits == "vol_del":
    vol_delete()

if test_suits == "recovery":
    recovery()
    
if test_suits == "mapping":
    mapping()

if test_suits == "sequence":
    sequence()
