#!/usr/bin/env python

import subprocess
import os
import sys
import getopt
from time import sleep

# slack details
slackcmd = ("./slackpost "
            "https://hooks.slack.com/services/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 "
            "sds-homestore "
            "regression-bot \""
           )

def slackpost(msg):
    cmd = slackcmd + msg + "\""
    subprocess.call(cmd, shell=True)

opts,args = getopt.getopt(sys.argv[1:], 't', ['test_suits='])
test_suits = ""

for opt,arg in opts:
    if opt in ('-t', '--test_suits'):
        test_suits = arg
        print(("testing suits (%s)")%(arg))

def normal():
    status = subprocess.check_output("./test_volume \
            --run_time=12000 --max_num_writes=5000000", shell=True)
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

def load():
    status = subprocess.check_output("./test_load \
            --num_io=100000000000 --num_keys=1000000 --run_time=21600 --gtest_filter=Map* ", shell=True)
    f = open( '/home/homestore/log_load.txt', 'w+' )
    f.write(status)
    f.close()
    return '[  PASSED  ] 1 test' in status

def sequence():
    slackpost("Regression Test Starting")
    if normal() == False:
        slackpost("Normal Test Failed")
        sys.exit(0)
    slackpost("Normal Test Passed")
    sleep(5)
    if load() == False:
        slackpost("Load Test Failed")
        sys.exit(0)
    slackpost("Load Test Passed")
    sleep(5)
    if mapping() == False:
        slackpost("Mapping Test Failed")
        sys.exit(0)
    slackpost("Mapping Test Passed")

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

if test_suits == "load":
    load()
