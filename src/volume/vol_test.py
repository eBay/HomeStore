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
    subprocess.call("./test_volume --run_time=360", shell=True)

def vol_delete():
    subprocess.call("./test_volume --gtest_filter=*vol_del*", shell=True)

def recovery():
    subprocess.call("./test_volume --gtest_filter=*normal_abort_random* --run_time=300", shell=True)

    for x in range(1, 300):
        subprocess.call("./test_volume --gtest_filter=*recovery_abort* --run_time=300", shell=True)

if test_suits == "normal":
    normal()
    
if test_suits == "recovery":
    recovery()
    
if test_suits == "vol_del":
    vol_delete()
