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
    output = subprocess.check_output("./test_volume --run_time=3600", shell=True)
    if output == false:
        print("Normal volume test error")
    return output

def vol_delete():
    output = subprocess.check_output("./test_volume --gtest_filter=*vol_del*", shell=True)
    if output == false:
        print("Delete volume test error")
    return output

def recovery():
    subprocess.call("./test_volume --gtest_filter=*normal_abort_random* --run_time=300 --install_crash=0", shell=True)
    for x in range(1, 50):
        subprocess.call("./test_volume --gtest_filter=*recovery_abort* --run_time=300 --install_crash=0", shell=True)

def mapping():
    output = subprocess.check_output("./test_mapping --num_ios=1000000", shell=True)
    if output == false:
        print("Mapping test error")
    return output

def sequence():
    if normal() == false:
        sys.exit(0)
    if vol_delete() == false:
        sys.exit(0)
    if mapping() == false:
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
