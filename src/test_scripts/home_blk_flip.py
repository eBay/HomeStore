from __future__ import print_function

import random
import logging
import datetime
from flip_rpc_client import *

def vol_vchild_error(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("vol_vchild_error",
                              fspec.FlipFrequency(count=1, percent=100),
                              [])
    print("vol_vchild_error set")

def vol_comp_error(address):
    fclient = FlipRPCClient(address)
    fclient.inject_ret_flip("delay_us_and_inject_error_on_completion",
                             fspec.FlipFrequency(count=1, percent=100),
                             [
                                fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                             ],
                             fspec.ParamValue(long_value=20)
                           )
    print("vol_comp_error")

def space_full_error(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("varsize_blkalloc_no_blks",
                            fspec.FlipFrequency(count=1, percent=100),
                            [
                                fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                            ]
                            )
    print("space_full_error")

def btree_split_failure(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("btree_split_failure",
                             fspec.FlipFrequency(count=1, percent=100),
                             [
                                fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                             ]
                            )
    print("btree_split_failure")

def btree_write_comp_fail(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("btree_write_comp_fail",
                              fspec.FlipFrequency(count=1, percent=100),
                              [
                                fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                              ]
                            )
    print("btree_write_cmpl_fail")

def btree_read_fail(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("btree_read_fail",
                              fspec.FlipFrequency(count=1, percent=100),
                              [
                                  fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                              ]
                            )
    print("btree_read_fail")

def btree_write_fail(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("btree_write_fail",
                              fspec.FlipFrequency(count=1, percent=100),
                              [
                                fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                              ]
                             )
                             
    print("btree_write_fail")
    
def btree_refresh_fail(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("btree_refresh_fail",
                              fspec.FlipFrequency(count=1, percent=100),
                              [
                                fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                              ]
                            )
    print("btree_refresh_fail")

def btree_split_panic(address):
    try:
        fclient = FlipRPCClient(address)
        fclient.inject_test_flip("btree_split_panic",
                                  fspec.FlipFrequency(count=1, percent=100),
                                  [
                                    fspec.FlipCondition(oper=fspec.Operator.DONT_CARE)
                                  ]
                                )
        print("btree_split_panic")
    except:
        print("could not set flip")
    
def io_write_error(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("io_write_error_flip",
                              fspec.FlipFrequency(count=1, percent=100),
                             fspec.FlipCondition(oper=fpesc.Operator.DONT_CARE)
                            )
    print("io_write_error")

def btree_blkalloc_no_blks(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("fixed_blkalloc_no_blks",
                              fspec.FlipFrequency(count=1, percent=100),
                              fspec.FlipCondition(oper=fpesc.Operator.DONT_CARE)
                            )
    print("btree_blkalloc_no_blks")

def io_read_error(address):
    fclient = FlipRPCClient(address)
    fclient.inject_test_flip("io_read_error_flip",
                              fspec.FlipFrequency(count=1, percent=100),
                              fspec.FlipCondition(oper=fpesc.Operator.DONT_CARE)
                            )
    print("io_read_error")

io_error_tests = [
         vol_vchild_error,
         vol_comp_error,
         space_full_error,
         btree_split_failure,
         btree_write_comp_fail,
         btree_read_fail,
         btree_write_fail,
         btree_refresh_fail,
         btree_blkalloc_no_blks,
        ]

panic_tests = [
                btree_split_panic
              ]

drive_fatal_tests = [
                    io_write_error,
                    io_read_error
                   ]

def set_flip( ip_addr, test_type ):
    address = ip_addr + ":50051"
    if test_type == "io_error_tests":
        random.seed(datetime.datetime.now())
        x = random.randrange(0, len(io_error_tests) - 1)
        io_error_tests[x](address)
    if test_type == "panic_tests":
        panic_tests[0](address)
    if test_type == "drive_fatal_test":
        random.seed(datetime.datetime.now())
        x = random.randrange(0, len(drive_fatal_tests) - 1)
        drive_fatal_tests[x](address)
        
