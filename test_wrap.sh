#!/bin/bash
#set -x

cmd=$*
run_num=0
run_status=()
level=()

run_cmd() {
    echo "Running test run_num=$run_num: $1"
    echo "Command: $*"
    echo "----------------------------------------------------------------------------"
    $*
    status=$?

    if [ $status -eq 0 ] ; then
        echo "---------------------------------------------------------------------------"
        echo "Test success run_num=$run_num: $1"
        run_status+=("Success")
    else
        echo "---------------------------------------------------------------------------"
        echo "Test failed run_num=$run_num: $1"
        run_status+=("FAILED")
    fi
    echo "*******************************************************************************************"
}

report() {
    echo "######################################"
    echo "Report:"
    echo "----------"
    printf "%-7s %-10s %-20s\n" "Run#" "Status" "DbgLevel"
    for i in ${!run_status[@]}; do
        printf "%-7d %-10s %-20s\n" $((i+1)) ${run_status[$i]} "${level[$i]}"
    done
    echo "######################################"
}


read -r -a array <<< "$*"
log_mods=""
if [ ${array[0]} == "--retry_log_mods" ] ; then
    log_mods=${array[1]}
    base_cmd=""
    for i in `seq 3 ${#array[@]}`; do 
        i=$((i-1))
        base_cmd="$base_cmd ${array[$i]}"
    done
else
    base_cmd=$*
fi

echo "Log mods for retry = " $log_mods
echo "*******************************************************************************************"

cmd=$base_cmd
level+=("Normal")
run_cmd $cmd
if [ ${run_status[$run_num]} == "Success" ] ; then
    report
    exit 0
fi

if [ "$log_mods" != "" ] ; then
    run_num=$(($run_num+1))
    cmd="$base_cmd --log_mods $log_mods"
    level+=("$log_mods")
    run_cmd $cmd
    if [ ${run_status[$run_num]} != "Success" ] ; then
        report
        exit 1
    fi
fi


run_num=$(($run_num+1))
cmd="$base_cmd -v trace"
level+=("All mods trace")
run_cmd $cmd
if [ ${run_status[$run_num]} != "Success" ] ; then
    report
    exit 1
fi

run_num=$(($run_num+1))
cmd="$base_cmd -v debug"
level+=("All mods debug")
run_cmd $cmd
if [ ${run_status[$run_num]} != "Success" ] ; then
    report
    exit 1
fi


report
exit 1
