#!/bin/bash
#set -x

cmd="$*"
run_num=0
run_status=()
level=()

run_cmd() {
    echo "Running test run_num=$run_num: $1"
    echo "Command: $*"
    echo "----------------------------------------------------------------------------"
    $@ & # run in background

    my_pid=$!  # get process id

    bin_name="$(ps -p $my_pid -o comm=)"  # get running process name associated with that pid
    echo running pid is $my_pid and process is $bin_name

    sleep_cnt=0
    while   [ -d /proc/$my_pid ] 
    do
        if [[ "$sleep_cnt" -gt 600 ]]; then  # set timeout to be 30 mins
            curl http://localhost:5000/api/v1/dumpStackTrace
            sleep 10 # sleep for a while for dump stack trace log to finish flushing;
            echo Killing $my_pid $bin_name because of timeout
            kill -9 $my_pid
            exit 1
        fi
        sleep 3
        ((sleep_cnt++))
    done

    echo "$my_pid $bin_name completed running, checking return status"
    wait $my_pid
    # The variable $? always holds the exit code of the last command to finish.
    # Here it holds the exit code of $my_pid, since wait exits with that code. 

    status=$?
    echo The exit status of the process was $status

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
    log_mods="${array[1]}"
    base_cmd=""
    for i in `seq 3 ${#array[@]}`; do 
        i=$((i-1))
        base_cmd="$base_cmd ${array[$i]}"
    done
else
    base_cmd="$*"
fi

echo "Log mods for retry = " $log_mods
echo "*******************************************************************************************"

cmd="$base_cmd"
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


#run_num=$(($run_num+1))
#cmd="$base_cmd -v trace"
#level+=("All mods trace")
#run_cmd $cmd
#if [ ${run_status[$run_num]} != "Success" ] ; then
#    report
#    exit 1
#fi

#run_num=$(($run_num+1))
#cmd="$base_cmd -v debug"
#level+=("All mods debug")
#run_cmd $cmd
#if [ ${run_status[$run_num]} != "Success" ] ; then
#    report
#    exit 1
#fi


report
exit 1
