import subprocess
def normal():
    subprocess.call("./test_volume --run_time=360", shell=True)

def recovery():
    subprocess.call("./test_volume --gtest_filter=*normal_abort_random* --run_time=300", shell=True)

    for x in range(1, 300):
        subprocess.call("./test_volume --gtest_filter=*recovery_abort* --run_time=300", shell=True)

#normal()
recovery()
