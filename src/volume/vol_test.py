import subprocess
def normal():
    subprocess.call("./test_volume --run_time=360", shell=True)

def recovery():
    subprocess.call("./test_volume --gtest_filter=*abort*", shell=True)
    subprocess.call("./test_volume --gtest_filter=*recovery* --run_time=120", shell=True)

#normal()
recovery()
