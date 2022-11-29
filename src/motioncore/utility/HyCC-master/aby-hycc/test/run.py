import os
import sys
import glob
import subprocess
import time

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
ABY_BIN = os.path.join(SCRIPT_DIR, "../../../../build/bin/aby-hycc");


def run_test(test_dir):
    print("===== Testing \"" + test_dir + "\" =====")
    saved_path = os.getcwd()
    os.chdir(test_dir)

    num_tests = 0
    num_errors = 0
    for circuit_spec_file in sorted(glob.glob("circuit_spec_*")):
        server_proc = subprocess.Popen([
            ABY_BIN,
            "-r", "0",
            "-c", circuit_spec_file,
            "--spec-file", "inputs.txt",
            "--perform-test",
            "-q",
        ])

        client_proc = subprocess.Popen([
            ABY_BIN,
            "-r", "1",
            "-c", circuit_spec_file,
            "--spec-file", "inputs.txt",
            "--perform-test",
            "-q",
        ])

        server_ret = server_proc.wait()
        client_ret = client_proc.wait()

        num_tests += 1
        if server_ret or client_ret:
            print("==> ERROR: \"" + test_dir + "/" + circuit_spec_file + "\" failed\n")
            num_errors += 1
        else:
            print("==> Info: \"" + test_dir + "/" + circuit_spec_file + "\" successful\n")

    os.chdir(saved_path)
    return num_tests, num_errors


num_tests = 0
num_errors = 0
for test_dir in glob.glob("test_*"):
    nt, ne = run_test(test_dir)
    num_tests += nt
    num_errors += ne

print(str(num_tests) + " tests, " + str(num_errors) + " errors")
sys.exit(num_errors > 0)
