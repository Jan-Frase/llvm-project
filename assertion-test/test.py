import subprocess
import os

SHOW_WARNINGS = True

ANALYZER_COMMAND = [
    "/home/jan/BA-Thesis/BA-Code/llvm-project/build/bin/clang",
    "--analyze",
    "-Xclang",
    "-analyzer-checker=optin.memfreeze.MemFreeze",
    "-I/usr/include/mpich-x86_64",
    # "--output=html",
    # "-L/usr/lib64/mpich/lib",
    # "-Wl,-rpath",
    # "-Wl,/usr/lib64/mpich/lib", 
    # "-Wl,--enable-new-dtags",
    # "-lmpi",
    "",
]

TEST_FILES_ROOT = "/home/jan/BA-Thesis/BA-Code/assertion-tests/"

dirs = os.listdir(TEST_FILES_ROOT)
dirs.sort()

print(dirs)

for dir in dirs:
    dir_path = os.path.join(TEST_FILES_ROOT, dir)
    if not os.path.isdir(dir_path):
       continue 

    print()
    print("==============================")
    print("Checking ", dir)

    all_files_in_dir = os.listdir(dir_path) 
    all_files_in_dir.sort()

    did_everything_pass = True
    for file_name in all_files_in_dir: 
        if not file_name.endswith(".c"):
            continue

        should_emit_warning = False
        if file_name.startswith("buffer-write"):
            should_emit_warning = True
        if file_name.startswith("double-freeze"):
            should_emit_warning = True 
        if file_name.startswith("missing-unfreeze"):
            should_emit_warning = True
        if file_name.startswith("unmatched_unfreeze"):
            should_emit_warning = True

        total_file_name = dir_path + "/" + file_name
        ANALYZER_COMMAND[len(ANALYZER_COMMAND) - 1] = total_file_name

        print()
        print("------------------------------")
        print("Now testing: ", file_name)
        result = subprocess.run(ANALYZER_COMMAND, capture_output=True, text=True)

        if result.returncode == 1:
            print("Clang crashed!")

        did_emit_warning = False
        if file_name.startswith("buffer-write"):
           did_emit_warning = "Premature buffer reuse" in result.stderr
        if file_name.startswith("double-freeze"):
            did_emit_warning = "Double nonblocking" in result.stderr
        if file_name.startswith("missing-unfreeze"):
            did_emit_warning = "has no matching wait" in result.stderr
        if file_name.startswith("unmatched_unfreeze"):
            did_emit_warning = "has no matching nonblocking" in result.stderr

        if SHOW_WARNINGS:
            print(result.stderr)

        if should_emit_warning == did_emit_warning:
            print("-> Correct!")
        else:
            did_everything_pass = False
            print("-> Oh no :(")

# print("Quick clean up :)")
        # for file in os.listdir(TEST_FILES_ROOT):
            #    if file.endswith(".plist"):
# os.remove(TEST_FILES_ROOT + file)

    if did_everything_pass:
        print("ALL GOOD!")
    else:
        print("something went wrong")
