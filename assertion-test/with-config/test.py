import subprocess
import os

SHOW_WARNINGS = True

ANALYZER_COMMAND = [
    "/home/jan/bachelor/llvm-project/build/bin/clang",
    "-I/usr/include/mpich-x86_64",
    # "--output=html",
    # "-L/usr/lib64/mpich/lib",
    # "-Wl,-rpath",
    # "-Wl,/usr/lib64/mpich/lib",
    # "-Wl,--enable-new-dtags",
    # "-lmpi",
    "--analyze",
    "-Xclang",
    "-analyzer-checker=optin.memlock.MemLock",
    "-Xanalyzer",
    "-analyzer-config",
    "-Xanalyzer",
    "",
    "",
]

TEST_FILES_ROOT = "/home/jan/bachelor/llvm-project/assertion-test/"

dirs = os.listdir(TEST_FILES_ROOT)
dirs.sort()

print(dirs)
did_everything_pass = True

for dir in dirs:
    dir_path = os.path.join(TEST_FILES_ROOT, dir)
    if not os.path.isdir(dir_path):
       continue 

    print()
    print("==============================")
    print("Checking ", dir)

    all_files_in_dir = os.listdir(dir_path) 
    all_files_in_dir.sort()

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


        ANALYZER_COMMAND[len(ANALYZER_COMMAND) - 2] = f"optin.memlock.MemLock:Config=./{dir}/config.yaml"

        total_file_name = dir_path + "/" + file_name
        ANALYZER_COMMAND[len(ANALYZER_COMMAND) - 1] = total_file_name

        print()
        print("------------------------------")
        print("Now testing: ", file_name)
        print(" ".join(ANALYZER_COMMAND))
        result = subprocess.run(ANALYZER_COMMAND, capture_output=True, text=True)

        print("Should emit warning: ", should_emit_warning)

        if result.returncode == 1:
            print("Clang crashed!")

        did_emit_warning = False
        if "buffer-write" in file_name:
           did_emit_warning = "Premature buffer reuse" in result.stderr
        if "double-freeze" in file_name:
            did_emit_warning = "Double nonblocking" in result.stderr
        if "missing-unfreeze" in file_name:
            did_emit_warning = "has no matching wait" in result.stderr
        if "unmatched_unfreeze" in file_name:
            did_emit_warning = "has no matching nonblocking" in result.stderr

        if SHOW_WARNINGS:
            print()
            print(result.stderr)

        if should_emit_warning == did_emit_warning:
            print("-> Correct!")
        else:
            did_everything_pass = False
            print("-> Oh no :(")

print("Quick clean up :)")
for file in os.listdir(TEST_FILES_ROOT):
    if file.endswith(".plist"):
        os.remove(TEST_FILES_ROOT + file)

if did_everything_pass:
    print("ALL GOOD!")
else:
    print("something went wrong")
