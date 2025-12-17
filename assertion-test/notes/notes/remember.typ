
== Tools
Clang-query - useful to create and test ast matchers - clang-query invalid_minimal.c -- -I/usr/include/mpich-x86_64 
dot - useful to create pngs from cfg dumps --  dot -Tpng /tmp/CFG-8277d9.dot -o cfg.png && firefox cfg.png
mpicc -show - useful to see the flags clang needs to compile mpi things

Command to run my checker:
../../llvm-project/build/bin/clang -I/usr/include/mpich-x86_64 -L/usr/lib64/mpich/lib -Wl,-rpath -Wl,/usr/lib64/mpich/lib -Wl,--enable-new-dtags -lmpi --analyze 
-Xanalyzer -analyzer-checker=optin.memfreeze.MemFreeze minimal.c 

== Building Clang 
https://clang.llvm.org/get_started.html

