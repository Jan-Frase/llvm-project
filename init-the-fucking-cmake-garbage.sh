cd build-rel

cmake \
  -DLLVM_ENABLE_PROJECTS=clang\
  -DLLVM_ENABLE_RUNTIMES=openmp\
  -DCMAKE_BUILD_TYPE=Release\
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DLLVM_PARALLEL_LINK_JOBS=2 \
  -DLLVM_USE_LINKER=mold \
  -G "Ninja" \
  ../llvm
