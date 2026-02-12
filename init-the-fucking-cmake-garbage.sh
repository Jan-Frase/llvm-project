cd build

cmake \
  -DLLVM_ENABLE_PROJECTS=clang \
  -DCMAKE_BUILD_TYPE=Debug\
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DLLVM_PARALLEL_LINK_JOBS=2 \
  -DLLVM_USE_LINKER=mold \
  -G "Ninja" \
  ../llvm
