//
// Created by jan on 11/10/25.
//

#ifndef LLVM_MEMFREEZE_H
#define LLVM_MEMFREEZE_H

#include "clang/StaticAnalyzer/Checkers/MPIFunctionClassifier.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"

namespace clang {
namespace ento {
namespace memfreeze {

enum State : unsigned char { Read_Write_Frozen, Write_Frozen, Unfrozen };
// This represents something like Request in MPI.
// So some sort of object that manages a non-blocking operation.
// It keeps track of the state of the operation and the relevant memory.
class AsyncOperation {
public:
  AsyncOperation(State S, const MemRegion *BufferRegion) : current_state{S}, buffer_region {BufferRegion} {}

  // TODO: Can this be deleted?
  void Profile(llvm::FoldingSetNodeID &Id) const {
    Id.AddInteger(current_state);
  }

  // TODO: Delete?
  bool operator==(const AsyncOperation &ToCompare) const {
    return current_state == ToCompare.current_state;
  }

  const State current_state;
  const MemRegion *buffer_region;
};

// Add a map to the State.
struct AsyncOperationMap {};
typedef llvm::ImmutableMap<const MemRegion *,
                           AsyncOperation>
    AsyncOperationMapImpl;
}  // end of namespace: memfreeze

template <>
struct ProgramStateTrait<memfreeze::AsyncOperationMap>
    : ProgramStatePartialTrait<memfreeze::AsyncOperationMapImpl> {
  static void *GDMIndex() {
    static int index = 0;
    return &index;
  }
};

} // end of namespace: ento
} // end of namespace: clang

#endif // LLVM_MEMFREEZE_H
