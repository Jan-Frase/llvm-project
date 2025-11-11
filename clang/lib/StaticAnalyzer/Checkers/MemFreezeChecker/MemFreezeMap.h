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

// This represents something like Request in MPI.
// So some sort of object that manages a non-blocking operation.
// It keeps track of the state of the operation and the relevant memory.
class AsyncOperation {
public:
  enum State : unsigned char { Frozen, Unfrozen };

  AsyncOperation(State S, const MemRegion *BufferRegion) : CurrentState{S}, BufferRegion {BufferRegion} {}

  // TODO: Can this be deleted?
  void Profile(llvm::FoldingSetNodeID &Id) const {
    Id.AddInteger(CurrentState);
  }

  // TODO: Delete?
  bool operator==(const AsyncOperation &ToCompare) const {
    return CurrentState == ToCompare.CurrentState;
  }

  const State CurrentState;
  const MemRegion *BufferRegion;
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
