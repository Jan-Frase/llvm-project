//
// Created by jan on 11/11/25.
//

#ifndef LLVM_MEMFREEZEBUGREPORTER_H
#define LLVM_MEMFREEZEBUGREPORTER_H
#include "MemFreezeMap.h"

#include "clang/StaticAnalyzer/Core/Checker.h"

namespace clang {
namespace ento {
namespace memfreeze {

class MemFreezeBugReporter {
public:
   MemFreezeBugReporter(const CheckerBase &CB)
      : UnmatchedWaitBugType(&CB, "Unmatched wait", MemFreezeError),
        MissingWaitBugType(&CB, "Missing wait", MemFreezeError),
        DoubleNonblockingBugType(&CB, "Double nonblocking", MemFreezeError) {}

  void reportDoubleNonblocking(const CallEvent &MPICallEvent,
                               const AsyncOperation &AO,
                               const MemRegion *const RequestRegion,
                               const ExplodedNode *const ExplNode,
                              BugReporter &BReporter) const;

  void reportMissingWait(const AsyncOperation &AO,
                         const MemRegion *const RequestRegion,
                         const ExplodedNode *const ExplNode,
                         BugReporter &BReporter) const;

  void reportUnmatchedWait(const CallEvent &CE,
                           const MemRegion *const RequestRegion,
                           const ExplodedNode *const ExplNode,
                           BugReporter &BReporter) const;

private:
  const llvm::StringLiteral MemFreezeError = "Memory Freeze Error";
  const BugType UnmatchedWaitBugType;
  const BugType MissingWaitBugType;
  const BugType DoubleNonblockingBugType;
};

}
}
}


#endif // LLVM_MEMFREEZEBUGREPORTER_H
