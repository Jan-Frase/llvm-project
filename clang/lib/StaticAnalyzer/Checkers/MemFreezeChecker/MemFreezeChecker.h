//
// Created by jan on 11/10/25.
//

#ifndef LLVM_MEMFREEZECHECKER_H
#define LLVM_MEMFREEZECHECKER_H
#include "MemFreezeBugReporter.h"

#include "clang/StaticAnalyzer/Core/Checker.h"

namespace clang {
namespace ento {
namespace memfreeze {
class MemFreezeChecker
    : public Checker<check::PreCall, check::DeadSymbols, check::Bind> {

public:
  MemFreezeChecker() : BReporter(*this) {}
  /*
   * ---> Checker entry points <---
   */

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;

  void checkBind(SVal Loc, SVal Val, const Stmt *S, bool AtDeclInit, CheckerContext &C) const;

  /*
   * ---> Various functions <---
   */

private:

  /// Checks if a request is used by nonblocking calls multiple times
  /// in sequence without an intermediate wait.
  ///
  void checkDoubleFreeze(const CallEvent &PreCallEvent,
                              CheckerContext &Ctx, const MemFreezeAttr *FreezeAttr) const;

  /// Checks if the request used by the wait function was not used at all
  /// before.
  ///
  void checkUnmatchedUnfreeze(const CallEvent &PreCallEvent,
                           CheckerContext &Ctx) const;

  /// Check if a nonblocking call is not matched by a wait.
  /// If a memory region is not alive and the last function using the
  /// request was a nonblocking call, this is rated as a missing wait.
  void checkMissingUnfreeze(SymbolReaper &SymReaper,
                         CheckerContext &Ctx) const;

  /// Check if a memory region was written to before a matching wait call was reached.
  /// TODO: What about reads?
  void checkUnsafeBufferWrite(SVal Loc, const Stmt *S, CheckerContext &C) const;

  MemFreezeBugReporter BReporter;
};

} // namespace memfreeze
} // namespace ento
} // namespace clang
#endif // LLVM_MEMFREEZECHECKER_H
