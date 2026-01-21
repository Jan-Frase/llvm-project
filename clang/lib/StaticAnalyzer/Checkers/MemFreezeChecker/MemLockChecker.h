//
// Created by jan on 11/10/25.
//

#ifndef LLVM_MEMFREEZECHECKER_H
#define LLVM_MEMFREEZECHECKER_H
#include "MemLockBugReporter.h"
#include "MemLockConfigHandler.h"

#include "clang/StaticAnalyzer/Core/Checker.h"

namespace clang {
namespace ento {
namespace memfreeze {

class MemLockChecker final : public Checker<check::PreCall, check::PostCall, check::DeadSymbols, check::Location> {

public:
  explicit MemLockChecker() : bug_reporter(*this) {}
  /*
   * ---> Checker entry points <---
   */

  void checkPreCall(const CallEvent &call_event, CheckerContext &context) const;

  void checkPostCall(const CallEvent &call, CheckerContext &context) const;

  void checkDeadSymbols(SymbolReaper &sym_reaper, CheckerContext &context) const;

  void checkLocation(SVal location, bool is_load, const Stmt *statement, CheckerContext &context) const;

  /*
   * ---> Various functions <---
   */

  MemLockConfigHandler config_handler;
private:

  /// Checks if a request is used by nonblocking calls multiple times
  /// in sequence without an intermediate wait.
  ///
  void checkDoubleFreeze(const CallEvent &PreCallEvent,
                              CheckerContext &Ctx, const int buffer_idx, const int request_idx, State freeze_state) const;

  /// Checks if the request used by the wait function was not used at all
  /// before.
  ///
  void checkUnmatchedUnfreeze(const CallEvent &PreCallEvent,
                           CheckerContext &Ctx, const int request_idx) const;

  /// Check if a nonblocking call is not matched by a wait.
  /// If a memory region is not alive and the last function using the
  /// request was a nonblocking call, this is rated as a missing wait.
  void checkMissingUnfreeze(SymbolReaper &SymReaper,
                         CheckerContext &Ctx) const;

  /// Check if a memory region was written to before a matching wait call was reached.
  void checkUnsafeBufferAccess(SVal Loc, const Stmt *S, CheckerContext &C, bool IsLoad) const;

  MemLockBugReporter bug_reporter;
};

} // namespace memfreeze
} // namespace ento
} // namespace clang
#endif // LLVM_MEMFREEZECHECKER_H
