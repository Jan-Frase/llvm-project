//
// Created by jan on 11/10/25.
//

#include "MemFreezeChecker.h"

#include "../../../../../build/tools/clang/include/clang/AST/Attrs.inc"
#include "../../../CodeGen/ABIInfoImpl.h"
#include "MemFreezeMap.h"

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

namespace clang {
namespace ento {
namespace memfreeze {
/*
 * ---> Checker entry points <---
 */

void MemFreezeChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Get the function declaration...
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(Call.getDecl());

  // ... check if it has the MemFreezeAttr ...
  if (const auto *FreezeAttr = FD->getAttr<MemFreezeAttr>()) {
    checkDoubleFreeze(Call, C, FreezeAttr);
  }

  // ... or the MemUnfreezeAttr.
  if (const auto *UnfreezeAttr = FD->getAttr<MemUnfreezeAttr>()) {
  }
}

void MemFreezeChecker::checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const {

}

void MemFreezeChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, bool AtDeclInit, CheckerContext &C) const {

}

/*
 * ---> Various functions <---
 */


void MemFreezeChecker::checkDoubleFreeze(const CallEvent &PreCallEvent,
                            CheckerContext &Ctx, const MemFreezeAttr *FreezeAttr) const {
  // Get the Buffer and OperationReference according to the annotation.
  const SVal BufferSVal = PreCallEvent.getArgSVal(FreezeAttr->getBuffer());
  const SVal OpRefSval = PreCallEvent.getArgSVal(FreezeAttr->getOperationReference());

  // If they aren't defined, the annotation must be faulty.
  if (BufferSVal.isUndef() || OpRefSval.isUndef()) {
    llvm::errs() << "BufferSVal or OperationReferenceSVal is undefined\n";
    return;
  }

  const MemRegion *BufferRegion = BufferSVal.getAsRegion();
  const MemRegion *OpRefRegion = OpRefSval.getAsRegion();

  // Check if we are already aware of this operation.
  const AsyncOperation *ExistingAO = Ctx.getState()->get<AsyncOperationMap>(OpRefRegion);

  // If we are, and it's already frozen, it's an error!
  if (ExistingAO && ExistingAO->CurrentState == AsyncOperation::State::Frozen) {
    ExplodedNode *ErrorNode = Ctx.generateNonFatalErrorNode();
    // BReporter.reportDoubleNonblocking(PreCallEvent, *ExistingAO, OpRefRegion, ErrorNode, Ctx.getBugReporter());
    llvm::errs() << "Double nonblocking!\n";
    Ctx.addTransition(ErrorNode->getState(), ErrorNode);
    return;
  }

  // If everything is fine, add the newly found operation.
  const AsyncOperation AO(AsyncOperation::State::Frozen, BufferRegion);
  ProgramStateRef State = Ctx.getState()->set<AsyncOperationMap>(OpRefRegion, AO);
  Ctx.addTransition(State);
}

void MemFreezeChecker::checkUnmatchedUnfreeze(const CallEvent &PreCallEvent,
                         CheckerContext &Ctx) const {

}

void MemFreezeChecker::checkMissingUnfreeze(SymbolReaper &SymReaper,
                       CheckerContext &Ctx) const {

}

void MemFreezeChecker::checkUnsafeBufferWrite(SVal Loc, const Stmt *S, CheckerContext &C) const {

}

}

// Registers my checker.
void registerMemFreezeChecker(CheckerManager &mgr) {
  mgr.registerChecker<memfreeze::MemFreezeChecker>();
}

bool shouldRegisterMemFreezeChecker(const CheckerManager &mgr) {
  return true;
}

}
}
