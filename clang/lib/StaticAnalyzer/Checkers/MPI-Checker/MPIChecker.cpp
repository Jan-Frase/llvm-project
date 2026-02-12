//===-- MPIChecker.cpp - Checker Entry Point Class --------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file defines the main class of MPI-Checker which serves as an entry
/// point. It is created once for each translation unit analysed.
/// The checker defines path-sensitive checks, to verify correct usage of the
/// MPI API.
///
//===----------------------------------------------------------------------===//

#include "MPIChecker.h"

#include "../../../../../llvm/lib/CodeGen/AsmPrinter/DwarfDebug.h"

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"

namespace clang {
namespace ento {
namespace mpi {

void MPIChecker::checkDoubleNonblocking(const CallEvent &PreCallEvent,
                                        CheckerContext &Ctx) const {
  if (!FuncClassifier->isNonBlockingType(PreCallEvent.getCalleeIdentifier())) {
    return;
  }
  const MemRegion *const RequestRegion =
      PreCallEvent.getArgSVal(PreCallEvent.getNumArgs() - 1).getAsRegion();
  if (!RequestRegion)
    return;
  const ElementRegion *const RequestElementRegion = dyn_cast<ElementRegion>(RequestRegion);

  // The region must be typed, in order to reason about it.
  if (!isa<TypedRegion>(RequestRegion) || (RequestElementRegion && !isa<TypedRegion>(RequestElementRegion->getSuperRegion())))
    return;

  ProgramStateRef State = Ctx.getState();
  const Request *const OldReq = State->get<RequestMap>(RequestRegion);

  // double nonblocking detected
  if (OldReq && OldReq->RqstState == Request::RequestState::Nonblocking) {
    ExplodedNode *ErrorNode = Ctx.generateNonFatalErrorNode();
    BReporter.reportDoubleNonblocking(PreCallEvent, *OldReq, RequestRegion, ErrorNode,
                                      Ctx.getBugReporter());
    Ctx.addTransition(ErrorNode->getState(), ErrorNode);
    return;
  }

  // no error
  const bool isFullLocking = FuncClassifier->isFullLocking(PreCallEvent.getCalleeIdentifier());
  const bool isWriteLocking = FuncClassifier->isWriteLocking(PreCallEvent.getCalleeIdentifier());

  Message::MessageState msgState;
  if (isFullLocking) {
    msgState = Message::MessageState::FullLocked;
  } else if (isWriteLocking) {
    msgState = Message::MessageState::WriteLocked;
  } else {
    msgState = Message::MessageState::Unlocked;
  }

  // Extract arguments
  SVal msgRegion = PreCallEvent.getArgSVal(0);
  SVal msgCount = PreCallEvent.getArgSVal(1);

  // Construct request
  if (msgState == Message::MessageState::Unlocked ||
      msgRegion.isUnknownOrUndef() || msgCount.isUnknownOrUndef()) {
    auto NewReq = Request(Request::RequestState::Nonblocking);
    State = State->set<RequestMap>(RequestRegion, NewReq);
  } else {
    Message message(msgState, msgRegion, msgCount, PreCallEvent.getSourceRange());
    auto NewReq = Request(Request::RequestState::Nonblocking, message);
    State = State->set<RequestMap>(RequestRegion, NewReq);
  }
  Ctx.addTransition(State);
}

void MPIChecker::checkUnmatchedWaits(const CallEvent &PreCallEvent,
                                     CheckerContext &Ctx) const {
  if (!FuncClassifier->isWaitType(PreCallEvent.getCalleeIdentifier()))
    return;
  const MemRegion *const MR = topRegionUsedByWait(PreCallEvent);
  if (!MR)
    return;
  const ElementRegion *const ER = dyn_cast<ElementRegion>(MR);

  // The region must be typed, in order to reason about it.
  if (!isa<TypedRegion>(MR) || (ER && !isa<TypedRegion>(ER->getSuperRegion())))
    return;

  SmallVector<const MemRegion *, 2> ReqRegions;
  allRegionsUsedByWait(ReqRegions, MR, PreCallEvent, Ctx);
  if (ReqRegions.empty())
    return;

  ProgramStateRef State = Ctx.getState();
  ExplodedNode *ErrorNode{nullptr};

  // Check all request regions used by the wait function.
  for (const auto &ReqRegion : ReqRegions) {
    const Request *const Req = State->get<RequestMap>(ReqRegion);
    State = State->set<RequestMap>(ReqRegion, Request(Request::Wait));
    if (!Req) {
      if (!ErrorNode) {
        ErrorNode = Ctx.generateNonFatalErrorNode(State);
        State = ErrorNode->getState();
      }
      // A wait has no matching nonblocking call.
      BReporter.reportUnmatchedWait(PreCallEvent, ReqRegion, ErrorNode,
                                    Ctx.getBugReporter());
    }
  }

  if (!ErrorNode) {
    Ctx.addTransition(State);
  } else {
    Ctx.addTransition(State, ErrorNode);
  }
}

void MPIChecker::checkMissingWaits(SymbolReaper &SymReaper,
                                   CheckerContext &Ctx) const {
  ProgramStateRef State = Ctx.getState();
  const auto &Requests = State->get<RequestMap>();
  if (Requests.isEmpty())
    return;

  ExplodedNode *ErrorNode{nullptr};

  auto ReqMap = State->get<RequestMap>();
  for (const auto &[ReqRegion, Req] : ReqMap) {
    if (!SymReaper.isLiveRegion(ReqRegion)) {
      if (Req.RqstState == Request::Nonblocking) {

        if (!ErrorNode) {
          ErrorNode = Ctx.generateNonFatalErrorNode(State);
          State = ErrorNode->getState();
        }
        BReporter.reportMissingWait(Req, ReqRegion, ErrorNode,
                                    Ctx.getBugReporter());
      }
      State = State->remove<RequestMap>(ReqRegion);
    }
  }

  // Transition to update the state regarding removed requests.
  if (!ErrorNode) {
    Ctx.addTransition(State);
  } else {
    Ctx.addTransition(State, ErrorNode);
  }
}

void MPIChecker::checkUnsafeBufferAccess(SVal AccessLoc, bool IsLoad, const Stmt *Stmt,
                                   CheckerContext &Ctx) const {
  // For every currently known async operation...
  for (const auto &[RqstRegion, Rqst] : Ctx.getState()->get<RequestMap>()) {
    // ... if the request is in the sending phase -> no error ...
    if (Rqst.RqstState== Request::Wait) continue;

    // ... if it's an unlocked buffer -> no error ...'
    if (Rqst.Msg.MsgState == Message::Unlocked) continue;

    // ... if it's a read in a write-frozen buffer -> no error ...
    if (IsLoad && Rqst.Msg.MsgState == Message::WriteLocked) continue;

    // ... if it's not in the same base region -> no error ...
    if (Rqst.Msg.MsgRegion.getAsRegion()->getBaseRegion() != AccessLoc.getAsRegion()->getBaseRegion())
      return;

    // ... if it's in the same region -> report error.
    if (Rqst.Msg.MsgRegion.getAsRegion() == AccessLoc.getAsRegion()) {
      auto ErrorNode = Ctx.generateNonFatalErrorNode();
      BReporter.reportUnsafeBufferAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, RqstRegion, ErrorNode, Ctx.getBugReporter());
      continue;
    }

    // Array handling:
    if (Rqst.Msg.MsgRegion.getAsRegion()->getAs<ElementRegion>() && AccessLoc.getAsRegion()->getAs<ElementRegion>()) {
      checkArrayAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, RqstRegion);
      continue;
    }

    if (AccessLoc.getAsRegion()->isSubRegionOf(Rqst.Msg.MsgRegion.getAsRegion())) {
      auto ErrorNode = Ctx.generateNonFatalErrorNode();
      BReporter.reportUnsafeBufferAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, RqstRegion, ErrorNode, Ctx.getBugReporter());
    }
  }
}

void MPIChecker::checkArrayAccess(const SVal AccessLoc, bool IsLoad, const Stmt *Stmt,
                                   CheckerContext &Ctx, const Request &Rqst, const MemRegion *const RqstRegion) const {
  const auto StartIndex = Rqst.Msg.MsgRegion.getAsRegion()->getAs<ElementRegion>()->getIndex();
  const auto EndIndex = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_Add, StartIndex, Rqst.Msg.MsgCount.castAs<NonLoc>(), StartIndex.getType(Ctx.getASTContext())).castAs<NonLoc>();
  const auto AccessIndex = AccessLoc.getAsRegion()->getAs<ElementRegion>()->getIndex();

  const auto IsAfterStart = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_GE, AccessIndex, StartIndex, Ctx.getSValBuilder().getConditionType());
  const auto IsBeforeEnd = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_LT, AccessIndex, EndIndex, Ctx.getSValBuilder().getConditionType());

  const auto IsInside = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_EQ, IsAfterStart.castAs<NonLoc>(), IsBeforeEnd.castAs<NonLoc>(), Ctx.getSValBuilder().getConditionType());

  if (!IsInside.isConstant()) return;

  if (const auto S1 = Ctx.getState()->assume(IsInside.castAs<DefinedSVal>(), true)) {
    auto ErrorNode = Ctx.generateNonFatalErrorNode(S1);
    BReporter.reportUnsafeBufferAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, RqstRegion, ErrorNode, Ctx.getBugReporter());
  }
}

const MemRegion *MPIChecker::topRegionUsedByWait(const CallEvent &CE) const {

  if (FuncClassifier->isMPI_Wait(CE.getCalleeIdentifier())) {
    return CE.getArgSVal(0).getAsRegion();
  }
  if (FuncClassifier->isMPI_Waitall(CE.getCalleeIdentifier())) {
    return CE.getArgSVal(1).getAsRegion();
  }
  return (const MemRegion *)nullptr;
}

void MPIChecker::allRegionsUsedByWait(
    llvm::SmallVector<const MemRegion *, 2> &ReqRegions,
    const MemRegion *const MR, const CallEvent &CE, CheckerContext &Ctx) const {

  MemRegionManager &RegionManager = MR->getMemRegionManager();

  if (FuncClassifier->isMPI_Waitall(CE.getCalleeIdentifier())) {
    const SubRegion *SuperRegion{nullptr};
    if (const ElementRegion *const ER = MR->getAs<ElementRegion>()) {
      SuperRegion = cast<SubRegion>(ER->getSuperRegion());
    }

    // A single request is passed to MPI_Waitall.
    if (!SuperRegion) {
      ReqRegions.push_back(MR);
      return;
    }

    DefinedOrUnknownSVal ElementCount = getDynamicElementCount(
        Ctx.getState(), SuperRegion, Ctx.getSValBuilder(),
        CE.getArgExpr(1)->getType()->getPointeeType());
    const llvm::APSInt &ArrSize =
        ElementCount.castAs<nonloc::ConcreteInt>().getValue();

    for (size_t i = 0; i < ArrSize; ++i) {
      const NonLoc Idx = Ctx.getSValBuilder().makeArrayIndex(i);

      const ElementRegion *const ER = RegionManager.getElementRegion(
          CE.getArgExpr(1)->getType()->getPointeeType(), Idx, SuperRegion,
          Ctx.getASTContext());

      ReqRegions.push_back(ER->getAs<MemRegion>());
    }
  } else if (FuncClassifier->isMPI_Wait(CE.getCalleeIdentifier())) {
    ReqRegions.push_back(MR);
  }
}

} // end of namespace: mpi
} // end of namespace: ento
} // end of namespace: clang

// Registers the checker for static analysis.
void clang::ento::registerMPIChecker(CheckerManager &MGR) {
  MGR.registerChecker<clang::ento::mpi::MPIChecker>();
}

bool clang::ento::shouldRegisterMPIChecker(const CheckerManager &mgr) {
  return true;
}
