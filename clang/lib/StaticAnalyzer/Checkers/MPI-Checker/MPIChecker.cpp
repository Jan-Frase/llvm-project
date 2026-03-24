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

static bool isArray(SVal CountSVal) {
  if (const auto *CountAPSInt= CountSVal.getAsInteger()) {
    auto value = CountAPSInt->getExtValue();
    if (value == 1) {
      return false;
    }
  }
  return true;
}

void MPIChecker::checkDoubleNonblocking(const CallEvent &PreCallEvent,
                                        CheckerContext &Ctx) const {
  PreCallEvent.dump();
  Ctx.getState()->dump();
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

  auto NewReq = Request(Request::RequestState::Nonblocking);
  if (isFullLocking) {
    const auto BufIndex = FuncClassifier->getFullLockedBufferIndex(PreCallEvent.getCalleeIdentifier());
    const auto CountIdx = FuncClassifier->getFullLockedCountIndex(PreCallEvent.getCalleeIdentifier());

    const auto Buf = PreCallEvent.getArgSVal(BufIndex);
    const auto Count = PreCallEvent.getArgSVal(CountIdx);

    if (!Buf.isUnknownOrUndef() && !Count.isUnknownOrUndef()) {
      Message Msg(Message::MessageState::FullLocked, Buf, Count, PreCallEvent.getSourceRange());
      NewReq.MsgVec.push_back(Msg);

      /*
      if (isArray(Count)) {
        llvm::errs() << "JAN - Array: ";
        Ctx.getLocation().dump();
        llvm::errs() << '\n';
      }
      else {
        llvm::errs() << "JAN - Other: ";
        Ctx.getLocation().dump();
        llvm::errs() << '\n';
      }
       */
    }
  } if (isWriteLocking) {
    const auto BufIndex = FuncClassifier->getWriteLockedBufferIndex(PreCallEvent.getCalleeIdentifier());
    const auto CountIdx = FuncClassifier->getWriteLockedCountIndex(PreCallEvent.getCalleeIdentifier());

    const auto Buf = PreCallEvent.getArgSVal(BufIndex);
    const auto Count = PreCallEvent.getArgSVal(CountIdx);

    if (!Buf.isUnknownOrUndef() && !Count.isUnknownOrUndef()) {
      Message Msg(Message::MessageState::WriteLocked, Buf, Count, PreCallEvent.getSourceRange());
      NewReq.MsgVec.push_back(Msg);

      /*
      if (isArray(Count)) {
        llvm::errs() << "JAN - Array: ";
        Ctx.getLocation().dump();
        llvm::errs() << '\n';
      }
      else {
        llvm::errs() << "JAN - Other: ";
        Ctx.getLocation().dump();
        llvm::errs() << '\n';
      }
       */
    }
  }

  State = State->set<RequestMap>(RequestRegion, NewReq);
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
  auto map = Ctx.getState()->get<RequestMap>();
  for (const auto &[RqstRegion, Rqst] : map) {
    for (Message Msg : Rqst.MsgVec) {
      auto MsgRegion = Msg.MsgLoc.getAsRegion();
      auto AccessRegion = AccessLoc.getAsRegion();
      // llvm::errs() << "UBA: Message Region Check Started.\n";
      // ... if the request is in the sending phase -> no error ...
      if (Rqst.RqstState == Request::Wait) continue;

      // ... if it's an unlocked buffer -> no error ...'
      if (Msg.MsgState == Message::Unlocked) continue;

      // ... if it's a read in a write-locked buffer -> no error ...
      if (IsLoad && Msg.MsgState == Message::WriteLocked) continue;

      // ... if it's not in the same base region -> no error ...
      if (MsgRegion->getBaseRegion() != AccessRegion->getBaseRegion())
        continue;

      // llvm::errs() << "UBA: Not immediately discarded.\n";

      // ... if it's in the same region -> report error.
      if (MsgRegion == AccessRegion) {
        // llvm::errs() << "UBA: Same region error.\n";
        const auto *ErrorNode = Ctx.generateNonFatalErrorNode();
        BReporter.reportUnsafeBufferAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, RqstRegion, ErrorNode, Ctx.getBugReporter());
        continue;
      }

      // Array handling:
      if (MsgRegion->getAs<ElementRegion>() && AccessRegion->getAs<ElementRegion>()
        && MsgRegion->castAs<ElementRegion>()->getSuperRegion() == AccessRegion->castAs<ElementRegion>()->getSuperRegion()) {
        // llvm::errs() << "UBA: Array check entered.\n";
        checkArrayAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, Msg, RqstRegion);
        continue;
      }

      // Compound types:
      if (AccessRegion->isSubRegionOf(MsgRegion)) {
        // llvm::errs() << "UBA: Subregion error.\n";
        auto ErrorNode = Ctx.generateNonFatalErrorNode();
        BReporter.reportUnsafeBufferAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, RqstRegion, ErrorNode, Ctx.getBugReporter());
      }
    }
  }
}

void MPIChecker::checkArrayAccess(const SVal AccessLoc, bool IsLoad, const Stmt *Stmt,
                                   CheckerContext &Ctx, const Request &Rqst, const Message &Msg, const MemRegion *const RqstRegion) const {
  const auto StartIndex = Msg.MsgLoc.getAsRegion()->getAs<ElementRegion>()->getIndex();
  const auto EndIndex = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_Add, StartIndex, Msg.MsgCount.castAs<NonLoc>(), StartIndex.getType(Ctx.getASTContext())).castAs<NonLoc>();
  const auto AccessIndex = AccessLoc.getAsRegion()->getAs<ElementRegion>()->getIndex();

  const auto IsAfterStart = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_GE, AccessIndex, StartIndex, Ctx.getSValBuilder().getConditionType());
  const auto IsBeforeEnd = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_LT, AccessIndex, EndIndex, Ctx.getSValBuilder().getConditionType());

  const auto IsInbetween = Ctx.getSValBuilder().evalBinOpNN(Ctx.getState(), BO_And, IsAfterStart.castAs<NonLoc>(), IsBeforeEnd.castAs<NonLoc>(), Ctx.getSValBuilder().getConditionType());

  if (!IsInbetween.isConstant()) {
    // llvm::errs() << "UBA: Array access is not constant.\n";
    return;
  }

  if (const auto S1 = Ctx.getState()->assume(IsInbetween.castAs<DefinedSVal>(), true)) {
    auto ErrorNode = Ctx.generateNonFatalErrorNode(S1);
    BReporter.reportUnsafeBufferAccess(AccessLoc, IsLoad, Stmt, Ctx, Rqst, RqstRegion, ErrorNode, Ctx.getBugReporter());
    // llvm::errs() << "UBA: Array error!\n";
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
