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
  const Message::MessageState MsgState = isFullLocking ? Message::MessageState::FullLocked: (isWriteLocking ? Message::MessageState::WriteLocked : Message::MessageState::Unlocked);

  const SVal MsgRegion = PreCallEvent.getArgSVal(0);
  const SVal MsgCount = PreCallEvent.getArgSVal(1);

  const Request NewReq = MsgState == Message::MessageState::Unlocked ||
                           MsgRegion.isUnknownOrUndef() ||
                           MsgCount.isUnknownOrUndef()
                       ? Request(Request::RequestState::Nonblocking)
                       : Request(Request::RequestState::Nonblocking,
                                 Message(MsgState, MsgRegion, MsgCount));

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

  llvm::SmallVector<const MemRegion *, 2> ReqRegions;
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

void MPIChecker::checkUnsafeBufferAccess(SVal Loc, bool IsLoad, const Stmt *Stmt,
                                   CheckerContext &Ctx) const {
  // For every currently known async operation...
  for (const auto &[_, Rqst] : Ctx.getState()->get<RequestMap>()) {
    // ... if the request is in the sending phase -> no error ...
    if (Rqst.RqstState== Request::Wait) continue;

    // ... if it's an unlocked buffer -> no error ...'
    if (Rqst.Msg.MsgState == Message::Unlocked) continue;

    // ... if it's a read in a write-frozen buffer -> no error ...
    if (IsLoad && Rqst.Msg.MsgState == Message::WriteLocked) continue;

    // checkAccessViaBits(Loc, IsLoad, Stmt, Ctx, Rqst);
    checkAccessBetter(Loc, IsLoad, Stmt, Ctx, Rqst);
  }
}

void MPIChecker::checkAccessBetter(SVal Loc, bool IsLoad, const Stmt *Stmt,
                                   CheckerContext &Ctx, Request Rqst) const {
  if (Rqst.Msg.MsgRegion.getAsRegion()->getBaseRegion() != Loc.getAsRegion()->getBaseRegion())
    return;
  const QualType MsgType = Rqst.Msg.MsgRegion.getAsRegion()->getAs<TypedValueRegion>()->getValueType();

  // TODO: Deal with scalars.
  if (!Rqst.Msg.MsgRegion.getAsRegion()->getAs<ElementRegion>())
    return;

  const auto MessageIndex = Rqst.Msg.MsgRegion.getAsRegion()->getAs<ElementRegion>()->getIndex();
  const auto MessageCount = Rqst.Msg.MsgCount.castAs<NonLoc>();
  const auto AccessIndex= Loc.getAsRegion()->getAs<ElementRegion>()->getIndex();

  llvm::errs() << "Message index: " << MessageIndex << ", Message count: " << MessageCount << ", Access index: " << AccessIndex << "\n";

  const auto End = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_Add, MessageIndex, MessageCount, MsgType);

  // Eh>

  const auto RightOfStart = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_GE, AccessIndex, MessageIndex, Ctx.getSValBuilder().getConditionType());
  const auto LeftOfEnd = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_LT, AccessIndex, End, Ctx.getSValBuilder().getConditionType());

  llvm::errs() << "Start: " << MessageIndex << "\n";
  llvm::errs() << "End: " << End << "\n";
  llvm::errs() << "Access: " << AccessIndex << "\n";

  llvm::errs() << "Right of start: " << RightOfStart << "\n";
  llvm::errs() << "Left of end: " << LeftOfEnd << "\n";

  const auto CombinedCondition = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_LAnd, RightOfStart, LeftOfEnd, Ctx.getSValBuilder().getConditionType());

  llvm::errs() << "Combined condition: " << CombinedCondition << "\n";
  const auto simplifiedCondition = Ctx.getSValBuilder().simplifySVal(Ctx.getState(), CombinedCondition);
  llvm::errs() << "Simplified condition: " << simplifiedCondition << "\n";

  if (const auto S1 = Ctx.getState()->assume(
          CombinedCondition.castAs<DefinedSVal>(), true)) {
    llvm::errs() << Lexer::getSourceText(CharSourceRange::getTokenRange(Stmt->getSourceRange()), Ctx.getSourceManager(), Ctx.getLangOpts()) << " ==> is UBA!\n";
  }
}

  void MPIChecker::checkAccessViaBits(SVal Loc, bool IsLoad, const Stmt *Stmt,
                                   CheckerContext &Ctx, Request Rqst) const {
  const auto *const MsgRegion = Rqst.Msg.MsgRegion.getAsRegion();
  const auto *const AccRegion = Loc.getAsRegion();

  const auto MsgOffset = MsgRegion->getAsOffset();
  const auto AccOffset = AccRegion->getAsOffset();

  // Offsets need to be valid.
  if (!MsgOffset.isValid() || !AccOffset.isValid()) {
    return;
  }

  // Access and message are not in the same superregion.
  if (MsgOffset.getRegion() != AccOffset.getRegion()) {
    return;
  }

  // Msg or Access is symbolic.
  if (MsgOffset.hasSymbolicOffset() || AccOffset.hasSymbolicOffset()) {
    llvm::errs() << "Symbolic offset detected!\n";
    return;
  }

  const QualType MsgType = MsgRegion->getAs<TypedValueRegion>()->getValueType();
  const auto MsgExtend = Ctx.getSValBuilder().makeIntVal(Ctx.getASTContext().getTypeSize(MsgType), MsgType);

  llvm::errs() << "Buffer from: " << MsgOffset.getOffset() << ", extending: " << Rqst.Msg.MsgCount << " times " << MsgExtend << " ---- Access at: " << AccOffset.getOffset() << "\n";

  // Start = MsgOffset
  // End = MsgOffset + Rqst.Msg.MsgCount * MsgExtend
  // if AccOffset.getOffset > Start und AccOffset.getOffset < End
  // Error!
  const auto Start = Ctx.getSValBuilder().makeIntVal(MsgOffset.getOffset(), MsgType);
  auto End = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_Mul, Rqst.Msg.MsgCount, MsgExtend, MsgType);
  End = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_Add, Start, End, MsgType);
  auto AccOffsetVal = Ctx.getSValBuilder().makeIntVal(AccOffset.getOffset(), MsgType);

  const auto RightOfStart = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_GE, AccOffsetVal, Start, MsgType);
  const auto LeftOfEnd = Ctx.getSValBuilder().evalBinOp(Ctx.getState(), BO_LT, AccOffsetVal, End, MsgType);

  llvm::errs() << "Start: " << Start << "\n";
  llvm::errs() << "End: " << End << "\n";
  llvm::errs() << "Access: " << AccOffsetVal << "\n";

  llvm::errs() << "Right of start: " << RightOfStart << "\n";
  llvm::errs() << "Left of end: " << LeftOfEnd << "\n";

  if (RightOfStart.getAsInteger()->getExtValue() == 1 && LeftOfEnd.getAsInteger()->getExtValue() == 1 ) {
    llvm::errs() << "UBA!\n";
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
