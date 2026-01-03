//
// Created by jan on 11/10/25.
//

#include "MemFreezeChecker.h"

#include "../../../../../llvm/lib/CodeGen/AsmPrinter/DwarfDebug.h"
#include "../../../CodeGen/ABIInfoImpl.h"
#include "MemFreezeMap.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/BinaryFormat/MsgPackDocument.h"
#include "llvm/Support/YAMLTraits.h"


namespace llvm {
namespace yaml {


template <> struct MappingTraits<clang::ento::memfreeze::Freezer> {
  static void mapping(IO &io, clang::ento::memfreeze::Freezer &freezer) {
    io.mapRequired("name", freezer.name);
    io.mapRequired("buffer_idx", freezer.buffer_idx);
    io.mapRequired("request_idx", freezer.request_idx);
  }
};

template <> struct SequenceTraits<std::vector<clang::ento::memfreeze::Freezer>> {

  static size_t size(IO &IO, std::vector<clang::ento::memfreeze::Freezer> &A) { return A.size(); }

  static clang::ento::memfreeze::Freezer &element(IO &IO, std::vector<clang::ento::memfreeze::Freezer> &A, size_t Index) {
    if (Index >= A.size()) {
      A.resize(Index + 1);
    }
    return A[Index];
  }
};

template <> struct MappingTraits<clang::ento::memfreeze::Unfreezer> {
  static void mapping(IO &io, clang::ento::memfreeze::Unfreezer &unfreezer) {
    io.mapRequired("name", unfreezer.name);
    io.mapRequired("request_idx", unfreezer.request_idx);
  }
};

template <> struct SequenceTraits<std::vector<clang::ento::memfreeze::Unfreezer>> {

  static size_t size(IO &IO, std::vector<clang::ento::memfreeze::Unfreezer> &A) { return A.size(); }

  static clang::ento::memfreeze::Unfreezer &element(IO &IO, std::vector<clang::ento::memfreeze::Unfreezer> &A, size_t Index) {
    if (Index >= A.size()) {
      A.resize(Index + 1);
    }
    return A[Index];
  }
};

template <> struct MappingTraits<clang::ento::memfreeze::Doc> {
  static void mapping(IO &io, clang::ento::memfreeze::Doc &doc) {
    io.mapOptional("read_write_freezers", doc.read_write_freezers);
    io.mapOptional("write_freezers", doc.write_freezers);
    io.mapOptional("unfreezers", doc.unfreezers);
  }
};


} // namespace yaml
} // namespace llvm

namespace clang {
namespace ento {
namespace memfreeze {
/*
 * ---> Checker entry points <---
 */
void MemFreezeChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Get the function declaration...
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(Call.getDecl());

  // llvm::errs() << FD->getName().data() << "\n";

  // ... or the MemUnfreezeAttr.
  for (const auto &[name, request_idx] : doc.unfreezers) {
    if (FD->getName().compare(name) == 0) {
      checkUnmatchedUnfreeze(Call, C, request_idx);
    }
  }
}

void MemFreezeChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Get the function declaration...
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(Call.getDecl());

  // ... check if its full-freezer ...
  for (const auto &[name, buffer_idx, request_idx] : doc.read_write_freezers) {
    if (FD->getName().compare(name) == 0) {
      checkDoubleFreeze(Call, C, buffer_idx, request_idx, Read_Write_Frozen);
    }
  }

  // ... or a write-freezer.
  for (const auto &[name, buffer_idx, request_idx] : doc.write_freezers) {
    if (FD->getName().compare(name) == 0) {
      checkDoubleFreeze(Call, C, buffer_idx, request_idx, Write_Frozen);
    }
  }
}

void MemFreezeChecker::checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &Ctx) const {
  checkMissingUnfreeze(SymReaper, Ctx);
}

// TODO: Use checkLocation instead lol.
void MemFreezeChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S, CheckerContext &C) const {
  checkUnsafeBufferAccess(Loc, S, C, IsLoad);
}

/*
 * ---> Various functions <---
 */


void MemFreezeChecker::checkDoubleFreeze(const CallEvent &PreCallEvent,
                            CheckerContext &Ctx, const int buffer_idx, const int request_idx, State freeze_state) const {
  // Get the Buffer and OperationReference according to the annotation.
  const SVal BufferSVal = PreCallEvent.getArgSVal(buffer_idx);
  const SVal OpRefSval = PreCallEvent.getArgSVal(request_idx);

  // If they aren't defined, the annotation must be faulty.
  if (BufferSVal.isUndef() || OpRefSval.isUndef()) {
    llvm::errs() << "BufferSVal or OperationReferenceSVal is undefined\n";
    return;
  }

  // Check if we are already aware of this operation.
  const MemRegion *OpRefRegion = OpRefSval.getAsRegion();
  const AsyncOperation *ExistingAO = Ctx.getState()->get<AsyncOperationMap>(OpRefRegion);

  // If we are, and it's already frozen, it's an error!
  if (ExistingAO && ExistingAO->CurrentState != Unfrozen) {
    ExplodedNode *ErrorNode = Ctx.generateNonFatalErrorNode();
    BReporter.reportDoubleNonblocking(PreCallEvent, *ExistingAO, OpRefRegion, ErrorNode, Ctx.getBugReporter());
    Ctx.addTransition(ErrorNode->getState(), ErrorNode);
    return;
  }

  // If everything is fine, add the newly found operation.
  auto BufferRegion = BufferSVal.getAs<Loc>().value().getAsRegion();
  // If what is being send is some kind of array, struct etc - go up one region
  switch (BufferRegion->getKind()) {
    case MemRegion::ElementRegionKind:
    case MemRegion::FieldRegionKind:
    case MemRegion::ObjCIvarRegionKind:
    case MemRegion::CXXBaseObjectRegionKind:
    case MemRegion::CXXDerivedObjectRegionKind:
      BufferRegion = cast<SubRegion>(BufferRegion)->getSuperRegion();
      break;
    default:
      break;
  }

  llvm::errs() << "Found new freeze operation!\n";
  BufferRegion->dumpToStream(llvm::errs());
  llvm::errs() << "\n";

  const AsyncOperation AO(freeze_state, BufferRegion);
  ProgramStateRef State = Ctx.getState()->set<AsyncOperationMap>(OpRefRegion, AO);
  Ctx.addTransition(State);
}

void MemFreezeChecker::checkUnmatchedUnfreeze(const CallEvent &PreCallEvent,
                         CheckerContext &Ctx, const int request_idx) const {
  const SVal OpRefSVal = PreCallEvent.getArgSVal(request_idx);
  const MemRegion *OpRefRegion = OpRefSVal.getAsRegion();

  const AsyncOperation *ExistingAO = Ctx.getState()->get<AsyncOperationMap>(OpRefRegion);
  const bool isAOMissing = ExistingAO == nullptr;

  const AsyncOperation AO(Unfrozen, isAOMissing ? nullptr : ExistingAO->BufferRegion);
  ProgramStateRef State = Ctx.getState()->set<AsyncOperationMap>(OpRefRegion, AO);

  // If we have arrived at an unfreeze call but nothing is frozen -> Error.
  if (isAOMissing) {
    ExplodedNode *ErrorNode = Ctx.generateNonFatalErrorNode(State);
    BReporter.reportUnmatchedWait(PreCallEvent, OpRefRegion, ErrorNode, Ctx.getBugReporter());
    Ctx.addTransition(ErrorNode->getState(), ErrorNode);
    return;
  }

  Ctx.addTransition(State);
}

void MemFreezeChecker::checkMissingUnfreeze(SymbolReaper &SymReaper,
                       CheckerContext &Ctx) const {
  ProgramStateRef State = Ctx.getState();
  const auto &Requests = State->get<AsyncOperationMap>();
  if (Requests.isEmpty())
    return;

  ExplodedNode *ErrorNode{nullptr};

  for (const auto &[mem_region, async_op] : Requests) {
    if (!SymReaper.isLiveRegion(mem_region)) {
      if (async_op.CurrentState != Unfrozen) {

        if (!ErrorNode) {
          ErrorNode = Ctx.generateNonFatalErrorNode(State);
          State = ErrorNode->getState();
        }
        BReporter.reportMissingWait(async_op, mem_region, ErrorNode,
                                    Ctx.getBugReporter());
      }
      State = State->remove<AsyncOperationMap>(mem_region);
    }
  }

  // Transition to update the state regarding removed requests.
  if (!ErrorNode) {
    Ctx.addTransition(State);
  } else {
    Ctx.addTransition(State, ErrorNode);
  }
}

void MemFreezeChecker::checkUnsafeBufferAccess(SVal Loc, const Stmt *S,
                                              CheckerContext &C, bool IsLoad) const {
  ProgramStateRef State = C.getState();

  // 1. Takes care of writes.
  const MemRegion *ModifiedRegion = Loc.getAsRegion();
  // For every currently known Request...
  for (const auto &[_, async_op] : State->get<AsyncOperationMap>()) {
    // ... if the request is in the sending phase -> no error ...
    if (async_op.CurrentState == Unfrozen) {
      continue;
    }

    // ... if it's a read in a write-frozen buffer -> no error ...
    if (IsLoad && async_op.CurrentState == Write_Frozen) {
      continue;
    }

    // ... and if nothing is null ...
    if (!async_op.BufferRegion|| !ModifiedRegion) {
      continue;
    }

    llvm::errs() << "ModifiedRegion: ";
    ModifiedRegion->dumpToStream(llvm::errs());
    llvm::errs() << "BufferRegion: ";
    async_op.BufferRegion->dumpToStream(llvm::errs());

    // ... check if the modified region is the buffer region or a subregion of it.
    if (ModifiedRegion->isSubRegionOf(async_op.BufferRegion)) {
      // If that's the case, we have an error :)
      const ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
      BReporter.reportUnsafeBufferUse(S, ErrNode, C.getBugReporter());
    }
  }
  // TODO: Add state transition?
}
} // namespace memfreeze


// Registers my checker.
void registerMemFreezeChecker(CheckerManager &mgr) {
  auto *const checker = mgr.registerChecker<memfreeze::MemFreezeChecker>();

  const AnalyzerOptions & options = mgr.getAnalyzerOptions();
  const auto path_to_yaml= options.getCheckerStringOption(checker, "Config");

  if (path_to_yaml.size() == 0) {
    mgr.reportInvalidCheckerOptionValue(checker, "Config", "must be set");
  }
  // TODO: For now i will load the file here. Ideally it would get loaded once.
  llvm::errs() << "MemFreezeChecker registered with path to yaml: " << path_to_yaml << "\n";

  auto Buffer = llvm::MemoryBuffer::getFile(path_to_yaml);
  if (!Buffer || Buffer.getError().value() != 0) {
    llvm::errs() << "Could not load yaml file: " << path_to_yaml << "\n";
  }

  memfreeze::Doc doc;
  llvm::yaml::Input input(Buffer.get()->getBuffer());
  input >> doc;

  if (input.error()) {
    llvm::errs() << "Invalid yaml.";
  }

  checker->doc = doc;
}

bool shouldRegisterMemFreezeChecker(const CheckerManager &mgr) {
  return true;
}

}
}
