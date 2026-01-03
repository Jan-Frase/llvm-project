//
// Created by jan on 11/11/25.
//

#include "MemLockBugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"

namespace clang {
namespace ento {
namespace memfreeze {

void MemLockBugReporter::reportUnsafeBufferUse(
    const Stmt *S, const ExplodedNode *const ExplNode,
    BugReporter &BReporter) const {
  std::string ErrorText = "Premature buffer reuse.";

  auto Report = std::make_unique<PathSensitiveBugReport>(
      UnsafeBufferUseBugType, ErrorText, ExplNode);

  Report->addRange(S->getSourceRange());
  BReporter.emitReport(std::move(Report));
}

void MemLockBugReporter::reportDoubleNonblocking(
    const CallEvent &MPICallEvent, const AsyncOperation &AO,
    const MemRegion *const RequestRegion,
    const ExplodedNode *const ExplNode,
    BugReporter &BReporter) const {

  std::string ErrorText;
  ErrorText = "Double nonblocking on request " +
              RequestRegion->getDescriptiveName() + ". ";

  auto Report = std::make_unique<PathSensitiveBugReport>(
      DoubleNonblockingBugType, ErrorText, ExplNode);

  Report->addRange(MPICallEvent.getSourceRange());
  SourceRange Range = RequestRegion->sourceRange();

  if (Range.isValid())
    Report->addRange(Range);

  BReporter.emitReport(std::move(Report));
}

void MemLockBugReporter::reportMissingWait(
    const AsyncOperation &AO, const MemRegion *const RequestRegion,
    const ExplodedNode *const ExplNode,
    BugReporter &BReporter) const {
  std::string ErrorText{"Request " + RequestRegion->getDescriptiveName() +
                        " has no matching wait. "};

  auto Report = std::make_unique<PathSensitiveBugReport>(MissingWaitBugType,
                                                         ErrorText, ExplNode);

  SourceRange Range = RequestRegion->sourceRange();
  if (Range.isValid())
    Report->addRange(Range);

  BReporter.emitReport(std::move(Report));
}

void MemLockBugReporter::reportUnmatchedWait(
    const CallEvent &CE, const MemRegion *const RequestRegion,
    const ExplodedNode *const ExplNode,
    BugReporter &BReporter) const {
  std::string ErrorText{"Request " + RequestRegion->getDescriptiveName() +
                        " has no matching nonblocking call. "};

  auto Report = std::make_unique<PathSensitiveBugReport>(UnmatchedWaitBugType,
                                                         ErrorText, ExplNode);

  Report->addRange(CE.getSourceRange());
  SourceRange Range = RequestRegion->sourceRange();
  if (Range.isValid())
    Report->addRange(Range);

  BReporter.emitReport(std::move(Report));
}

} // end of namespace: mpi
} // end of namespace: ento
} // end of namespace: clang
