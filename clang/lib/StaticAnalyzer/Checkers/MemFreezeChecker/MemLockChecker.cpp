
#include "MemLockChecker.h"

#include "../../../../../llvm/lib/CodeGen/AsmPrinter/DwarfDebug.h"
#include "../../../CodeGen/ABIInfoImpl.h"
#include "MemLockMap.h"

#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/Support/YAMLTraits.h"

namespace clang::ento {
namespace memfreeze {

// ========================================
//
// Function 1.
// Checks for double locks whenever a function exits.
// If everything is fine, it adds the locked operation to the map.
//
// ========================================
void MemLockChecker::checkPostCall(const CallEvent &call,
                                   CheckerContext &context) const {
  // Get the function declarations name...
  const auto a = call.getDecl();
  if (a == nullptr) return;
  const auto b = dyn_cast<FunctionDecl>(a);
  if (b == nullptr) return;
  const StringRef fn_name = b->getName();

  // ... check if it's name is in the list of full-freezers ...
  const auto read_write_locker_data = std::find_if(
      config_handler.doc.full_locker.begin(),
      config_handler.doc.full_locker.end(),
      [&fn_name](const Freezer &freezer) { return freezer.name == fn_name; });
  const bool read_write_locker_found = read_write_locker_data != config_handler.doc.full_locker.end();

  // ... or in the list of write-freezers ...
  const auto write_locker_data = std::find_if(
      config_handler.doc.write_locker.begin(),
      config_handler.doc.write_locker.end(),
      [&fn_name](const Freezer &freezer) { return freezer.name == fn_name; });
  const bool write_locker_found = write_locker_data != config_handler.doc.write_locker.end();

  // If the function is not an unfreezer -> Return.
  if (!read_write_locker_found && !write_locker_found) return;

  // If the name appears in both lists -> Config incorrect!
  if (read_write_locker_found && write_locker_found) {
    llvm::errs() << "Function " << fn_name << " is both a read-write locker and a write locker!\n";
    return;
  }

  // Get the lock index according to the config.
  const int lock_idx = read_write_locker_found ? read_write_locker_data->lock_idx : write_locker_data->lock_idx;

  // Get the lock region.
  const auto *const lock_region = call.getArgSVal(lock_idx).getAsRegion();

  // Check if we are already aware of this operation.
  const AsyncOperation *old_operation =
      context.getState()->get<AsyncOperationMap>(lock_region);

  // If we are, and it's already frozen, it's an error!
  if (old_operation && old_operation->current_state != Unfrozen) {
    ExplodedNode *error_node = context.generateNonFatalErrorNode();
    bug_reporter.reportDoubleNonblocking(call, *old_operation, lock_region, error_node, context.getBugReporter());
    context.addTransition(error_node->getState(), error_node);
    return;
  }

  // Get buffer index.
  const int buffer_idx = read_write_locker_found ? read_write_locker_data->buffer_idx : write_locker_data->buffer_idx;
  // Get the buffer pointer, read its value (which is the location it points to) and get that location as a region.
  const auto *buffer_region = call.getArgSVal(buffer_idx).getAs<Loc>().value().getAsRegion();

  // If what is being sent is some kind of array, struct etc. - go up one region
  switch (buffer_region->getKind()) {
  case MemRegion::ElementRegionKind:
  case MemRegion::FieldRegionKind:
  case MemRegion::ObjCIvarRegionKind:
  case MemRegion::CXXBaseObjectRegionKind:
  case MemRegion::CXXDerivedObjectRegionKind:
    buffer_region= cast<SubRegion>(buffer_region)->getSuperRegion();
    break;
  default:
    break;
  }

  const AsyncOperation async_operation(read_write_locker_found ? Read_Write_Frozen : Write_Frozen, buffer_region);
  const ProgramStateRef state = context.getState()->set<AsyncOperationMap>(lock_region, async_operation);
  context.addTransition(state);
}

// ========================================
//
// Function 2.
// Checks for unmatched unlocks whenever a function is called.
// If everything is fine, it updates the operation to be unlocked.
//
// ========================================
void MemLockChecker::checkPreCall(const CallEvent &call_event,
                                  CheckerContext &context) const {
  // Get the function declarations name...
  const auto a = call_event.getDecl();
  if (a == nullptr) return;
  const auto b = dyn_cast<FunctionDecl>(a);
  if (b == nullptr) return;
  const StringRef fn_name = b->getName();

  // ... and check if it's name is in the list of unfreezers.
  const auto unfreezer_data = std::find_if(
      config_handler.doc.unlocks.begin(),
      config_handler.doc.unlocks.end(),
      [&fn_name](const Unlocker &unlocker) { return unlocker.name == fn_name; });

  // If the function is not an unfreezer -> Return.
  if (unfreezer_data == config_handler.doc.unlocks.end()) return;

  // Get the argument at the specified index and then its memory location.
  const MemRegion *lock_region = call_event.getArgSVal(unfreezer_data->lock_idx).getAsRegion();

  // Check if we are aware of an operation regarding this region.
  const AsyncOperation *old_async_operation = context.getState()->get<AsyncOperationMap>(lock_region);
  const bool old_ao_found = old_async_operation != nullptr;

  // Update/Create operation, either without a buffer or with if we know which one.
  const AsyncOperation new_async_operation(Unfrozen, old_ao_found ? old_async_operation->buffer_region : nullptr);
  const ProgramStateRef new_state = context.getState()->set<AsyncOperationMap>(lock_region, new_async_operation);

  // If we are aware of an operation -> Everything is fine.
  // It would be nicer to also check if the operation is in the correct state.
  // This is possible (make this section quite a bit messier though) but should not be needed.
  if (old_ao_found) {
    context.addTransition(new_state);
    return;
  }

  // If we have arrived at an unfreeze call but nothing is frozen -> Error.
  ExplodedNode *error_node = context.generateNonFatalErrorNode(new_state);
  bug_reporter.reportUnmatchedWait(call_event, lock_region, error_node, context.getBugReporter());
  context.addTransition(error_node->getState(), error_node);
}

// ========================================
//
// Function 3.
// Checks for missing unfreeze whenever a lock goes out of scope.
// If everything is fine, it removes the operation from the map.
//
// ========================================
void MemLockChecker::checkDeadSymbols(SymbolReaper &sym_reaper,
                                      CheckerContext &context) const {
  // Create error node.
  ExplodedNode *error_node{nullptr};
  // Get state and operation map.
  ProgramStateRef state = context.getState();
  const auto &operation_map = state->get<AsyncOperationMap>();
  if (operation_map.isEmpty())
    return;

  // Loop over all tracked async operations...
  for (const auto &[mem_region, async_op] : operation_map) {
    // ... if the region is still alive -> it's irrelevant.
    if (sym_reaper.isLiveRegion(mem_region)) {
      continue;
    }

    // ... if it's in the unfrozen state -> it's fine.
    if (async_op.current_state == Unfrozen) {
      continue;
    }

    // If we made it here:
    // The lock of a still locked memory region just went out of scope -> Error!
    // Create the error node once.
    if (!error_node) {
      error_node = context.generateNonFatalErrorNode(state);
      state = error_node->getState();
    }

    // Report the error.
    bug_reporter.reportMissingWait(async_op, mem_region, error_node, context.getBugReporter());
    state = state->remove<AsyncOperationMap>(mem_region);
  }

  // Add transition to update the state regarding removed operations.
  if (!error_node) {
    context.addTransition(state);
  } else {
    context.addTransition(state, error_node);
  }
}

// ========================================
//
// Function 4.
// Checks for unsafe memory accesses whenever a location is touched.
// If everything is fine, it does nothing.
//
// ========================================
void MemLockChecker::checkLocation(SVal location, bool is_load, const Stmt *statement,
                                   CheckerContext &context) const {
  // Get state and modified region.
  ProgramStateRef state = context.getState();
  const MemRegion *modified_region = location.getAsRegion();

  // For every currently known async operation...
  for (const auto &[_, async_op] : state->get<AsyncOperationMap>()) {
    // ... if the request is in the sending phase -> no error ...
    if (async_op.current_state == Unfrozen) continue;

    // ... if it's a read in a write-frozen buffer -> no error ...
    if (is_load && async_op.current_state == Write_Frozen) continue;

    // ... and if nothing is null ...
    if (!async_op.buffer_region || !modified_region) continue;

    // ... check if the modified region is the buffer region or a subregion of it.
    if (modified_region->isSubRegionOf(async_op.buffer_region)) {
      // If that's the case, we have an error :)
      const ExplodedNode *error_node = context.generateNonFatalErrorNode();
      bug_reporter.reportUnsafeBufferUse(statement, error_node, context.getBugReporter());
      return;
    }
  }
}
} // namespace memfreeze

// ======================================
//
// Registers checker.
//
// ======================================

void registerMemLockChecker(CheckerManager &mgr) {
  auto *const checker = mgr.registerChecker<memfreeze::MemLockChecker>();

  const AnalyzerOptions &options = mgr.getAnalyzerOptions();
  const auto path_to_yaml = options.getCheckerStringOption(checker, "Config");

  if (path_to_yaml.size() == 0) {
    mgr.reportInvalidCheckerOptionValue(checker, "Config", "must be set");
  }
  // TODO: For now i will load the file here. Ideally it would get loaded once.
  llvm::errs() << "MemLockChecker loading yaml from disk: " << path_to_yaml << "\n";

  auto buffer = llvm::MemoryBuffer::getFile(path_to_yaml, true);
  if (!buffer || buffer.getError().value() != 0) {
    llvm::errs() << "Could not load yaml file: " << path_to_yaml << "\n";
  }

  memfreeze::Doc doc;
  llvm::yaml::Input input(buffer.get()->getBuffer());
  input >> doc;

  if (input.error()) {
    llvm::errs() << "Invalid yaml.";
  }

  checker->config_handler.doc = doc;
}

bool shouldRegisterMemLockChecker(const CheckerManager &mgr) { return true; }

} // namespace clang::ento
