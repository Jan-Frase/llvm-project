#ifndef LLVM_MEMLOCKCONFIGHANDLER_H
#define LLVM_MEMLOCKCONFIGHANDLER_H
#include "llvm/Support/YAMLTraits.h"

#include <string>
#include <vector>

namespace clang::ento::memfreeze {

struct Freezer {
  std::string name;
  int buffer_idx;
  int lock_idx;
};

struct Unlocker {
  std::string name;
  int lock_idx;
};

struct Doc {
  std::vector<Freezer> full_locker;
  std::vector<Freezer> write_locker;
  std::vector<Unlocker> unlocks;
};

class MemLockConfigHandler {
public:
  Doc doc;
};

} // namespace clang::ento::memfreeze

namespace llvm::yaml {

template <> struct MappingTraits<clang::ento::memfreeze::Freezer> {
  static void mapping(IO &io, clang::ento::memfreeze::Freezer &freezer) {
    io.mapRequired("name", freezer.name);
    io.mapRequired("buffer_idx", freezer.buffer_idx);
    io.mapRequired("lock_idx", freezer.lock_idx);
  }
};

template <>
struct SequenceTraits<std::vector<clang::ento::memfreeze::Freezer>> {

  static size_t size(IO &IO, std::vector<clang::ento::memfreeze::Freezer> &A) {
    return A.size();
  }

  static clang::ento::memfreeze::Freezer &
  element(IO &IO, std::vector<clang::ento::memfreeze::Freezer> &A,
          size_t Index) {
    if (Index >= A.size()) {
      A.resize(Index + 1);
    }
    return A[Index];
  }
};

template <> struct MappingTraits<clang::ento::memfreeze::Unlocker> {
  static void mapping(IO &io, clang::ento::memfreeze::Unlocker &unfreezer) {
    io.mapRequired("name", unfreezer.name);
    io.mapRequired("lock_idx", unfreezer.lock_idx);
  }
};

template <>
struct SequenceTraits<std::vector<clang::ento::memfreeze::Unlocker>> {

  static size_t size(IO &IO,
                     std::vector<clang::ento::memfreeze::Unlocker> &A) {
    return A.size();
  }

  static clang::ento::memfreeze::Unlocker &
  element(IO &IO, std::vector<clang::ento::memfreeze::Unlocker> &A,
          size_t Index) {
    if (Index >= A.size()) {
      A.resize(Index + 1);
    }
    return A[Index];
  }
};

template <> struct MappingTraits<clang::ento::memfreeze::Doc> {
  static void mapping(IO &io, clang::ento::memfreeze::Doc &doc) {
    io.mapOptional("full_locker", doc.full_locker);
    io.mapOptional("write_locker", doc.write_locker);
    io.mapOptional("unlocker", doc.unlocks);
  }
};

} // namespace llvm::yaml

#endif // LLVM_MEMLOCKCONFIGHANDLER_H
