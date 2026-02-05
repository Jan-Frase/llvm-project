//===-- MPITypes.h - Functionality to model MPI concepts --------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file provides definitions to model concepts of MPI. The mpi::Request
/// class defines a wrapper class, in order to make MPI requests trackable for
/// path-sensitive analysis.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MPICHECKER_MPITYPES_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_MPICHECKER_MPITYPES_H

#include "clang/StaticAnalyzer/Checkers/MPIFunctionClassifier.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "llvm/ADT/SmallSet.h"

namespace clang {
namespace ento {
namespace mpi {

class Message {
public:
  enum MessageState : unsigned char { FullLocked, WriteLocked, Unlocked };

  Message(const MessageState MS, const SVal MessageRegion, const SVal MsgCount) : MsgState{MS}, MsgRegion {MessageRegion}, MsgCount {MsgCount} {}

  void Profile(llvm::FoldingSetNodeID &Id) const {
    Id.AddInteger(MsgState);
    Id.Add(MsgRegion);
    Id.Add(MsgCount);
  }

  bool operator==(const Message &ToCompare) const {
    return MsgState == ToCompare.MsgState &&
        MsgRegion == ToCompare.MsgRegion &&
          MsgCount == ToCompare.MsgCount;
  }

  const MessageState MsgState;
  const SVal MsgRegion;
  const SVal MsgCount;
};

class Request {
public:
  enum RequestState : unsigned char { Nonblocking, Wait };

  Request(const RequestState RS, const Message Msg) : RqstState{RS}, Msg{Msg} {}
  Request(const RequestState RS) : RqstState{RS}, Msg(Message(Message::Unlocked, SVal(), SVal())) {}

  void Profile(llvm::FoldingSetNodeID &Id) const {
    Id.AddInteger(RqstState);
    Id.Add(Msg);
  }

  bool operator==(const Request &ToCompare) const {
    return RqstState == ToCompare.RqstState && Msg == ToCompare.Msg;
  }

  const RequestState RqstState;
  const Message Msg;
};

// The RequestMap stores MPI requests which are identified by their memory
// region. Requests are used in MPI to complete nonblocking operations with wait
// operations. A custom map implementation is used, in order to make it
// available in an arbitrary amount of translation units.
struct RequestMap {};
typedef llvm::ImmutableMap<const clang::ento::MemRegion *,
                           clang::ento::mpi::Request>
    RequestMapImpl;

} // end of namespace: mpi

template <>
struct ProgramStateTrait<mpi::RequestMap>
    : public ProgramStatePartialTrait<mpi::RequestMapImpl> {
  static void *GDMIndex() {
    static int index = 0;
    return &index;
  }
};

} // end of namespace: ento
} // end of namespace: clang
#endif
