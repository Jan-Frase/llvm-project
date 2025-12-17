#ifndef CLEAR_ERROR_H
#define CLEAR_ERROR_H

#include <mpi.h>

void demonstrateTypeMismatch(int rank);
void demonstrateIncorrectBufferReferencing(int rank);
void demonstrateDoubleNonblocking(int rank);
void demonstrateUnmatchedWait(int rank);
void demonstrateMissingWait(int rank);
void demonstrateOverwrittenBuffer(int rank);
void demonstrateOverwrittenBufferWhenRecieving(int rank); 
void demonstrateFreedBufferBeforeSending(int rank);
void demonstrateBufferMismatch(int rank);

#endif // CLEAR_ERROR_H
