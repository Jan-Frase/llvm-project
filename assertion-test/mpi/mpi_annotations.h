#include <mpi.h>

#pragma once
__attribute__((mem_freeze(0, 6)))
int MPI_Isend(const void *buf, int count, MPI_Datatype datatype,
              int dest, int tag, MPI_Comm comm, MPI_Request *request);

__attribute__((mem_unfreeze(0)))
int MPI_Wait(MPI_Request *request, MPI_Status *status);

__attribute__((mem_freeze(0, 6)))
int MPI_Irecv(void *buf, int count, MPI_Datatype datatype, int source, int tag, MPI_Comm comm, MPI_Request *request);

