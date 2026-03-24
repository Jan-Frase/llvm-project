#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

void foo() {
  MPI_Request request;
  int buf = 12345;

MPI_Isend(&buf, 1, MPI_INT, 1, 0, MPI_COMM_WORLD, &request);

int flag = 0;
MPI_Test(&request, &flag, MPI_STATUS_IGNORE);

if (!flag){
  buf = 666;
}
else {
  MPI_Wait(&request, MPI_STATUS_IGNORE);
}
}
