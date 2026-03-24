#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int calc(int i) {
  return i * 2;
}

void foo() {
  MPI_Init(NULL, NULL);

  MPI_Request request;

  int size = 512;
  int buf[size];
  int* send_buf = buf + size / 2 - 1;

  MPI_Isend(send_buf, size / 2, MPI_INT, 1, 0, MPI_COMM_WORLD, &request);
  buf[size] = 12345;
  for (int* i = &buf[255]; i != buf; i--) {
    *i = calc(size);
  }

  MPI_Wait(&request, MPI_STATUS_IGNORE);

  MPI_Finalize();
  return;
}
