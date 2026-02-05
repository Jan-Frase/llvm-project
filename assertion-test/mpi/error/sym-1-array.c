#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int foo(int a) {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;

  int buf_size = 1000000;

  int *buf = (int *)malloc(buf_size * sizeof(int));

  // Sender
  if (rank == 0) {
    // Start nonblocking send
    MPI_Isend(buf + a, b, MPI_INT, 1, 0, MPI_COMM_WORLD, &request);
    // "Accidentally" overwrite the buffer before send completes
    buf[c] = 666;

    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
  } else if (rank == 1) {
    // Reciever
    MPI_Irecv(buf, buf_size, MPI_INT, 0, 0, MPI_COMM_WORLD, &request);
    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
  }

  printf("Bye.\n");
  free(buf);
  MPI_Finalize();
  return 0;
}
