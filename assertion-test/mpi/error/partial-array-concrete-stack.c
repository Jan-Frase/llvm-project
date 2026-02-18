#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

void foo() {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;

  int buf[200];

  // Sender
  if (rank == 0) {
    // Start nonblocking send
    MPI_Isend(buf + 50, 100, MPI_INT, 1, 0, MPI_COMM_WORLD, &request);
    // "Accidentally" overwrite the buffer before send completes
    buf[66] = 666;

    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
  } else if (rank == 1) {
    // Reciever
    MPI_Irecv(buf, 100, MPI_INT, 0, 0, MPI_COMM_WORLD, &request);
    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
  }

  printf("Bye.\n");
  MPI_Finalize();
  return;
}
