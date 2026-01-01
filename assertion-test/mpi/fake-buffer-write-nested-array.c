#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;
  int buf_x_size = 3;
  int buf_y_size = 10000;

  int **buf = malloc(buf_x_size * sizeof(int *));

  for (int x = 0; x < buf_x_size; x++) {
    buf[x] = malloc(buf_y_size * sizeof(int));
  }

  // Sender
  if (rank == 0) {
    // Start nonblocking send
    MPI_Isend(buf[2], buf_y_size, MPI_INT, 1, 0, MPI_COMM_WORLD, &request);
    // "Accidentally" overwrite the buffer before send completes
    buf[1][321] = 666;

    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
  } else if (rank == 1) {
    // Reciever
    MPI_Irecv(buf[2], buf_y_size, MPI_INT, 0, 0, MPI_COMM_WORLD, &request);
    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
  }

  free(buf);
  MPI_Finalize();
  return 0;
}