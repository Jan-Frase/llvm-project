#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;

  int buf = 12345;

  // Sender
  if (rank == 0) {
    // Start nonblocking send
    MPI_Isend(&buf, 1, MPI_INT, 1, 0, MPI_COMM_WORLD, &request);

    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);

    // "Accidentally" overwrite the buffer before send completes
    buf = 666;

    printf("Send corrupted buffer.\n");
  } else if (rank == 1) {
    // Reciever
    MPI_Irecv(&buf, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &request);
    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
    printf("Recieved corrputed buffer: %d\n", buf);
  }

  printf("Bye.\n");
  MPI_Finalize();
  return 0;
}
