#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;
  // Large buffer (4B * 1'000'000 = 4 MB) -> should exceed eager threshold and
  // thus force rendezvous mode. Eager – in Eager protocol, the message, with
  // all of its data, is sent directly to the target. Eager protocol is mostly
  // used for small-medium sized messages. Rendezvous – in Rendezvous
  // protocol, the initiator of the transaction sends a small descriptor
  // describing its intention to send data. The target will fetch the data
  // from the initiator when it has a matching buffer. Rendezvous is mostly
  // used for large messages.
  int buf_size = 1000000;

  int *buf = (int *)malloc(buf_size * sizeof(int));

  // Sender
  if (rank == 0) {
    // Start nonblocking send
    MPI_Isend(buf, buf_size, MPI_INT, 1, 0, MPI_COMM_WORLD, &request);
    // "Accidentally" overwrite the buffer before send completes
    buf[666666] = 666;

    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
    printf("Send corrupted buffer.\n");
  } else if (rank == 1) {
    // Reciever
    MPI_Irecv(buf, buf_size, MPI_INT, 0, 0, MPI_COMM_WORLD, &request);
    // Wait
    MPI_Wait(&request, MPI_STATUS_IGNORE);
    printf("Recieved corrputed buffer: %d\n", buf[666666]);
  }

  printf("Bye.\n");
  free(buf);
  MPI_Finalize();
  return 0;
}
