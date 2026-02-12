#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

typedef struct {
  int a;
  int b;
  int data[1000000];
} Buffer;

int main(int argc, char *argv[]) {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;

  Buffer *buf = (Buffer *)malloc(sizeof(Buffer));

  // Create MPI datatype for Buffer
  MPI_Datatype MPI_Buffer_type;

  int blocklengths[3] = {1, 1, 1000000};
  MPI_Aint offsets[3];
  MPI_Datatype types[3] = {MPI_INT, MPI_INT, MPI_INT};

  offsets[0] = offsetof(Buffer, a);
  offsets[1] = offsetof(Buffer, b);
  offsets[2] = offsetof(Buffer, data);

  MPI_Type_create_struct(3, blocklengths, offsets, types, &MPI_Buffer_type);
  MPI_Type_commit(&MPI_Buffer_type);

  if (rank == 0) {
    buf->a = 1;
    buf->b = 2;

    MPI_Isend(buf, 1, MPI_Buffer_type, 1, 0, MPI_COMM_WORLD, &request);

    // "Accidentally" overwrite before completion
    buf->a = 999;

    MPI_Wait(&request, MPI_STATUS_IGNORE);
    printf("Sent potentially corrupted struct.\n");
  } else if (rank == 1) {
    MPI_Irecv(buf, 1, MPI_Buffer_type, 0, 0, MPI_COMM_WORLD, &request);

    MPI_Wait(&request, MPI_STATUS_IGNORE);
    printf("Received a: %d\n", buf->a);
    printf("Received b: %d\n", buf->b);
    printf("Received data[666666]: %d\n", buf->data[666666]);
  }

  printf("Bye.\n");

  MPI_Type_free(&MPI_Buffer_type);
  free(buf);
  MPI_Finalize();
  return 0;
}
