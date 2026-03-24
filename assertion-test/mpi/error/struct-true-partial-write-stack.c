#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

typedef struct {
  float a;
  float b;
  int data[1000000];
} Buffer;

int main(int argc, char *argv[]) {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;

  // Create MPI datatype for Buffer
  MPI_Datatype MPI_Buffer_type;

  int blocklengths[2] = {1, 1};
  MPI_Aint offsets[2];
  MPI_Datatype types[2] = {MPI_INT, MPI_FLOAT};

  offsets[0] = offsetof(Buffer, a);
  offsets[1] = offsetof(Buffer, b);

  MPI_Type_create_struct(2, blocklengths, offsets, types, &MPI_Buffer_type);
  MPI_Type_commit(&MPI_Buffer_type);

  Buffer buf;

  if (rank == 0) {
    buf.a = 1;
    buf.b = 2;

    MPI_Isend(&buf, 1, MPI_Buffer_type, 1, 0, MPI_COMM_WORLD, &request);

    // Overwrite before completion
    buf.data[666666] = 999;

    MPI_Wait(&request, MPI_STATUS_IGNORE);
    printf("Sent potentially corrupted struct.\n");
  } else if (rank == 1) {
    MPI_Irecv(&buf, 1, MPI_Buffer_type, 0, 0, MPI_COMM_WORLD, &request);

    MPI_Wait(&request, MPI_STATUS_IGNORE);
    printf("Received a: %d\n", buf.a);
    printf("Received b: %d\n", buf.b);
    printf("Received data[666666]: %d\n", buf.data[666666]);
  }

  printf("Bye.\n");

  MPI_Type_free(&MPI_Buffer_type);
  MPI_Finalize();
  return 0;
}
