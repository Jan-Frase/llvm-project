#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int rank, size;
  MPI_Init(NULL, NULL);

  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  MPI_Request request;

  int* buf = malloc(size * sizeof(int));

  MPI_Igather(&rank, 1, MPI_INT,
              buf, 1, MPI_INT,
              0, MPI_COMM_WORLD, &request);
if (rank != 0)
rank = 42;

  MPI_Wait(&request, MPI_STATUS_IGNORE);

   if (rank == 0) {
      for (int i = 0; i < size; i++) {
printf("%d\n", buf[i]);}
    }

  free(buf);
  MPI_Finalize();
  return 0;
}