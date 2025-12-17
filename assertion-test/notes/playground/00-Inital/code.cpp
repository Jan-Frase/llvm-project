#include <iostream>
#include <mpi.h>
using namespace std;

// module load mpi/openmpi-x86_64
// mpic++ -o code-mpi code.cpp
// compile using mpic++ -o code-mpi code.cpp
// run using mpirun -n 4 code-mpi
int main(int argc, char *argv[]) { 
    MPI_Init(&argc, &argv);
    cout << "Hello, World!" << endl;
    
    int processor_amount;
    MPI_Comm_size(MPI_COMM_WORLD, &processor_amount);

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    cout << "Processor Amount " << processor_amount << " Processor Rank " << rank << endl; 

    MPI_Barrier(MPI_COMM_WORLD);
    if (rank == 0) {
      cout << "All processors passed the barrier." << endl; 
    }

    if (rank == 0) {
      int buf = 42;
      // const void* buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm
      MPI_Send(&buf, 1, MPI_INT, 1, 0, MPI_COMM_WORLD);
    } if (rank == 1) {
      int recieved_message; 
      MPI_Recv(&recieved_message, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      cout << "Prcoess 1 recieved_message " << recieved_message << endl;
    }

    MPI_Finalize();
    return 0;
}
