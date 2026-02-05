#include <mpi.h>
#include <iostream>
#include <vector>
#include "unistd.h"
#include "clear_error.h"

// ----------------------
// 1. AST-based checks
//  ----------------------

// 1.1. type mismatch
// buffer type and specified MPI type do not match
void demonstrateTypeMismatch(int rank) {
    if (rank == 0) {
        int buf = 42;
        MPI_Send(&buf, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD);
    } else if (rank == 1) {
        int received_message;
        MPI_Recv(&received_message, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received_message " << received_message << std::endl;
    }
}

// 1.2. incorrect buffer referencing 
// buffer is not correctly referenced when passed to an MPI function
void demonstrateIncorrectBufferReferencing(int rank) {
    if (rank == 0) {
        int buf = 42;
        int* buf_pointer = &buf;
        MPI_Send(&buf_pointer, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD);
    } else if (rank == 1) {
        int received_message;
        MPI_Recv(&received_message, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received_message " << received_message << std::endl;
    }
}

// ----------------------
// 2. Path-sensitiv checks
//  ----------------------


// 2.1. double nonblocking
// double request usage of nonblocking calls without intermediate wait
void demonstrateDoubleNonblocking(int rank) {
    MPI_Request requestOne;
    if (rank == 0) {
        int buf = 42;
        MPI_Isend(&buf, 1, MPI_INT, 1, 0, MPI_COMM_WORLD, &requestOne);
        MPI_Isend(&buf, 1, MPI_INT, 1, 0, MPI_COMM_WORLD, &requestOne);
        MPI_Wait(&requestOne, MPI_STATUS_IGNORE);
    } else if (rank == 1) {
        int received_message;
        MPI_Irecv(&received_message, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &requestOne);
        MPI_Wait(&requestOne, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received_message " << received_message << std::endl;
    }
}

// 2.2. unmatched wait
// waiting for a request that was never used by a non-blocking call
void demonstrateUnmatchedWait(int rank) {
    MPI_Request requestTwo;
    if (rank == 0) {
        MPI_Wait(&requestTwo, MPI_STATUS_IGNORE);
    } else if (rank == 1) {
        MPI_Wait(&requestTwo, MPI_STATUS_IGNORE);
    }
}

// 2.3. missing wait
// nonblocking call without matching wait
void demonstrateMissingWait(int rank) {
    MPI_Request requestThree;
    if (rank == 0) {
        int buf = 42;
        MPI_Isend(&buf, 1, MPI_INT, 1, 0, MPI_COMM_WORLD, &requestThree);
    } else if (rank == 1) {
        int received_message;
        MPI_Irecv(&received_message, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &requestThree);
        MPI_Wait(&requestThree, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received_message " << received_message << std::endl;
    }
}

// ----------------------
// 3. Potential future checks 
//  ----------------------

// 3.1. Overwritten buffer whilst sending
// This can be quite a tricky bug since it only goes wrong when using a large enough buffer 
void demonstrateOverwrittenBuffer(int rank) {
    MPI_Request request;
    if (rank == 0) {
        // Large buffer (4 MB) -> should exceed eager threshold
        std::vector<int> buf(1'000'000, 42);

        std::cout << "Process 0 sending buffer of size " << buf.size()
                  << " with initial value " << buf[0] << std::endl;

        // Start nonblocking send
        MPI_Isend(buf.data(), buf.size(), MPI_INT, 1, 0, MPI_COMM_WORLD, &request);

        // "Accidentally" overwrite the buffer before send completes
        for (size_t i = 0; i < buf.size(); i++) {
            buf[i] = 666;
        }
        MPI_Wait(&request, MPI_STATUS_IGNORE);
    } else if (rank == 1) {
        std::vector<int> received_message(1'000'000, 0);
        MPI_Irecv(received_message.data(), received_message.size(), MPI_INT, 0, 0, MPI_COMM_WORLD, &request);

        MPI_Wait(&request, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received buffer[0] = " << received_message[0]
                  << ", buffer[last] = " << received_message.back() << std::endl;
    }
}


// 3.2. Overwritten buffer whilst recieving
// This can be quite a tricky bug since it only goes wrong when using a large enough buffer 
void demonstrateOverwrittenBufferWhenRecieving(int rank) {
    MPI_Request request;
    if (rank == 0) {
        // Large buffer (4 MB) -> should exceed eager threshold
        std::vector<int> buf(1'000'000, 42);

        std::cout << "Process 0 sending buffer of size " << buf.size()
                  << " with initial value " << buf[0] << std::endl;

        // Start nonblocking send
        MPI_Isend(buf.data(), buf.size(), MPI_INT, 1, 0, MPI_COMM_WORLD, &request);

        MPI_Wait(&request, MPI_STATUS_IGNORE);
    } else if (rank == 1) {
        std::vector<int> received_message(1'000'000, 0);
        MPI_Irecv(received_message.data(), received_message.size(), MPI_INT, 0, 0, MPI_COMM_WORLD, &request);

        // Sleep briefly
        sleep(1);

        // Overwritte buffer before recieving is finished.
        received_message[0] = 666;
        received_message[999'999] = 666;
        
        MPI_Wait(&request, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received buffer[0] = " << received_message[0]
                  << ", buffer[last] = " << received_message.back() << std::endl;
    }
}

// 3.3. buffer free'd before sending
// Since this results in reading random memory it usually crashes - thus this isnt that important to check statically
void demonstrateFreedBufferBeforeSending(int rank) {
    MPI_Request request;
    if (rank == 0) {
        // Large buffer (4 MB) -> should exceed eager threshold
        std::vector<int>* buf = new std::vector<int>(1000000, 42);

        std::cout << "Process 0 sending buffer of size " << buf->size()
                  << " with initial value " << 42 << std::endl;

        // Start nonblocking send
        MPI_Isend(buf->data(), buf->size(), MPI_INT, 1, 0, MPI_COMM_WORLD, &request);

        delete buf->data();

        MPI_Wait(&request, MPI_STATUS_IGNORE);
    } else if (rank == 1) {
        std::vector<int> received_message(1'000'000, 0);
        MPI_Irecv(received_message.data(), received_message.size(), MPI_INT, 0, 0, MPI_COMM_WORLD, &request);
        
        MPI_Wait(&request, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received buffer[0] = " << received_message[0]
                  << ", buffer[last] = " << received_message.back() << std::endl;
    }
}

// 3.4. missmatched buffer size
// results in a runtime crash anyways
void demonstrateBufferMismatch(int rank) {
    if (rank == 0) {
        int buf[] = {42, 42};
        MPI_Send(&buf, 2, MPI_INT, 1, 0, MPI_COMM_WORLD);
    } else if (rank == 1) {
        int received_message;
        MPI_Recv(&received_message, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        std::cout << "Process 1 received_message " << received_message << std::endl;
    }
}

// ----------------------
// Main 
//  ----------------------

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    
    int processor_amount;
    MPI_Comm_size(MPI_COMM_WORLD, &processor_amount);

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    
    if (rank == 0) {
      std::cout << "Hello! Here I will demonstrate every error that the MPI-Checker should find." << std::endl;
      std::cout << "Processor Amount " << processor_amount << std::endl;     
    }
    
    // demonstrateTypeMismatch(rank);
    // demonstrateIncorrectBufferReferencing(rank);
    // demonstrateDoubleNonblocking(rank);
    // demonstrateUnmatchedWait(rank);
    // demonstrateMissingWait(rank);
    demonstrateOverwrittenBuffer(rank);
    // demonstrateOverwrittenBufferWhenRecieving(rank);
    // demonstrateFreedBufferBeforeSending(rank);
    // demonstrateTypeMismatch(rank);

    MPI_Finalize();
    return 0;
}
