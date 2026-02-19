#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINES 1000
#define MAX_LEN 100

// ------------------------------
// Threat severity scoring
// ------------------------------
int threat_score(char *line) {
    if (strstr(line, "FAILED_LOGIN")) return 1;
    if (strstr(line, "PORT_SCAN")) return 3;
    if (strstr(line, "MALWARE_ALERT")) return 5;
    if (strstr(line, "DDOS_ATTACK")) return 10;
    return 0;
}

int main(int argc, char *argv[]) {

    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    double start_time = MPI_Wtime();

    char logs[MAX_LINES][MAX_LEN];
    int total_lines = 0;

    // ------------------------------
    // Master reads file
    // ------------------------------
    if (rank == 0) {

        if (argc < 2) {
    if (rank == 0)
        printf("Usage: mpirun -np <num> ./mpi_log_analyzer <filename>\n");
    MPI_Finalize();
    return 1;
}

FILE *file = fopen(argv[1], "r");

        if (file == NULL) {
            printf("Error opening file.\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        while (fgets(logs[total_lines], MAX_LEN, file)) {
            total_lines++;
        }

        fclose(file);

        printf("Total logs read: %d\n", total_lines);
    }

    // ------------------------------
    // Broadcast total_lines to all processes
    // ------------------------------
    MPI_Bcast(&total_lines, 1, MPI_INT, 0, MPI_COMM_WORLD);

    // Handle uneven distribution
    int lines_per_process = total_lines / size;
    int remainder = total_lines % size;

    if (rank == 0 && remainder != 0) {
        printf("Warning: Some logs will be ignored due to uneven division.\n");
    }

    char local_logs[MAX_LINES][MAX_LEN];

    // ------------------------------
    // Non-blocking Scatter
    // ------------------------------
    MPI_Request scatter_request;

    MPI_Iscatter(logs,
                 lines_per_process * MAX_LEN,
                 MPI_CHAR,
                 local_logs,
                 lines_per_process * MAX_LEN,
                 MPI_CHAR,
                 0,
                 MPI_COMM_WORLD,
                 &scatter_request);

    MPI_Wait(&scatter_request, MPI_STATUS_IGNORE);

    // ------------------------------
    // Local computation
    // ------------------------------
    int local_threat_score = 0;

    for (int i = 0; i < lines_per_process; i++) {
        local_threat_score += threat_score(local_logs[i]);
    }

    printf("Process %d Local Threat Score: %d\n",
           rank, local_threat_score);

    // ------------------------------
    // Non-blocking Reduce
    // ------------------------------
    int global_threat_score = 0;
    MPI_Request reduce_request;

    MPI_Ireduce(&local_threat_score,
                &global_threat_score,
                1,
                MPI_INT,
                MPI_SUM,
                0,
                MPI_COMM_WORLD,
                &reduce_request);

    MPI_Wait(&reduce_request, MPI_STATUS_IGNORE);

    // ------------------------------
    // Master prints final result
    // ------------------------------
    double end_time = MPI_Wtime();

    if (rank == 0) {
        printf("\n==============================\n");
        printf("GLOBAL THREAT SCORE: %d\n", global_threat_score);
        printf("Execution Time: %f seconds\n", end_time - start_time);
        printf("==============================\n");
    }

    MPI_Finalize();
    return 0;
}
