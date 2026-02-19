#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE 2048

// Convert string to lowercase
void to_lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

// Dynamic keyword-based threat scoring
int calculate_threat_score(char *line) {
    int score = 0;

    if (strstr(line, "failed")) score += 2;
    if (strstr(line, "brute")) score += 5;
    if (strstr(line, "sql")) score += 8;
    if (strstr(line, "xss")) score += 7;
    if (strstr(line, "malware")) score += 10;
    if (strstr(line, "unauthorized")) score += 6;
    if (strstr(line, "ddos")) score += 9;
    if (strstr(line, "phishing")) score += 5;
    if (strstr(line, "error")) score += 1;
    if (strstr(line, "attack")) score += 4;

    return score;
}

int main(int argc, char *argv[]) {

    int rank, size;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 2) {
        if (rank == 0)
            printf("Usage: ./mpi_log_analyzer <logfile>\n");
        MPI_Finalize();
        return 0;
    }

    FILE *file = fopen(argv[1], "r");
    if (!file) {
        if (rank == 0)
            printf("Error opening file.\n");
        MPI_Finalize();
        return 0;
    }

    int total_logs = 0;
    char line[MAX_LINE];

    // First pass: count total logs
    while (fgets(line, MAX_LINE, file) != NULL) {
        total_logs++;
    }

    rewind(file);  // Go back to start of file

    MPI_Barrier(MPI_COMM_WORLD);
    double start_time = MPI_Wtime();

    int logs_per_process = total_logs / size;
    int remainder = total_logs % size;

    int start = rank * logs_per_process + (rank < remainder ? rank : remainder);
    int end = start + logs_per_process + (rank < remainder ? 1 : 0);

    int current_line = 0;
    int local_score = 0;

    // Second pass: process only assigned lines
    while (fgets(line, MAX_LINE, file) != NULL) {

        if (current_line >= start && current_line < end) {
            to_lowercase(line);
            local_score += calculate_threat_score(line);
        }

        current_line++;
    }

    fclose(file);

    printf("Process %d Local Threat Score: %d\n", rank, local_score);

    int global_score = 0;

    MPI_Reduce(&local_score, &global_score, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    double end_time = MPI_Wtime();

    if (rank == 0) {
        printf("\n==============================\n");
        printf("Total logs read: %d\n", total_logs);
        printf("GLOBAL THREAT SCORE: %d\n", global_score);
        printf("Execution Time: %f seconds\n", end_time - start_time);
        printf("==============================\n");
    }

    MPI_Finalize();
    return 0;
}
