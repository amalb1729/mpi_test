// File: cracker_dynamic_final.c
// To compile: mpicc cracker_dynamic_final.c -o load_mpi -lcrypt

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>

#define MAX_PASSWORD_LENGTH 6
#define CHARSET "abcdefghijklmnopqrstuvwxyz0123456789"
#define CHARSET_SIZE 36
#define WORK_CHUNK_SIZE 100000
#define TAG_WORK_REQUEST 1
#define TAG_WORK_ASSIGNMENT 2
#define TAG_NO_MORE_WORK 3
#define TAG_PASSWORD_FOUND 4
#define TAG_GLOBAL_STOP 5 // New tag for the instant stop signal

// (generate_password, calculate_combinations, and check_password are unchanged)
void generate_password(long long index, char *password, int length) {
    for (int i = length - 1; i >= 0; i--) {
        password[i] = CHARSET[index % CHARSET_SIZE];
        index /= CHARSET_SIZE;
    }
    password[length] = '\0';
}
long long calculate_combinations(int length) {
    long long total = 1;
    for (int i = 0; i < length; i++) {
        total *= CHARSET_SIZE;
    }
    return total;
}
int check_password(const char *password, const char *hash) {
    char salt[32];
    int dollar_count = 0;
    int i;
    for (i = 0; i < strlen(hash) && dollar_count < 3; i++) {
        salt[i] = hash[i];
        if (hash[i] == '$') {
            dollar_count++;
        }
    }
    salt[i] = '\0';
    char *result = crypt(password, salt);
    return result != NULL && strcmp(result, hash) == 0;
}

// --- MANAGER'S LOGIC ---
void manager_main(int size, const char* target_hash, double global_start_time) {
    double end_time;
    int global_found = 0;
    char found_password[MAX_PASSWORD_LENGTH + 1] = {0};
    int finder_rank = -1;

    for (int len = 1; len <= MAX_PASSWORD_LENGTH && !global_found; len++) {
        long long total_combinations = calculate_combinations(len);
        long long next_start_index = 0;
        int workers_finished = 0;

        printf("Trying length %d (%lld combinations)...\n", len, total_combinations);
        
        // Initial work distribution
        for (int i = 1; i < size; i++) {
            if (next_start_index < total_combinations) {
                MPI_Send(&next_start_index, 1, MPI_LONG_LONG, i, TAG_WORK_ASSIGNMENT, MPI_COMM_WORLD);
                next_start_index += WORK_CHUNK_SIZE;
            } else {
                MPI_Send(0, 0, MPI_INT, i, TAG_NO_MORE_WORK, MPI_COMM_WORLD);
                workers_finished++;
            }
        }
        
        while (workers_finished < (size - 1)) {
            MPI_Status status;
            long long dummy_request;
            MPI_Recv(&dummy_request, 1, MPI_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &status);
            int worker_rank = status.MPI_SOURCE;

            if (status.MPI_TAG == TAG_PASSWORD_FOUND) {
                global_found = 1;
                finder_rank = worker_rank;
                MPI_Recv(found_password, MAX_PASSWORD_LENGTH + 1, MPI_CHAR, worker_rank, TAG_PASSWORD_FOUND, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                printf("  [%.4fs] [Manager] Received FOUND signal from Process %d. Entering shutdown mode.\n", MPI_Wtime() - global_start_time, worker_rank);
                fflush(stdout);
                
                // Now that it's found, just listen for other workers and tell them to stop
                // This replaces the previous logic.
                for (int i = 1; i < size; i++) {
                    MPI_Send(0, 0, MPI_INT, i, TAG_GLOBAL_STOP, MPI_COMM_WORLD);
                }
                // All workers have been told to stop, so we can exit the loop.
                workers_finished = size - 1;

            } else if (status.MPI_TAG == TAG_WORK_REQUEST) {
                if (next_start_index >= total_combinations) {
                    MPI_Send(0, 0, MPI_INT, worker_rank, TAG_NO_MORE_WORK, MPI_COMM_WORLD);
                    workers_finished++;
                } else {
                    MPI_Send(&next_start_index, 1, MPI_LONG_LONG, worker_rank, TAG_WORK_ASSIGNMENT, MPI_COMM_WORLD);
                    next_start_index += WORK_CHUNK_SIZE;
                }
            }
        }
        MPI_Barrier(MPI_COMM_WORLD); // All processes wait here before starting next length
    }
    
    end_time = MPI_Wtime();

    if (global_found) {
        printf("\n========================================\n");
        printf("PASSWORD FOUND!\n");
        printf("Process %d found: %s\n", finder_rank, found_password);
        printf("Time taken: %.2f seconds\n", end_time - global_start_time);
        printf("========================================\n");
    } else {
        printf("\nPassword not found within the specified constraints.\n");
        printf("Time taken: %.2f seconds\n", end_time - global_start_time);
    }
}

// --- WORKER'S LOGIC ---
void worker_main(int rank, const char* target_hash, double global_start_time) {
    int should_exit_completely = 0;
    for (int len = 1; len <= MAX_PASSWORD_LENGTH && !should_exit_completely; len++) {
        while (1) {
            long long start_index;
            MPI_Status status;
            MPI_Recv(&start_index, 1, MPI_LONG_LONG, 0, MPI_ANY_TAG, MPI_COMM_WORLD, &status);

            if (status.MPI_TAG == TAG_NO_MORE_WORK) {
                break; // Manager told me to stop for THIS length.
            }
            if (status.MPI_TAG == TAG_GLOBAL_STOP) {
                should_exit_completely = 1;
                break; // Manager told me the entire job is done.
            }

            long long end_index = start_index + WORK_CHUNK_SIZE;
            int found_in_chunk = 0;
            for (long long i = start_index; i < end_index && i < calculate_combinations(len); i++) {
                // --- FIX: INSTANT STOP CHECK ---
                // Periodically check if a stop message has arrived, without blocking.
                if (i > start_index && i % 5000 == 0) {
                    int flag = 0;
                    MPI_Iprobe(0, TAG_GLOBAL_STOP, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
                    if (flag) {
                        should_exit_completely = 1;
                        break; // Stop working on this chunk immediately
                    }
                }

                char password[MAX_PASSWORD_LENGTH + 1];
                generate_password(i, password, len);
                if (check_password(password, target_hash)) {
                    long long dummy = 0;
                    MPI_Send(&dummy, 1, MPI_LONG_LONG, 0, TAG_PASSWORD_FOUND, MPI_COMM_WORLD);
                    MPI_Send(password, strlen(password) + 1, MPI_CHAR, 0, TAG_PASSWORD_FOUND, MPI_COMM_WORLD);
                    found_in_chunk = 1;
                    should_exit_completely = 1; // I found it, so I should exit
                    break;
                }
            }
            
            if (should_exit_completely) {
                break;
            }
            
            // Finished my chunk, ask for another for this length.
            long long dummy_request = 0;
            MPI_Send(&dummy_request, 1, MPI_LONG_LONG, 0, TAG_WORK_REQUEST, MPI_COMM_WORLD);
        }
        MPI_Barrier(MPI_COMM_WORLD);
    }
}

int main(int argc, char *argv[]) {
    int rank, size;
    char target_hash[128] = {0};
    double global_start_time = 0.0;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (rank == 0) {
        if (argc != 2 || size < 2) {
            printf("Usage: %s <password_hash>\n", argv[0]);
            printf("Requires at least 2 processes (1 manager, 1+ workers).\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        strncpy(target_hash, argv[1], sizeof(target_hash) - 1);
        printf("Starting distributed password cracking with dynamic load balancing...\n");
        printf("Manager: Process 0\nWorkers: %d\n", size - 1);
        printf("Target hash: %s\n", target_hash);
        global_start_time = MPI_Wtime();
    }

    MPI_Bcast(&global_start_time, 1, MPI_DOUBLE, 0, MPI_COMM_WORLD);
    MPI_Bcast(target_hash, sizeof(target_hash), MPI_CHAR, 0, MPI_COMM_WORLD);
    
    if (rank == 0) {
        manager_main(size, target_hash, global_start_time);
    } else {
        worker_main(rank, target_hash, global_start_time);
    }

    // --- FIX: CLEAN EXIT ---
    // All processes, manager and worker, will naturally arrive here after their main loops are complete.
    // The barrier ensures no process terminates early.
    MPI_Barrier(MPI_COMM_WORLD);
    
    MPI_Finalize();
    return 0;
}
