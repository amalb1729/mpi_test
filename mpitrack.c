// File: cracker_final_safe_timed.c
// To compile: mpicc cracker_final_safe_timed.c -o crmpi -lcrypt

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>

#define MAX_PASSWORD_LENGTH 6
#define CHARSET "abcdefghijklmnopqrstuvwxyz0123456789"
#define CHARSET_SIZE 36
#define MAX_PROCESSES 256
// --- The desired update frequency in seconds ---
#define PROGRESS_UPDATE_SECONDS 0.5

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

int main(int argc, char *argv[]) {
    int rank, size;
    double start_time, end_time;
    char target_hash[128];
    char found_password[MAX_PASSWORD_LENGTH + 1] = {0};
    int password_found = 0;
    int global_found = 0;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (rank == 0) {
        if (argc != 2) {
            printf("Usage: %s <password_hash>\n", argv[0]);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        strncpy(target_hash, argv[1], sizeof(target_hash) - 1);
        printf("Starting distributed password cracking...\n");
        printf("Target hash: %s\n", target_hash);
    }

    MPI_Bcast(target_hash, sizeof(target_hash), MPI_CHAR, 0, MPI_COMM_WORLD);
    start_time = MPI_Wtime();

    for (int len = 1; len <= MAX_PASSWORD_LENGTH && !global_found; len++) {
        long long total_combinations = calculate_combinations(len);
        long long combinations_per_process = total_combinations / size;
        long long start_index = rank * combinations_per_process;
        long long end_index = (rank == size - 1) ? total_combinations : start_index + combinations_per_process;

        if (rank == 0) {
            printf("Trying length %d (%lld combinations)... ", len, total_combinations);
            fflush(stdout);
        }

        double last_update_time = MPI_Wtime();
        long long total_checked_for_len = 0;
        long long passwords_in_batch = 0;

        for (long long i = start_index; i < end_index; i++) {
            char password[MAX_PASSWORD_LENGTH + 1];
            generate_password(i, password, len);
            if (check_password(password, target_hash)) {
                strcpy(found_password, password);
                password_found = 1;
                // No break here; let the sync point handle the exit.
            }

            passwords_in_batch++;
            double current_time = MPI_Wtime();

            // --- SAFE, TIME-BASED PROGRESS AND STOP CHECK ---
            if ((current_time - last_update_time >= PROGRESS_UPDATE_SECONDS) || password_found) {
                long long batch_sum = 0;
                // Step 1: All processes must participate to sum up the work done.
                MPI_Allreduce(&passwords_in_batch, &batch_sum, 1, MPI_LONG_LONG, MPI_SUM, MPI_COMM_WORLD);

                if (rank == 0) {
                    total_checked_for_len += batch_sum;
                    printf("\rTrying length %d (%lld combinations)... Progress: %.2f%%", len, total_combinations,
                           (double)total_checked_for_len / total_combinations * 100.0);
                    fflush(stdout);
                }
                passwords_in_batch = 0;
                last_update_time = current_time;

                // Step 2: Now that all processes are synchronized, check if anyone found the password.
                MPI_Allreduce(&password_found, &global_found, 1, MPI_INT, MPI_LOR, MPI_COMM_WORLD);
                if (global_found) {
                    break; // All processes will break out of the loop together safely.
                }
            }
        }

        // Final sync point at the end of the length to ensure 100% is shown
        if (!global_found) {
            long long final_batch_sum = 0;
            MPI_Allreduce(&passwords_in_batch, &final_batch_sum, 1, MPI_LONG_LONG, MPI_SUM, MPI_COMM_WORLD);
            if (rank == 0) {
                total_checked_for_len += final_batch_sum;
                printf("\rTrying length %d (%lld combinations)... Progress: 100.00%%\n", len, total_combinations);
                fflush(stdout);
            }
            MPI_Allreduce(&password_found, &global_found, 1, MPI_INT, MPI_LOR, MPI_COMM_WORLD);
        }
    }

    end_time = MPI_Wtime();

    if (global_found) {
        if (rank == 0 && password_found == 0) {
             printf("\n"); // Add a newline if another process found the password
        } else if (rank != 0 && password_found == 1) {
            // Silence other workers to keep output clean
        } else if(rank==0 && password_found==1){
             printf("\n");
        }


        char all_passwords[MAX_PROCESSES][MAX_PASSWORD_LENGTH + 1];
        memset(all_passwords, 0, sizeof(all_passwords));
        MPI_Gather(found_password, MAX_PASSWORD_LENGTH + 1, MPI_CHAR, all_passwords, MAX_PASSWORD_LENGTH + 1, MPI_CHAR, 0, MPI_COMM_WORLD);

        if (rank == 0) {
            printf("========================================\n");
            printf("PASSWORD FOUND!\n");
            for (int i = 0; i < size; i++) {
                if (strlen(all_passwords[i]) > 0) {
                    printf("Process %d found: %s\n", i, all_passwords[i]);
                }
            }
            printf("Time taken: %.2f seconds\n", end_time - start_time);
            printf("========================================\n");
        }
    } else {
        if (rank == 0) {
            printf("\nPassword not found within the specified constraints.\n");
            printf("Time taken: %.2f seconds\n", end_time - start_time);
        }
    }

    MPI_Finalize();
    return 0;
}
