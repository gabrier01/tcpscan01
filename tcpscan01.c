#define _POSIX_C_SOURCE 200112L
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#pragma region "log and exit"
void puts_exit(char* msg) {
    puts(msg);
    exit(EXIT_FAILURE);
}

void panic(char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}
#pragma endregion

#pragma region "program options"
volatile int opt_v = 0;
volatile int opt_ipv6 = 0;
volatile int opt_thr = 5;
volatile int opt_to = 500000;
volatile char* opt_host = NULL;
volatile int opt_bg = 0;

volatile int opt_ports[65536] = { 0 };
volatile int opt_ports_len = 0;

int int_opt_parser(char* param, char* str, int min, int max) {
    char* errors;
    int parsed = strtol(str, &errors, 10);

    int has_invalid_char = 0;
    while (*errors) {
        if (*errors++ != ' ') ++has_invalid_char;
    }

    int is_invalid = errno || has_invalid_char || parsed < min || parsed > max;
    if (is_invalid) {
        fprintf(stderr, "Invalid value '%s' for %s [%d..%d]\n", str, param, min, max);
        exit(EXIT_FAILURE);
    }

    errno = 0;
    return parsed;
}

void print_help(char** argv, const char* options) {
    const char* const help_str =
        "\nOptions:"
        "\n  -6            Enables IPv6 support (default: IPv4 only)."
        "\n  -v            Enables verbose mode, displaying detailed information."
        "\n  -b            Enables banner grabbing. This may significantly slow down the scan"
        "\n  -h            prints this help message"
        "\n  -t <ms>       Sets the connection timeout (default: 100; 50 to 10000 milliseconds)."
        "\n  -c <number>   Sets the concurrency (default: 5; 1 to 50 threads)."
        "\nRequired:"
        "\n  -H <hostname> Specifies the hostname to scan."
        "\n  -p <ports>    List of ports separated by comma"
        "\n"
        "\nExample:"
        "\n  ./scanner -v -t5 -c10 -6 -H example.com -p 21,22,23,80,443,3306"
        "\n"
        "\nDescription:"
        "\n  Scans common ports (21, 22, 80, 443, 8080) on the specified hostname,"
        "\n  checking which are open. Use verbose mode (-v) to see details of the"
        "\n  process, including resolved IP addresses and tested ports.";

    printf("Usage: %s -%s -H <hostname> -p <p1,p2,p3...>\n%s\n",
        argv[0],
        options,
        help_str
    );
}

void parse_ports(char* ports) {
    char* token = strtok(ports, ",");
    while (token != NULL) {
        int port = int_opt_parser("-p", token, 1, 65535);
        opt_ports[opt_ports_len++] = port;

        token = strtok(NULL, ",");
    }
}

void set_options(int argc, char** argv) {
    const char* available_options = "6vbht:c:H:p:";
    char opt;
    while ((opt = getopt(argc, argv, available_options)) != -1) {
        switch (opt) {
            case 'v': // enables verbose mode
                opt_v = 1;
                break;
            case 'c': // concurrency number (threads)
                opt_thr = int_opt_parser("-c", optarg, 1, 50);
                break;
            case 't': // timeout
                opt_to = int_opt_parser("-t", optarg, 50, 100000) * 1000;
            case '6': // enables ipv6
                opt_ipv6 = 1;
                break;
            case 'H': // set hostname
                opt_host = optarg;
                break;
            case 'b': // enables banner grabbing
                opt_bg = 1;
                break;
            case 'p': // target ports
                parse_ports(optarg);
                break;
            case 'h': // help message
                print_help(argv, available_options);
                exit(EXIT_SUCCESS);
            default:
                print_help(argv, available_options);
                exit(EXIT_FAILURE);
        }
    }

    if (opt_host == NULL) {
        print_help(argv, available_options);
        exit(EXIT_FAILURE);
    }

    if (opt_ports_len == 0) {
        print_help(argv, available_options);
        exit(EXIT_FAILURE);
    }
}
#pragma endregion

#pragma region "thread safe stack"
struct ts_stack_t {
    pthread_mutex_t mu;
    void** data;
    size_t max;
    int top;
};

void stack_init(struct ts_stack_t* stack, int max_capacity) {
    stack->top = -1;
    stack->max = max_capacity;
    stack->data = calloc(max_capacity, sizeof(void *));
    if (!stack->data)
        panic("init_stack::calloc");

    if (pthread_mutex_init(&stack->mu, NULL) != 0)
        panic("init_stack::pthread_mutex_init");
}

void stack_push(struct ts_stack_t* stack, void* data) {
    pthread_mutex_lock(&stack->mu);

    if (stack->top + 1 >= (int)stack->max)
        panic("stack_push::max_size_reached");
    stack->data[++stack->top] = data;

    pthread_mutex_unlock(&stack->mu);
}

void* stack_pop(struct ts_stack_t* stack) {
    void* output = NULL;

    pthread_mutex_lock(&stack->mu);
    if (stack->top >= 0)
        output = stack->data[stack->top--];
    pthread_mutex_unlock(&stack->mu);

    return output;
}
#pragma endregion

int get_host_addresses(const char* host, struct addrinfo ** output) {
    int ai_family = opt_ipv6 ? AF_UNSPEC : AF_INET;
    return getaddrinfo(host, NULL, &(struct addrinfo){
        .ai_family = ai_family, .ai_socktype = SOCK_STREAM
    }, output);
}

int count_addresses(struct addrinfo* root) {
    int count = 0;
    for (struct addrinfo* cur_addr = root; cur_addr != NULL; cur_addr = cur_addr->ai_next) {
        ++count;
    }
    return count;
}

int print_ip(struct addrinfo* info, char* prefix) {
    if (!prefix) prefix = "";

    char ip_buffer[INET6_ADDRSTRLEN] = { 0 };
    void* addr = info->ai_family == AF_INET ?
        (void *)&((struct sockaddr_in *)info->ai_addr)->sin_addr :
        (void *)&((struct sockaddr_in6 *)info->ai_addr)->sin6_addr;

    in_port_t n_port = info->ai_family == AF_INET ?
        ((struct sockaddr_in *)info->ai_addr)->sin_port :
        ((struct sockaddr_in6 *)info->ai_addr)->sin6_port;

    inet_ntop(info->ai_family, addr, ip_buffer, sizeof(ip_buffer));
    return printf("%s%s %hu\n", prefix, ip_buffer, ntohs(n_port));
}

void set_port(struct addrinfo* info, int port) {
    if (info->ai_family == AF_INET) {
        ((struct sockaddr_in *)info->ai_addr)->sin_port = port;
    } else {
        ((struct sockaddr_in6 *)info->ai_addr)->sin6_port = port;
    }
}

struct addrinfo* cpy_addrinfo(struct addrinfo* info) {
    struct addrinfo* copy_addrinfo = calloc(1, sizeof(struct addrinfo));
    if (!copy_addrinfo) panic("cpy_addrinfo::calloc");
    memcpy(copy_addrinfo, info, sizeof(*info));

    copy_addrinfo->ai_addr = calloc(1, info->ai_addrlen);
    if (!copy_addrinfo->ai_addr) panic("copy_addrinfo:ai_addr::calloc");
    memcpy(copy_addrinfo->ai_addr, info->ai_addr, info->ai_addrlen);

    return copy_addrinfo;
}


// thread routine
void* connect_routine(void* args) {
    struct ts_stack_t* stack = (struct ts_stack_t *)args;

    while (1) {
        struct addrinfo* info = stack_pop(stack);
        if (!info) break; // no more data to process

        int sfd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
        if (sfd == -1) panic("connect_routine::socket");

        struct timeval tv = { 0, opt_to };
        setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        int err = connect(sfd, info->ai_addr, info->ai_addrlen);

        if (err == 0) {
            #define OPEN_SIZE sizeof("[OPEN] | ")-1
            char buffer[1024 + OPEN_SIZE] = { 0 };
            strcpy(buffer, "[OPEN] | ");

            if (opt_bg) {
                setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
                int r = recv(sfd, buffer + OPEN_SIZE, sizeof(buffer) - OPEN_SIZE, 0);
                strcpy(buffer + OPEN_SIZE + r - 2, " | ");
            }
            print_ip(info, buffer);
        } else if (opt_v)
            print_ip(info, "[CLOSED] | ");

        free(info->ai_addr);
        free(info);

        close(sfd);

    }

    pthread_exit(NULL);
}

pthread_t* init_threads(void* (*routine)(void *), struct ts_stack_t* stack) {
    pthread_t* threads = calloc(opt_thr, sizeof(pthread_t));
    if (!threads) panic("init_threads::calloc");

    for (int i = 0; i < opt_thr; i++) {
        if (pthread_create(&threads[i], NULL, routine, stack) != 0)
            panic("init_threads::pthread_create");
    }

    return threads;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    set_options(argc, argv);

    opt_v && printf("Hostname: %s\n", opt_host);

    struct addrinfo* root = NULL;
    if (get_host_addresses((const char *)opt_host, &root) != 0)
        panic("get_host_addresses");

    int count_addrs = count_addresses(root);

    if (opt_v) {
        printf("IPs resolved: %lu\n", count_addrs);
        printf("Using threads: %d\n", opt_thr);
        printf("Sockets to be tested: %lu\n", count_addrs * opt_ports_len);
        printf("Connection timeout: %dms\n", opt_to / 1000);
        opt_ipv6 && printf("IPv6 enabled\n");
        opt_bg && printf("Banner grabbing enabled\n");
    }

    struct ts_stack_t stack = { 0 };
    stack_init(&stack, count_addrs * opt_ports_len);

    opt_v && puts("\nWill try:");
    for (struct addrinfo* cur_node = root; cur_node != NULL; cur_node = cur_node->ai_next) {
        for (int port_i = 0; port_i < opt_ports_len; port_i++) {
            struct addrinfo* info = cpy_addrinfo(cur_node);
            set_port(info, htons(opt_ports[port_i]));

            stack_push(&stack, info);
            opt_v && print_ip(info, "[TRY] ");
        }
    }
    opt_v && puts("");
    freeaddrinfo(root);

    pthread_t* threads = init_threads(connect_routine, &stack);
    for (int i = 0; i < opt_thr; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(stack.data);

    return EXIT_SUCCESS;
}
