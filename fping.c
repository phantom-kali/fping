#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>
#include <math.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_PACKET_SIZE 65527
#define DEFAULT_PACKET_SIZE 56
#define MAX_HOSTS 10

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

struct ping_stats
{
    unsigned long packets_sent;
    unsigned long packets_received;
    double min_rtt;
    double max_rtt;
    double sum_rtt;
    double sum_rtt_square; // For jitter calculation
    struct timeval last_rtt;
};

struct ping_target
{
    char *hostname;
    struct sockaddr_in addr;
    struct ping_stats stats;
};

struct ping_config
{
    bool verbose;
    bool quiet;
    int timeout_ms;
    bool show_dns;
};

volatile bool running = true;
struct ping_target targets[MAX_HOSTS];
int num_targets = 0;
int packet_size = DEFAULT_PACKET_SIZE;

const char *icmp_type_str[] = {
    [ICMP_ECHOREPLY] = "Echo Reply",
    [ICMP_DEST_UNREACH] = "Destination Unreachable",
    [ICMP_SOURCE_QUENCH] = "Source Quench",
    [ICMP_REDIRECT] = "Redirect",
    [ICMP_ECHO] = "Echo Request",
    [ICMP_TIME_EXCEEDED] = "Time Exceeded",
    [ICMP_PARAMETERPROB] = "Parameter Problem"};

struct ping_config config = {
    .verbose = false,
    .quiet = false,
    .timeout_ms = 1000,
    .show_dns = false};

void signal_handler(int signo)
{
    if (!config.quiet)
    {
        printf("\nReceived SIGINT, stopping...\n");
    }
    running = false;
}

void init_stats(struct ping_stats *stats)
{
    memset(stats, 0, sizeof(*stats));
    stats->min_rtt = 999999.0;
}

void print_statistics(struct ping_stats *stats)
{
    // Always print statistics even in quiet mode since it's the final summary
    double loss = 100.0 * (stats->packets_sent - stats->packets_received) / stats->packets_sent;
    double avg_rtt = stats->sum_rtt / stats->packets_received;
    double variance = (stats->sum_rtt_square / stats->packets_received) - (avg_rtt * avg_rtt);
    double jitter = sqrt(variance);

    printf("\n--- Ping statistics ---\n");
    printf("%lu packets transmitted, %lu received, %.1f%% packet loss\n",
           stats->packets_sent, stats->packets_received, loss);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
           stats->min_rtt, avg_rtt, stats->max_rtt, jitter);
}

// Add this prototype before the send_ping function
uint16_t compute_checksum(uint16_t *addr, int len);

void print_verbose_header(struct iphdr *iph, struct icmphdr *icmph)
{
    printf("IP Header:\n");
    printf("  Version: %d, IHL: %d, TOS: %d\n", iph->version, iph->ihl, iph->tos);
    printf("  Total Length: %d, ID: %d\n", ntohs(iph->tot_len), ntohs(iph->id));
    printf("  TTL: %d, Protocol: %d\n", iph->ttl, iph->protocol);

    printf("ICMP Header:\n");
    printf("  Type: %d (%s), Code: %d\n",
           icmph->type,
           icmp_type_str[icmph->type] ? icmp_type_str[icmph->type] : "Unknown",
           icmph->code);
    printf("  Checksum: 0x%04x\n", ntohs(icmph->checksum));
}

void send_ping(int sockfd, struct ping_target *target)
{
    char packet[MAX_PACKET_SIZE];
    struct icmphdr *icmp = (struct icmphdr *)packet;
    struct timeval *tv = (struct timeval *)(packet + sizeof(struct icmphdr));

    memset(packet, 0, packet_size);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = ++target->stats.packets_sent;

    gettimeofday(tv, NULL);
    icmp->checksum = compute_checksum((uint16_t *)icmp, packet_size);

    if (!config.quiet && config.show_dns)
    {
        printf("Pinging %s [%s]\n", target->hostname,
               inet_ntoa(target->addr.sin_addr));
    }

    if (sendto(sockfd, packet, packet_size, 0,
               (struct sockaddr *)&target->addr, sizeof(target->addr)) == -1)
    {
        perror("sendto");
    }
}

// Replace the empty implementation with a proper checksum calculation
uint16_t compute_checksum(uint16_t *addr, int len)
{
    uint32_t sum = 0;
    uint16_t *w = addr;

    // Add up 16-bit words
    while (len > 1)
    {
        sum += *w++;
        len -= 2;
    }

    // Add left-over byte, if any
    if (len > 0)
    {
        sum += *(uint8_t *)w;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

void receive_ping(int sockfd)
{
    char buffer[MAX_PACKET_SIZE];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    struct timeval tv_now;

    // Use non-blocking receive
    struct timeval timeout;
    timeout.tv_sec = config.timeout_ms / 1000;
    timeout.tv_usec = (config.timeout_ms % 1000) * 1000;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    int result = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT,
                          (struct sockaddr *)&sender, &sender_len);

    if (result < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK && !config.quiet)
        {
            perror("recvfrom");
        }
        return;
    }

    struct iphdr *iph = (struct iphdr *)buffer;
    struct icmphdr *icmph = (struct icmphdr *)(buffer + (iph->ihl << 2));

    if (config.verbose && !config.quiet)
    {
        print_verbose_header(iph, icmph);
    }

    if (icmph->type == ICMP_ECHOREPLY)
    {
        for (int i = 0; i < num_targets; i++)
        {
            if (sender.sin_addr.s_addr == targets[i].addr.sin_addr.s_addr)
            {
                struct timeval *tv_sent = (struct timeval *)(buffer + (iph->ihl << 2) + sizeof(struct icmphdr));
                gettimeofday(&tv_now, NULL); // Move this here to ensure accurate timing
                double rtt = (tv_now.tv_sec - tv_sent->tv_sec) * 1000.0 +
                             (tv_now.tv_usec - tv_sent->tv_usec) / 1000.0;

                // Update statistics even in quiet mode
                targets[i].stats.packets_received++;
                targets[i].stats.min_rtt = MIN(targets[i].stats.min_rtt, rtt);
                targets[i].stats.max_rtt = MAX(targets[i].stats.max_rtt, rtt);
                targets[i].stats.sum_rtt += rtt;
                targets[i].stats.sum_rtt_square += rtt * rtt;

                // Only print if not in quiet mode
                if (!config.quiet)
                {
                    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
                           packet_size, inet_ntoa(sender.sin_addr),
                           icmph->un.echo.sequence, iph->ttl, rtt);
                }
                break;
            }
        }
    }
    else if (!config.quiet)
    {
        printf("Received ICMP %s message (Type: %d, Code: %d) from %s\n",
               icmp_type_str[icmph->type] ? icmp_type_str[icmph->type] : "Unknown",
               icmph->type, icmph->code, inet_ntoa(sender.sin_addr));
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s [-s size] hostname [hostname2 ...]\n", argv[0]);
        exit(1);
    }

    int opt;
    while ((opt = getopt(argc, argv, "s:vqt:d")) != -1)
    {
        switch (opt)
        {
        case 's':
            packet_size = atoi(optarg);
            if (packet_size < sizeof(struct icmphdr) + sizeof(struct timeval) ||
                packet_size > MAX_PACKET_SIZE)
            {
                fprintf(stderr, "Invalid packet size\n");
                exit(1);
            }
            break;
        case 'v':
            config.verbose = true;
            break;
        case 'q':
            config.quiet = true;
            break;
        case 't':
            config.timeout_ms = atoi(optarg);
            if (config.timeout_ms < 100 || config.timeout_ms > 60000)
            {
                fprintf(stderr, "Invalid timeout (100-60000 ms)\n");
                exit(1);
            }
            break;
        case 'd':
            config.show_dns = true;
            break;
        }
    }

    if (config.verbose && config.quiet)
    {
        fprintf(stderr, "Cannot use both verbose and quiet modes\n");
        exit(1);
    }

    // Improve signal handling
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);

    for (int i = optind; i < argc && num_targets < MAX_HOSTS; i++)
    {
        struct hostent *host = gethostbyname(argv[i]);
        if (!host)
        {
            fprintf(stderr, "Could not resolve hostname '%s'\n", argv[i]);
            continue;
        }

        targets[num_targets].hostname = argv[i];
        targets[num_targets].addr.sin_family = AF_INET;
        targets[num_targets].addr.sin_port = 0;
        memcpy(&targets[num_targets].addr.sin_addr, host->h_addr_list[0], host->h_length);
        init_stats(&targets[num_targets].stats);
        num_targets++;
    }

    if (num_targets == 0)
    {
        fprintf(stderr, "No valid hosts specified\n");
        exit(1);
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1)
    {
        perror("socket");
        exit(1);
    }

    fd_set read_fds;
    struct timeval timeout;

    while (running)
    {
        for (int i = 0; i < num_targets; i++)
        {
            send_ping(sockfd, &targets[i]);
        }

        // Modified select timeout for more responsive Ctrl+C
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100ms timeout

        if (select(sockfd + 1, &read_fds, NULL, NULL, &timeout) > 0)
        {
            receive_ping(sockfd);
        }

        // Use nanosleep for more precise timing
        struct timespec sleep_time = {0, 1000000000}; // 1 second
        nanosleep(&sleep_time, NULL);
    }

    for (int i = 0; i < num_targets; i++)
    {
        printf("\nStatistics for %s:\n", targets[i].hostname);
        print_statistics(&targets[i].stats);
    }

    close(sockfd);
    return 0;
}