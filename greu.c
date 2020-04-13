/* System headers */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Network headers */
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

/* System-dependent headers */
#ifdef __linux__
/* Linux tunnel header */
#include <linux/if_tun.h>
#else
#ifndef __MACH__
/* Non-macOS BSD header */
#include <net/if_tun.h>
#endif
#endif

/* libevent */
#include <event.h>

/* Control headers */
#include <spawn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#define ETHER_PACKET 0x6558
#define IPv4_PACKET 0x0800
#define IPv6_PACKET 0x86DD

#define ARRAY_SIZE 10
#define BUFSIZE 1024

struct tuntap {
    char *tuntap_location;
    int is_tap;
    int fd;
    int socket_fd;
    uint32_t key;
};

struct gre_header {
    uint16_t flags;
    uint16_t protocol;
};

extern int errno;
extern char **environ;

struct tuntap **taplist;
int num_tuntaps;

/**
 *  Print usage information for the program.
 */
#ifdef __linux__
void
#else
__dead void
#endif
usage()
{
    extern char *__progname;
    fprintf(stderr, "%s", "greu [-46d] [-l address] [-p port] [-e /dev/tapX[@key]] [-i /dev/tunX[@key]] server [port]");
    exit(1);
}

struct addrinfo *
resolve_address(const char *hostname, const char *service_name, sa_family_t ai_family)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = ai_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    error = getaddrinfo(hostname, service_name, &hints, &res);

    if (error) {
        lerrx(1, "%s", gai_strerror(error));
    }

    return res;
}

/**
 *  Open a socket to a server using a hostname and service name.
 */
int
connect_to_server(char* hostname, char* service_name, sa_family_t ai_family, const char *src_address, const char *src_port)
{
    struct addrinfo *local_addrinfo, *remote_addrinfo, *res;
    int socket_fd;
    const char *cause;

    local_addrinfo = resolve_address(src_address, src_port, ai_family);

    /* Attempt to bind to the specified local address and port */
    for (res = local_addrinfo; res != NULL; res = res->ai_next) {
        socket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

        if (socket_fd < 0) {
            cause = strerror(errno);
            continue;
        }

        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
            cause = strerror(errno);
            continue;
        }

        /* Bind socket to a specific local address and port if necessary */
        if (bind(socket_fd, res->ai_addr, res->ai_addrlen) < 0) {
            cause = strerror(errno);
            close(socket_fd);
            socket_fd = -1;
            continue;
        }

        break;
    }

    remote_addrinfo = resolve_address(hostname, service_name, ai_family);

    /* Attempt to connect to the specified hostname/service_name pair */
    for (res = remote_addrinfo;  res != NULL; res = res->ai_next) {
        if (connect(socket_fd, res->ai_addr, res->ai_addrlen) < 0) {
            cause = strerror(errno);
            close(socket_fd);
            socket_fd = -1;
            continue;
        }

        break;
    }

    if (socket_fd < 0) {
        lerr(1, "Error connecting to server: %s", cause);
    }

    freeaddrinfo(local_addrinfo);
    freeaddrinfo(remote_addrinfo);

    return socket_fd;
}

/**
 *  Decapsulate packets received from a socket and return them to their respective TUN/TAP interface.
 */
void
decapsulate(int fd, short events, void *conn)
{
    char *buffer;
    struct gre_header *header;
    uint32_t key;
    int is_tap;
    ssize_t read_length;

    buffer = malloc(BUFSIZE);

    if (read_length = read(fd, buffer, BUFSIZE), read_length < 0) {
        lerrx(1, "Error reading from socket: %s", strerror(errno));
    }

    header = (struct gre_header *) buffer;

    /* Check GRE Key Present field */
    if (header->flags & 0x2000) {
        memcpy(&key, &buffer[4], sizeof(key));
        buffer += 4;
        read_length -= 4;
    }

    /* Read packet protocol type */
    if (ntohs(header->protocol) == ETHER_PACKET) {
        is_tap = 1;
    } else {
        is_tap = 0;
    }

    int i;
    for (i = 0; i < num_tuntaps; ++i) {
        /* Ensure whether packet is for TUN/TAP matches */
        if (taplist[i]->is_tap == is_tap) {
            if (taplist[i]->key == ntohs(key)) {
                write(taplist[i]->fd, &buffer[4], read_length - 4);
            }
        }
    }
}

/**
 *  Encapsulate packets receive from a TUN/TAP interface with a GRE header.
 */
void
encapsulate(int fd, short events, void *conn)
{
    char *buffer;
    struct tuntap *tuntap_struct;
    struct gre_header header;
    ssize_t read_length;
    ssize_t datalen;

    char *data;
    uint32_t address_family;

    buffer = malloc(BUFSIZE);
    tuntap_struct = (struct tuntap *) conn;
    memset(&header, 0, sizeof(struct gre_header));

    /* Read frame/packet from tunnel device */
    if (read_length = read(fd, buffer, BUFSIZE), read_length < 0) {
        lerrx(1, "Error reading from tunnel device %s: %s", tuntap_struct->tuntap_location, strerror(errno));
    }

    /* Set GRE Key Present field */
    if (tuntap_struct->key != 0) {
        header.flags = header.flags | 0x2000;
    }

    /* Set GRE Protocol Type field */
    if (tuntap_struct->is_tap) {
        header.protocol = htons(ETHER_PACKET);
    } else {
        /* TUN prefixes data with 4-byte network order EtherType */
        memcpy(&address_family, buffer, sizeof(address_family));

        switch (ntohl(address_family)) {
            case AF_INET:
                header.protocol = htons(IPv4_PACKET);
                break;

            case AF_INET6:
                header.protocol = htons(IPv6_PACKET);
                break;

            default:
                /* Address family is unsupported */
                return;
        }

        buffer += 4;
        read_length -= 4;
    }

    /* Initialise data buffer and prepend header */
    data = malloc(sizeof(struct gre_header) + read_length);
    memset(data, 0, sizeof(struct gre_header) + read_length);
    memcpy(data, &header, sizeof(struct gre_header));
    datalen = sizeof(struct gre_header) + read_length;

    /* Prepend GRE key to data if necessary */
    if (tuntap_struct->key != 0) {
        if (data = realloc(data, sizeof(struct gre_header) + sizeof(uint32_t) + read_length), data == NULL) {
            lerrx(1, "%s", strerror(errno));
        }

        memcpy(&data[4], &tuntap_struct->key, sizeof(uint32_t));
        datalen += 4;
    }

    /* Append data read from tunnel device to data buffer */
    memcpy(&data[datalen - read_length], buffer, read_length);

    write(tuntap_struct->socket_fd, data, datalen);
}

/**
 *  Open a TUN/TAP interface using a named location.
 */
int
open_tuntap(char *device_parameter, int is_tap, int socket_fd)
{
    int fd, err;
    struct event *ev;
    struct tuntap *tuntap_struct;
    char *tuntap_location;

    uintmax_t key_value;

    /* Split key from device path */
    tuntap_location = strsep(&device_parameter, "@");

#ifdef __linux__
    /* Open the default tunnel device if on Linux */
    if (fd = open("/dev/net/tun", O_RDWR), fd < 0) {
        lerrx(1, "Error opening generic tunnel device for %s: %s", tuntap_location, strerror(err));
        return fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
    strncpy(ifr.ifr_name, device_parameter, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        lerrx(1, "Error opening tunnel device %s: %s", tuntap_location, strerror(err));
        return fd;
    }

#else
    if (fd = open(tuntap_location, O_RDWR), fd < 0) {
        err = errno;
        lerrx(1, "Error opening tunnel device %s: %s", tuntap_location, strerror(err));
        return fd;
    }
#endif

    /* Make sure the file descriptor isn't blocking */
    if (err = ioctl(fd, FIONBIO, &(int){ 1 }), err < 0) {
        close(fd);
        lerrx(1, "Error opening tunnel device %s: %s", tuntap_location, strerror(err));
    }

    /* Initialise TUN/TAP details */
    tuntap_struct = malloc(sizeof(struct tuntap));
    memset(tuntap_struct, 0, sizeof(struct tuntap));
    tuntap_struct->tuntap_location = tuntap_location;
    tuntap_struct->is_tap = is_tap;
    tuntap_struct->fd = fd;
    tuntap_struct->socket_fd = socket_fd;

    /* Convert key to a valid uint32_t */
    if (device_parameter != NULL) {
        key_value = strtoumax(device_parameter, NULL, 32);
        if (key_value == UINTMAX_MAX) {
            lerrx(1, "Invalid key specified for device %s", tuntap_location);
        } else {
            tuntap_struct->key = htons((uint32_t) key_value);
        }
    }

    taplist[num_tuntaps++] = tuntap_struct;

    /* Register an event for the given file descriptor */
    ev = malloc(sizeof(struct event));
    memset(ev, 0, sizeof(struct event));
    event_set(ev, fd, EV_READ|EV_PERSIST, encapsulate, tuntap_struct);

    if (event_add(ev, NULL) < 0) {
        lerrx(1, "Error listening to tap %s", tuntap_location);
    }

    return fd;
}

/**
 *  Multiplex multiple IP or Ethernet tunnels over a single UDP socket.
 */
int
main(int argc, char** argv)
{
    char* program_path = argv[0];
    int option;

    /* Option Values */
    char *hostname, *service_name, *src_address, *src_port;
    sa_family_t ai_family;

    int socket_fd;

    int daemonise = 1;

    /* Initialise default values */
    ai_family = AF_UNSPEC;
    service_name = "4754";
    src_address = NULL;
    src_port = "4754";

    struct event *socket_event;

    char **taps;
    int num_taps;

    char **tuns;
    int num_tuns;

    num_taps = 0;
    num_tuns = 0;
    num_tuntaps = 0;

    taps = malloc(ARRAY_SIZE * sizeof(char *));
    tuns = malloc(ARRAY_SIZE * sizeof(char *));

    /* Parse options using getopt */
    while ((option = getopt(argc, argv, "46dl:p:e:i:")), option != -1) {
        switch (option) {
            case '4':
                /* Force greu to use IPv4 addresses only */
                ai_family = AF_INET;
                break;

            case '6':
                /* Force greu to use IPv6 addresses only */
                ai_family = AF_INET6;
                break;

            case 'd':
                /* Do not daemonise. greu daemonises by default */
                daemonise = 0;
                break;

            case 'l':
                /* Bind to the specified local address */
                src_address = optarg;
                break;

            case 'p':
                /* Use the specified source port */
                src_port = optarg;
                break;

            case 'e':
                /* Tunnel Ethernet traffic for the specified tunnel device */
                taps[num_taps++] = optarg;
                break;

            case 'i':
                /* Tunnel IPv4 and IPv6 traffic for the specified tunnel device */
                tuns[num_tuns++] = optarg;
                break;

            case '?':
            default:
                usage();
                break;
        }
    }

    /* Adjust argc and argv to account for switches and flags */
    argc -= optind;
    argv += optind;

    /* A server must be specified */
    if (argc < 1) {
        usage();
    } else if (argc > 1) {
        /* Check whether a specific destination port or service has been specified */
        service_name = argv[1];
        /* TODO: Check this is correct */
        src_port = argv[1];
    }

    if (num_taps < 1 && num_tuns < 1) {
        lerrx(1, "At least one IP or Ethernet tunnel must be configured.");
    }

    hostname = argv[0];

    /* Open a UDP socket to specified server (default port 4754) */
    socket_fd = connect_to_server(hostname, service_name, ai_family, src_address, src_port);

    /* TODO: daemon() has been deprecated */
    /* Daemonise */
    if (daemonise) {
        pid_t pid;
        int err;

        err = posix_spawn(&pid, program_path, NULL, NULL, argv, environ);

        if (err == 0) {
          /* Daemon initialisation succeeded */
          exit(0);
        } else {
          lerrx(1, "Daemon initialisation failed");
        }
    }

    /* Initialise libevent */
    /* Event setup has to occur after daemonisation. Event struct data is not carried across fork */
    event_init();

    /* Create event for when data is received on the socket */
    socket_event = malloc(sizeof(struct event));
    memset(socket_event, 0, sizeof(struct event));
    event_set(socket_event, socket_fd, EV_READ|EV_PERSIST, decapsulate, socket_event);
    event_add(socket_event, NULL);

    /* Allocate memory for global taplist */
    taplist = malloc((num_taps + num_tuns) * sizeof(struct tuntap));
    memset(taplist, 0, (num_taps + num_tuns) * sizeof(struct tuntap));

    /* Loop through configured TUN/TAP interfaces */
    int i;
    for (i = 0; i < num_taps; ++i) {
        open_tuntap(taps[i], 1, socket_fd);
    }

    for (i = 0; i < num_tuns; ++i) {
        open_tuntap(tuns[i], 0, socket_fd);
    }

    /* Redirect output to syslog once devices open */
    logger_syslog(getprogname());

    /* Run the event loop. This is a blocking call */
    event_dispatch();

    for (i = 0; i < num_tuntaps; ++i) {
        close(taplist[i]->fd);
    }

    free(taps);
    free(tuns);
    free(taplist);
    close(socket_fd);

    return 0;
}
