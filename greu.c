#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_tun.h>

#include <event.h>

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

struct gre_packet {
    unsigned short preamble;
    unsigned short ethertype;
    unsigned short checksum;
    unsigned short reserved;
    unsigned long key;
    unsigned long sequence;
    unsigned char data[];
};

extern int errno;

struct tuntap **taplist;
int num_tuntaps;

/**
 *  Print usage information for the program.
 */
__dead void
usage()
{
    extern char *__progname;
    fprintf(stderr, "greu [-46d] [-l address] [-p port] [-e /dev/tapX[@key]] [-i /dev/tunX[@key]] server [port]\n");
    exit(1);
}

/**
 *  Open a UDP socket using an addrinfo struct.
 */
int
open_socket(struct addrinfo *result, struct addrinfo *local_result)
{
    struct addrinfo *res0;
    int socket_fd;
    const char *cause;
    
    socket_fd = -1;
    
    /* Find a result that matches the hints given */
    for (res0 = result; res0; res0 = res0->ai_next) {
        /* Open a corresponding socket */
        socket_fd = socket(res0->ai_family, res0->ai_socktype, res0->ai_protocol);
        
        if (socket_fd < 0) {
            cause = "socket";
            continue;
        }
        
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
            cause = "socket options";
            continue;
        }
        
        /* Bind socket to a specific local address and port if necessary */
        if (local_result != NULL) {
            if (bind(socket_fd, local_result->ai_addr, sizeof(*local_result->ai_addr)) < 0) {
                cause = "bind";
                close(socket_fd);
                socket_fd = -1;
                continue;
            }
            freeaddrinfo(local_result);
        }
        
        /* Connect to the corresponding socket */
        if (connect(socket_fd, res0->ai_addr, res0->ai_addrlen) < 0) {
            cause = "connect";
            close(socket_fd);
            socket_fd = -1;
            continue;
        }
        
        break;
    }
    
    if (socket_fd < 0) {
        lerr(1, "%s", cause);
    }
    
    freeaddrinfo(res0);
    return socket_fd;
}

/**
 *  Resolve a hostname and service name into an addrinfo struct.
 */
struct addrinfo *
resolve_addresses(char *hostname, char *service_name, sa_family_t ai_family)
{
    /* TODO: Desired source port is not returned from getaddrinfo */
    int error;
    struct addrinfo hints, *res0;
    
    /* Request a UDP socket using a particular address family */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    
    if (ai_family == AF_INET6) {
        hints.ai_family = AF_INET6;
    } else {
        hints.ai_family = AF_INET;
    }
    
    /* Resolve the hostname */
    error = getaddrinfo(hostname, service_name, &hints, &res0);
    
    if (error) {
        lerrx(1, "%s", gai_strerror(error));
    }
    
    return res0;
}

/**
 *  Open a socket to a server using a hostname and service name.
 */
int
connect_to_server(char* hostname, char* service_name, sa_family_t ai_family, char *src_address, char *src_port)
{
    struct addrinfo *result, *local_result;
    
    result = resolve_addresses(hostname, service_name, ai_family);
    
    if (src_address != NULL) {
        local_result = resolve_addresses(src_address, src_port, ai_family);
    } else {
        local_result = NULL;
    }
    
    return open_socket(result, local_result);
}

/**
 *  Decapsulate packets received from a socket and return them to their respective TUN/TAP interface.
 */
void
decapsulate(int fd, short events, void *conn)
{
    char buffer[BUFSIZE];
    struct gre_packet *packet;
    int is_tap;
    
    packet = (struct gre_packet *) buffer;
    read(fd, &buffer, BUFSIZE);
    
    if (ntohs(packet->ethertype) == ETHER_PACKET) {
        is_tap = 1;
    } else {
        is_tap = 0;
    }
    
    for (int i = 0; i < num_tuntaps; ++i) {
        if (taplist[i]->is_tap == is_tap) {
            if (taplist[i]->key == ntohs(packet->key)) {
                write(taplist[i]->fd, packet->data, sizeof(*packet->data));
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
    /* TODO: Packets on tun are prefixed with ethertype read tun(4) better */
    unsigned char buffer[BUFSIZE];
    struct tuntap *tuntap_struct;
    struct gre_packet packet;
    
    tuntap_struct = (struct tuntap *) conn;
    memset(&packet, 0, sizeof(struct gre_packet));
    
    /* Read frame/packet */
    read(fd, &buffer, BUFSIZE);
    strncpy(packet.data, buffer, BUFSIZE);
    
    /* Populate EtherType value */
    if (tuntap_struct->is_tap) {
        packet.ethertype = ETHER_PACKET;
    } else {
        /* Check whether TUN packet is IPv4 or IPv6 */
        if ((buffer[0] & 0x40) == 0x40) {
            packet.ethertype = IPv4_PACKET;
        } else {
            packet.ethertype = IPv6_PACKET;
        }
    }
    
    packet.key = tuntap_struct->key;
    
    write(tuntap_struct->socket_fd, &packet, sizeof(struct gre_packet) + BUFSIZE);
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
    
    /* Open the default tunnel device */
    if (fd = open(tuntap_location, O_RDWR), fd < 0) {
        err = errno;
        lerrx(1, "Error opening tunnel device %s: %s", tuntap_location, strerror(err));
        return fd;
    }
    
    /* Set the file descriptor to represent a TUN/TAP */
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
            tuntap_struct->key = (uint32_t) key_value;
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
        src_port = argv[1];
    }
    
    hostname = argv[0];
    
    /* Open a UDP socket to specified server (default port 4754) */
    socket_fd = connect_to_server(hostname, service_name, ai_family, src_address, src_port);
    
    /* Initialise libevent */
    event_init();
    
    /* Create event for when data is received on the socket */
    socket_event = malloc(sizeof(struct event));
    memset(socket_event, 0, sizeof(struct event));
    event_set(socket_event, socket_fd, EV_READ|EV_PERSIST, decapsulate, socket_event);
    event_add(socket_event, NULL);
    
    /* Loop through configured TUN/TAP interfaces */
    if (num_taps < 1 && num_tuns < 1) {
        lerrx(1, "At least one IP or Ethernet tunnel must be configured.");
    }
    
    /* Allocate memory for global taplist */
    taplist = malloc((num_taps + num_tuns) * sizeof(struct tuntap));
    
    for (int i = 0; i < num_taps; ++i) {
        open_tuntap(taps[i], 1, socket_fd);
    }
    
    for (int i = 0; i < num_tuns; ++i) {
        open_tuntap(tuns[i], 0, socket_fd);
    }
    
    /* TODO: Event setup has to occur after daemonisation. Event struct data is not carried across fork */
    
    /* Daemonise */
    if (daemonise) {
        logger_syslog(getprogname());
        daemon(0, 0);
    }
    
    /* Run the event loop. This is a blocking call */
    event_dispatch();
    
    // When packets become available on TUN/TAP, encapsulate them in GRE over UDP and send them through the socket
    
    // Implement GRE Key extension header
    
    // Allow doing this for multiple tun/taps
    
    free(taps);
    free(tuns);
    close(socket_fd);
    
    return 0;
}
