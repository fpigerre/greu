#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>

#ifdef __linux__
#include <linux/if_tun.h>
#else
#include <net/if_tun.h>
#endif

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
    unsigned long key;
    char *data;
};

extern int errno;

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
    fprintf(stderr, "greu [-46d] [-l address] [-p port] [-e /dev/tapX[@key]] [-i /dev/tunX[@key]] server [port]\n");
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
    
    for (res = remote_addrinfo;  res != NULL; res = res->ai_next) {
        /* Connect to the corresponding socket */
        if (connect(socket_fd, res->ai_addr, res->ai_addrlen) < 0) {
            cause = strerror(errno);
            close(socket_fd);
            socket_fd = -1;
            continue;
        }
        
        break;
    }
    
    if (socket_fd < 0) {
        lerr(1, "%s", cause);
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
    char buffer[BUFSIZE];
    struct gre_packet *packet;
    int is_tap;
    size_t length;
    
    read(fd, &buffer, BUFSIZE);
    packet = (struct gre_packet *) buffer;
    
    if (ntohs(packet->ethertype) == ETHER_PACKET) {
        is_tap = 1;
        length = sizeof(*packet->data);
    } else {
        is_tap = 0;
        length = sizeof(packet->ethertype) + sizeof(*packet->data);
    }
    
    int i;
    for (i = 0; i < num_tuntaps; ++i) {
        /* Ensure whether packet is for TUN/TAP matches */
        if (taplist[i]->is_tap == is_tap) {
            if (taplist[i]->key == ntohs(packet->key)) {
                if (is_tap) {
                    write(taplist[i]->fd, packet->data, length);
                } else {
                    write(taplist[i]->fd, htons(packet->ethertype) + packet->data, length);
                }
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
    char buffer[BUFSIZE];
    struct tuntap *tuntap_struct;
    struct gre_packet packet;
    ssize_t read_length;
    
    tuntap_struct = (struct tuntap *) conn;
    memset(&packet, 0, sizeof(struct gre_packet));
    
    /* Read frame/packet */
    if (read_length = read(fd, &buffer, BUFSIZE), read_length < 0) {
        lerrx(1, "Error reading from tunnel device %s: %s\n", tuntap_struct->tuntap_location, strerror(read_length));
    }
    
    /* Copy read data to packet struct */
    packet.data = malloc(read_length);
    memset(packet.data, 0, read_length);
    
    /* Populate EtherType value */
    if (tuntap_struct->is_tap) {
        packet.ethertype = ETHER_PACKET;
        strncpy(packet.data, buffer, read_length);
    } else {
        /* Check whether TUN packet is IPv4 or IPv6 */
        if ((buffer[0] & 0x40) == 0x40) {
            packet.ethertype = IPv4_PACKET;
        } else {
            packet.ethertype = IPv6_PACKET;
        }
        /* Packets from tun(4) are prefixed with a 4 byte tunnel header */
        strncpy(&packet.data[4], buffer, read_length - (4 * sizeof(char)));
    }
    
    packet.key = tuntap_struct->key;
    
    write(tuntap_struct->socket_fd, &packet, sizeof(struct gre_packet) + read_length);
    free(packet.data);
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
    
    if (num_taps < 1 && num_tuns < 1) {
        lerrx(1, "At least one IP or Ethernet tunnel must be configured.");
    }
    
    hostname = argv[0];
    
    /* Open a UDP socket to specified server (default port 4754) */
    socket_fd = connect_to_server(hostname, service_name, ai_family, src_address, src_port);
    
    /* TODO: daemon() has been deprecated */
    /* Daemonise */
    if (daemonise) {
        logger_syslog(getprogname());
        daemon(0, 0);
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
