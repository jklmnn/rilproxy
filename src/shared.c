// Libc includes
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <unistd.h>
#include <arpa/inet.h> // for htons
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>

#include "rilproxy.h"

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif // !ETH_P_ALL

socket_t*
udp_socket (const char *host, unsigned short port)
{
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    int fd, rv;
    socket_t *sock = 0;

    fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) err (1, "socket");

    int enable = 1;
    rv = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if (rv < 0) warn ("setsockopt(SO_REUSEADDR)");

    memset (&local_addr, 0, sizeof (local_addr));

    local_addr.sin_family      = AF_INET;
    local_addr.sin_port        = htons(port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    rv = bind (fd, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if (rv < 0) err (2, "udp_server_socket.bind to %d", port);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port   = htons(port);
    remote_addr.sin_addr.s_addr = inet_addr(host);

    rv = connect (fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
    if (rv < 0) err (2, "connect");

    if(fd >= 0 && rv >= 0){
        sock = (socket_t*)malloc(sizeof(socket_t));
        sock->type = UDP;
        sock->socket = fd;
    }

    return sock;
}

socket_t*
unix_client_socket (const char *socket_path)
{
    int rv = -1;
    int fd = -1;
    struct sockaddr_un addr;
    socket_t *sock = 0;

    fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) err (1, "socket");

    addr.sun_family = AF_UNIX;
    strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path));

    rv = connect (fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_un));
    if (rv < 0)
    {
        close (fd);
        err (2, "unix_client_socket.connect to %s", socket_path);
    }

    fprintf (stderr, "Connected to %s\n", socket_path);
    
    if(fd >= 0 && rv >= 0){
        sock = (socket_t*)malloc(sizeof(socket_t));
        sock->type = UNIX;
        sock->socket = fd;
    }

    return sock;
}

socket_t*
unix_server_socket (const char *socket_path, const char *user)
{
    int rv = -1;
    int fd = -1;
    int msgfd = -1;
    struct sockaddr_un addr;
    socket_t *sock = 0;

    fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) err (1, "socket");

    addr.sun_family = AF_UNIX;
    strncpy (addr.sun_path, socket_path, sizeof (addr.sun_path));

    rv = bind (fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_un));
    if (rv < 0) err (2, "unix_server_socket.bind to %s", socket_path);

    // Change user
    rv = chown (socket_path, get_uid (user), -1);
    if (rv < 0) err (3, "unix_server_socket.chown of %s", socket_path);

    // Change mode
    rv = chmod (socket_path, 0666);
    if (rv < 0) err (4, "unix_server_socket.chmod of %s", socket_path);

    rv = listen (fd, 1);
    if (rv < 0) err (5, "unix_server_socket.listen for %s", socket_path);

    msgfd = accept (fd, NULL, NULL);
    if (msgfd < 0) err (5, "unix_server_socket.accept to %s", socket_path);

    rv = close (fd);
    if (rv < 0) err (6, "unix_server_socket.close for %s", socket_path);

    rv = unlink (socket_path);
    if (rv < 0) err (7, "unix_server_socket.unlink for %s", socket_path);

    if (msgfd >= 0 && rv >= 0){
        sock = (socket_t*)malloc(sizeof(socket_t));
        sock->type = UNIX;
        sock->socket = msgfd;
    }

    return sock;
}

socket_t*
raw_ethernet_socket(const char *interface_name)
{
    int fd = -1;
    int rv = -1;
    int sockopt;
    struct sockaddr_ll bindaddr;
    struct ifreq if_idx;
    socket_t *sock;

    // Create socket (note: need root or CAP_NET_RAW)
    fd = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
    {
        return 0;
    }

    // Make socket reusable
    sockopt = 1;
    rv = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof (sockopt));
    if (rv < 0)
    {
        return 0;
    }

    // Get interface index
    bzero (&if_idx, sizeof (if_idx));
    strncpy (if_idx.ifr_name, interface_name, IFNAMSIZ - 1);
    rv = ioctl (fd, SIOCGIFINDEX, &if_idx);
    if (rv < 0)
    {
        return 0;
    }

    // Bind socket to interface
    rv = setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&if_idx, sizeof(if_idx));
    if (rv < 0)
    {
        return 0;
    }

    // Bind to interfaces for sending
    bzero (&bindaddr, sizeof(bindaddr));
    bindaddr.sll_family   = AF_PACKET;
    bindaddr.sll_protocol = htons(ETH_P_ALL);
    bindaddr.sll_ifindex  = if_idx.ifr_ifindex;

    rv = bind (fd, (struct sockaddr *)&bindaddr, sizeof (bindaddr));
    if (rv < 0)
    {
        return 0;
    }
    sock = (socket_t*)malloc(sizeof(socket_t));
    sock->type = RAW;
    sock->socket = fd;
    return sock;
}

struct passwd *
get_user (const char *username)
{
    struct passwd *user;

    user = getpwnam (username);
    if (user == NULL)
    {
        warn ("getpwnam(%s)", username);
        return NULL;
    }

    return user;
}

int
get_uid (const char *username)
{
    struct passwd *user = get_user (username);
    return user->pw_uid;
}

int
get_gid (const char *username)
{
    struct passwd *user = get_user (username);
    return user->pw_gid;
}

int
send_control_message (socket_t *fd, uint32_t message_type)
{
    int rv = -1;
    message_t message;

    message.length = htonl (4);
    message.id     = message_type;

    rv = s_write (fd, &message, sizeof (message));
    if (rv < 0)
    {
        warn ("send_control_message.s_write message %u", message_type);
        return -1;
    }

    return 0;
}

int
socket_copy (int source_fd, int dest_fd, const char *local, const char *remote)
{
    ssize_t i;
    ssize_t bytes_written = -1;
    ssize_t bytes_read = -1;
    char buffer[RILPROXY_BUFFER_SIZE];
    char hexdump_buffer[3*sizeof(buffer)+1];

    bytes_read = read (source_fd, &buffer, sizeof (buffer));
    if (bytes_read < 0)
    {
        warn ("socket_copy: [%s -> %s] error reading source socket", local, remote);
        return -SOCKET_COPY_READ_ERROR;
    }

    if (bytes_read == 0)
    {
        warn ("socket_copy: [%s -> %s] reading socket closed", local, remote);
        return -SOCKET_COPY_READ_CLOSED;
    }

    bytes_written = write (dest_fd, &buffer, bytes_read);
    if (bytes_written < 0)
    {
        warn ("socket_copy: [%s -> %s] error writing destination socket", local, remote);
        return -SOCKET_COPY_WRITE_ERROR;
    }

    if (bytes_written < bytes_read)
    {
        warn ("socket_copy: [%s -> %s] read %zd bytes, wrote %zd bytes", local, remote, bytes_read, bytes_written);
        return 0;
    }

    warnx ("[%s -> %s]: read %zd, wrote %zd bytes", local, remote, bytes_read, bytes_written);

    // Prepare hexdump
    bzero (hexdump_buffer, sizeof (hexdump_buffer));
    for (i = 0; i < bytes_read; i++)
    {
        sprintf (hexdump_buffer + 3*i, "%02x ", 0xff & buffer[i]);
    }
    warnx ("[%s -> %s]: %s", local, remote, hexdump_buffer);

    return 0;
}

void
proxy (socket_t *local_fd, socket_t *remote_fd)
{
    int rv = -1;
    fd_set fds;

    for (;;)
    {
        FD_ZERO (&fds);
        FD_SET (local_fd->socket, &fds);
        FD_SET (remote_fd->socket, &fds);

        rv = select (MAX(local_fd->socket, remote_fd->socket) + 1, &fds, NULL, NULL, NULL);
        if (rv < 0)
        {
            warn ("select failed");
            continue;
        }

        if (FD_ISSET (local_fd->socket, &fds))
        {
            socket_copy (local_fd->socket, remote_fd->socket, "local", "remote");
        }

        if (FD_ISSET (remote_fd->socket, &fds))
        {
            socket_copy (remote_fd->socket, local_fd->socket, "remote", "local");
        }
    }
}

void
wait_control_message (socket_t *sock, uint32_t message_type)
{
    ssize_t msize;
    char buffer[1500];
    message_t *message;

    for (;;)
    {
        msize = s_read (sock, &buffer, sizeof (buffer));
        if (msize < 0)
        {
            err (1, "read");
        }

        message = (message_t *)&buffer;
        uint32_t len = ntohl (message->length);
        if (len == 4 && message->id == message_type)
        {
            return;
        }

        printf ("Got unknown message (len=%d, id=%x)\n", len, message->id);
    }
}

ssize_t
s_write(socket_t *sock, const void *buf, size_t count)
{
    switch(sock->type){
        case RAW: warn("Type RAW(%u) not implemented.", sock->type);
                  return 0;
        case UDP:
        case UNIX: return write(sock->socket, buf, count);
        default: warn("Unknown type: %u", sock->type);
                 return 0;
    }
}

ssize_t
s_read(socket_t *sock, void *buf, size_t count)
{
    switch(sock->type){
        case RAW: warn("Type RAW(%u) not implemented.", sock->type);
                  return 0;
        case UDP:
        case UNIX: return read(sock->socket, buf, count);
        default: warn("Unknown type: %u", sock->type);
                 return 0;
    }
}
