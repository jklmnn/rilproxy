#include <err.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#include "rilproxy.h"

int
bridge_copy (int source_fd, int dest_fd, const char *local, const char *remote)
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
bridge (socket_t *local_fd, socket_t *remote_fd)
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
            bridge_copy (local_fd->socket, remote_fd->socket, "local", "remote");
        }

        if (FD_ISSET (remote_fd->socket, &fds))
        {
            bridge_copy (remote_fd->socket, local_fd->socket, "remote", "local");
        }
    }
}

int
main(int argc, char **argv)
{
    socket_t *left_fd = 0;
    socket_t *right_fd = 0;

    // Check number of arguments
    if (argc != 3)
    {
        errx (1, "Insufficient arguments");
    }

    left_fd = raw_ethernet_socket (argv[1], ETH_P_ALL, 0x0);
    if (left_fd == 0)
    {
        err (4, "Left: create_socket(%s)", argv[1]);
    }

    right_fd = raw_ethernet_socket (argv[2], ETH_P_ALL, 0x0);
    if (right_fd == 0)
    {
        err (4, "Right: create_socket(%s)", argv[2]);
    }

    bridge (left_fd, right_fd);
}
