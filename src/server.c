// Libc includes
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// local includes
#include "rilproxy.h"

int
main (int argc, char **argv)
{
    socket_t *remote = 0;
    socket_t *local = 0;
    int rv = -1;
    char *interface_name, *local_path;

    if (argc < 3) errx (1, "Insufficient arguments (%s <local_socket_path> <interface_name>)", argv[0]);

    local_path = argv[1];
    interface_name = argv[2];

    printf ("Connecting %s on %s\n", local_path, interface_name);

    // Open UDP socket to client proxy
    remote = raw_ethernet_socket (interface_name, ETH_P_RIL);
    if (remote == 0) errx (254, "Opening remote socket");
    printf ("Server: UDP socket created.\n");

    // Create RILd socket
    local = unix_server_socket (local_path, "radio");
    if (local == 0) errx (253, "Opening local socket");
    printf ("Server: Unix domain socket created.\n");

    // Connected, send startup message
    rv = send_control_message (remote, MESSAGE_SETUP_ID);
    if (rv < 0) errx (252, "Sending control message");
    printf ("Server: Sent startup message.\n");

    proxy (local, remote);
    return 0;
}
