// Libc includes
#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

// Linux includes
#include <linux/if_ether.h>

// local includes
#include "rilproxy.h"

int
main (int argc, char **argv)
{
    int rv = -1;
    socket_t *remote = 0;
    socket_t *local = 0;
    char *interface_name, *local_path;

    if (argc < 3) errx (1, "Insufficient arguments (%s <local_socket_path> <interface_name>)", argv[0]);

    warnx ("Started");

    local_path = argv[1];
    interface_name = argv[2];

    // Open listening UDP socket
    warnx ("Setting up UDP socket");
    remote = raw_ethernet_socket (interface_name, ETH_P_RIL);
    if (remote == 0) errx (254, "Opening interface");

    // Wait for setup message
    warnx ("Waiting for control message");
    wait_control_message (remote, MESSAGE_SETUP_ID);

    // Drop privileges to 'radio'
    warnx ("Dropping privileges");

    rv = setgid (get_gid ("radio"));
    if (rv < 0)
    {
        send_control_message (remote, MESSAGE_TEARDOWN_ID);
        err (251, "setting group to 'radio'");
    }

    rv = setuid (get_uid ("radio"));
    if (rv < 0)
    {
        send_control_message (remote, MESSAGE_TEARDOWN_ID);
        err (253, "Dropping user to 'radio'");
    }

    // Open unix domain socket
    warnx ("Opening ril socket");
    local = unix_client_socket (local_path);
    if (local == 0)
    {
        send_control_message (remote, MESSAGE_TEARDOWN_ID);
        errx (252, "Opening local unix domain socket");
    }

    warnx ("Forwarding packets");
    proxy (local, remote);
    return 0;
}
