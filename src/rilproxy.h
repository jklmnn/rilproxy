#ifndef __RILPROXY_H__
#define __RILPROXY_H__

enum
{
    RILPROXY_PORT = 18912,
    RILPROXY_BUFFER_SIZE = 3000
};

enum {
#ifndef ETH_P_ALL
    ETH_P_ALL = 0x0003,
#endif // !ETH_P_ALL
    ETH_P_RIL = 0x524c
};

static const uint8_t source_mac[6] = { 0x43, 0x4d, 0x50, 0x4e, 0x4c, 0x54 };
static const uint8_t destination_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

typedef struct {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
} __attribute__((packed)) ethernet_frame_t;

typedef union {
    ethernet_frame_t frame;
} packet_meta_data_t;

typedef enum {
    RAW,
    UDP,
    UNIX
} socket_type_t;

typedef struct {
    socket_type_t type;
    int socket;
    packet_meta_data_t meta;
} socket_t;

int socket_copy (int source_fd, int dest_fd, const char *local, const char *remote);

socket_t *udp_socket (const char *host, unsigned short port);
socket_t *unix_client_socket (const char *socket_path);
socket_t *unix_server_socket (const char *socket_path, const char *user);
socket_t *raw_ethernet_socket(const char *interface_name, uint16_t eth_type);
int get_uid (const char *username);
int get_gid (const char *username);
int send_control_message (socket_t* sock, uint32_t message_type);
void wait_control_message (socket_t* sock, uint32_t message_type);
void proxy (socket_t *local_fd, socket_t *remote_fd);

ssize_t s_write(socket_t *, const void*, size_t);
ssize_t s_read(socket_t *, void*, size_t);

typedef struct
{
    uint32_t length;
    uint32_t id;
} message_t;

enum { MESSAGE_SETUP_ID = 0xC715, MESSAGE_TEARDOWN_ID = 0xC717 };

enum
{
    SOCKET_COPY_READ_ERROR,
    SOCKET_COPY_READ_CLOSED,
    SOCKET_COPY_WRITE_ERROR,
    SOCKET_COPY_WRITE_CLOSED
};

#define MAX(a,b) (((a)>(b))?(a):(b))

#endif // __RILPROXY_H__
