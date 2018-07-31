
#ifndef DHCP_FUNC_H
#define DHCP_FUNC_H

#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <string>

#include "dhcp_options.h"

typedef enum {
    LOG_QUIET,
    LOG_DEBUG,
    LOG_INFO,
    LOG_VERBOSE,
} verbose_level_t;

#define COLOR_BLACK                         "\033[4;30m"
#define COLOR_RED                           "\033[4;31m"
#define COLOR_GREEN                         "\033[4;32m"
#define COLOR_YELLOW                        "\033[4;33m"
#define COLOR_BLUE                          "\033[4;34m"
#define COLOR_MAGENTA                       "\033[4;35m"
#define COLOR_CYAN                          "\033[4;36m"
#define COLOR_GRAY                          "\033[4;37m"
#define COLOR_NONE                          "\033[0m"



#define DHCP_SERVER_PORT                    67
#define DHCP_CLIENT_PORT                    68
#define SERVER_TIMEOUT_SEC                  5

#define DHCP_MAGIC_COOKIE                   0x63825363

#define BUF_SIZ                             (256 * 256)
#define ETH_MAC_ADDR_LEN                    6

#define DHCP_BOOTREQUEST                    1
#define DHCP_BOOTREPLY                      2

#define DHCP_CHADDR_LEN                     16
#define DHCP_SNAME_LEN                      64
#define DHCP_FILE_LEN                       128

#define DHCP_HARDWARE_TYPE_10_EHTHERNET     1

#define MESSAGE_TYPE_PAD                    0
#define MESSAGE_TYPE_REQ_SUBNET_MASK        1
#define MESSAGE_TIME_OFFSET                 2
#define MESSAGE_TYPE_ROUTER                 3
#define MESSAGE_TYPE_DNS                    6
#define MESSAGE_TYPE_HOST_NAME              12
#define MESSAGE_TYPE_DOMAIN_NAME            15
#define MESSAGE_TYPE_INTERFACE_MTU          26
#define MESSAGE_TYPE_BROADCAST_ADDR         28
#define MESSAGE_TYPE_NET_TIME_PROTO_SERV    42
#define MESSAGE_TYPE_NETBIOS_OVER_TCP_NAME  44
#define MESSAGE_TYPE_NETBIOS_OVER_TCP_SCOPE 47
#define MESSAGE_TYPE_REQ_IP                 50
#define MESSAGE_TYPE_DHCP                   53
#define MESSAGE_TYPE_PARAMETER_REQ_LIST     55
#define MESSAGE_TYPE_DOMAIN_SEARCH          119
#define MESSAGE_TYPE_CLASSLESS_STATIC_ROUTE 121

#define MESSAGE_TYPE_END                    255

#define MAX_PACKET_SIZE                     576
#define OPTIONS_OFFSET                      240
#define OPTIONS_MAX_SIZE                    336 // without magic

#define DHCP_OPTION_DISCOVER                1
#define DHCP_OPTION_OFFER                   2
#define DHCP_OPTION_REQUEST                 3
#define DHCP_OPTION_DHCPDECLINE             4
#define DHCP_OPTION_ACK                     5
#define DHCP_OPTION_NACK                    6
#define DHCP_OPTION_RELEASE                 7
#define DHCP_OPTION_INFORM                  8

#define DHCP_BROADCAST_FLAG                 32768

typedef struct dhcp
{
    uint8_t     opcode;                     // 0
    uint8_t     htype;                      // 1
    uint8_t     hlen;                       // 2
    uint8_t     hops;                       // 3
    uint32_t    xid;                        // 4
    uint16_t    secs;                       // 8
    uint16_t    flags;                      // 10
    uint32_t    ciaddr;                     // 12
    uint32_t    yiaddr;                     // 16
    uint32_t    siaddr;                     // 20
    uint32_t    giaddr;                     // 24
    uint8_t     chaddr[DHCP_CHADDR_LEN];    // 28
    char        sname[DHCP_SNAME_LEN];      // 44
    char        p_file[DHCP_FILE_LEN];      // 108
    uint32_t    magic_cookie;               // 236
    uint8_t     p_options[OPTIONS_MAX_SIZE];// 240
} dhcp_t;

class DHCP_Client
{
public:
    DHCP_Client();
    virtual ~DHCP_Client();

    int fill_dhcp_option(uint8_t *packet, uint8_t code,
                     uint8_t *data, uint8_t len);

    int dhcp_setup();
    int dhcp_discover();
    int dhcp_offer();
    int dhcp_request();
    int dhcp_ack();
    int dhcp_release();
    int dhcp_inform();

    void set_dev_name(std::string device)
    {
        _dev_name = device;
    }

    int dev_is_set()
    {
        return _dev_name.length();
    }

    int get_dhcp_sock()
    {
        return _dhcp_socket;
    }

    void set_ci(char *ci)
    {
        _ci = ci;
    }

    void set_gi(char *gi)
    {
        _gi = gi;
    }

    void set_ri(char *ri)
    {
        fprintf(stdout, "ri: %s\n", ri);
        _ri = ri;
    }

    void set_hw(char *hw)
    {
        _hw = std::string(hw);
    }

    void set_serveraddr(std::string serveraddr)
    {
        _server_addr = serveraddr;
    }

    void set_log_level(int lv)
    {
        _log_level = lv;
    }

    void dhcp_close();
    void dhcp_dump(unsigned char *buffer, int size);
    void printip(unsigned char * buffer, const char *desc = "");

private:
    std::string         _dev_name;
    int                 _dhcp_socket;
    struct sockaddr_in  _dhcp_client;   // offer
    struct sockaddr_in  _dhcp_server;   // discovery
    int                 _serveripaddress;
    int                 _log_level;
    uint32_t            _client_ip;
    uint32_t            _gateway_ip;
    std::string         _ci;        // client ip
    std::string         _gi;        // Gateway IP address
    std::string         _ri;        // Requested IP
    std::string         _server_addr;
    std::string         _hw;    // hw address
    unsigned char       _serveridentifier[4];
    uint8_t _mac[ETH_MAC_ADDR_LEN];
};

#endif // DHCP_FUNC_H
