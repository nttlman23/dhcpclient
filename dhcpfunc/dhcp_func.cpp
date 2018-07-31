
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <dhcp_func.h>

void hexDump(const char *desc, void *addr, int len, int offset)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    if (desc != NULL)
    {
        printf ("%s:\n", desc);
    }

    fprintf(stdout, "\e[4m         | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\e[0m\n");

    for (i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
            {
                fprintf(stdout, "  %s\n", buff);
            }
            fprintf(stdout, "%08x |", i + (offset * 0x200));
        }
        fprintf(stdout, " %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
        {
            buff[i % 16] = '.';
        }
        else
        {
            buff[i % 16] = pc[i];
        }

        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0)
    {
        fprintf(stdout, "   ");
        i++;
    }
    fprintf(stdout, "  %s\n", buff);
}

DHCP_Client::DHCP_Client()
    :_dev_name(""),
      _dhcp_socket(-1),
      _serveripaddress(0),
      _log_level(LOG_QUIET),
      _client_ip(0),
      _gateway_ip(0),
      _ci("0.0.0.0"),
      _gi("0.0.0.0"),
      _ri("0.0.0.0"),
      _server_addr("255.255.255.255"),
      _hw("00:00:00:00:00:00")
{
}

DHCP_Client::~DHCP_Client()
{
    dhcp_close();
}

int DHCP_Client::fill_dhcp_option(uint8_t *packet, uint8_t code,
                                  uint8_t *data, uint8_t len)
{
    packet[0] = code;
    packet[1] = len;
    memcpy(&packet[2], data, len);

    return len + (sizeof(uint8_t) * 2);
}

int DHCP_Client::dhcp_discover()
{
    fprintf(stdout, COLOR_YELLOW "\nDISCOVER------------->\n" COLOR_NONE);

    struct sockaddr_in sockaddr_broadcast;
    dhcp_t dhcp;
    uint8_t option;
    int offset = 0;
    uint32_t req_ip;
    int packet_size = sizeof(dhcp_t);
    struct sockaddr_in sa;
    uint8_t parameter_req_list[] = {MESSAGE_TYPE_REQ_SUBNET_MASK,
                                    MESSAGE_TYPE_BROADCAST_ADDR,
                                    MESSAGE_TIME_OFFSET,
                                    MESSAGE_TYPE_ROUTER,
                                    MESSAGE_TYPE_DOMAIN_NAME,
                                    MESSAGE_TYPE_DNS,
                                    MESSAGE_TYPE_DOMAIN_SEARCH,
                                    MESSAGE_TYPE_HOST_NAME,
                                    MESSAGE_TYPE_NETBIOS_OVER_TCP_NAME,
                                    MESSAGE_TYPE_NETBIOS_OVER_TCP_SCOPE,
                                    MESSAGE_TYPE_INTERFACE_MTU,
                                    MESSAGE_TYPE_CLASSLESS_STATIC_ROUTE,
                                    MESSAGE_TYPE_NET_TIME_PROTO_SERV};

    memset(&dhcp, 0, sizeof(dhcp_t));

    dhcp.opcode = DHCP_BOOTREQUEST;
    dhcp.htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp.hlen = ETH_MAC_ADDR_LEN;
    memcpy(dhcp.chaddr, _mac, ETH_MAC_ADDR_LEN);
    srand(time(NULL));
    dhcp.xid = rand();
    dhcp.secs = 0x00;
    dhcp.flags = htons(DHCP_BROADCAST_FLAG);

    memset(&sa, 0, sizeof(sa));
    inet_pton(AF_INET, _ci.c_str(), &(sa.sin_addr));
    dhcp.ciaddr = sa.sin_addr.s_addr;

    memset(&sa, 0, sizeof(sa));
    inet_pton(AF_INET, _gi.c_str(), &(sa.sin_addr));
    dhcp.giaddr = sa.sin_addr.s_addr;

    dhcp.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    option = DHCP_OPTION_DISCOVER;
    offset += fill_dhcp_option(dhcp.p_options + offset, MESSAGE_TYPE_DHCP,
                               &option, sizeof(option));

    if (_ri.compare("0.0.0.0"))
    {
        memset(&sa, 0, sizeof(sa));
        inet_pton(AF_INET, _ri.c_str(), &(sa.sin_addr));
        req_ip = sa.sin_addr.s_addr;

        offset += fill_dhcp_option(dhcp.p_options + offset, MESSAGE_TYPE_REQ_IP,
                                (u_int8_t *)&req_ip, sizeof(req_ip));
    }

    offset += fill_dhcp_option(dhcp.p_options + offset,
                            MESSAGE_TYPE_PARAMETER_REQ_LIST,
                            (u_int8_t *)&parameter_req_list,
                            sizeof(parameter_req_list));

    dhcp.p_options[offset++] = MESSAGE_TYPE_END;

    packet_size -= (OPTIONS_MAX_SIZE - offset);

    dhcp_dump((unsigned char *)&dhcp, packet_size);

    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    memset(&sockaddr_broadcast.sin_zero, 0, sizeof(sockaddr_broadcast.sin_zero));

    char address[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &sockaddr_broadcast.sin_addr, address, INET_ADDRSTRLEN);

    fprintf(stdout, "DHCPDISCOVER to %s port %d\n", address,
           ntohs(sockaddr_broadcast.sin_port));

    sendto(_dhcp_socket, (char *)&dhcp, packet_size, 0,
           (struct sockaddr *)&sockaddr_broadcast, sizeof(sockaddr_broadcast));

    return 0;
}

int DHCP_Client::dhcp_offer()
{
    fprintf(stdout, COLOR_GREEN "\nOFFER<-------------\n" COLOR_NONE);

    fd_set read;
    struct timeval timeout;
    struct sockaddr_in source;
    dhcp_t dhcp_pack;
    socklen_t address_size;
    int res;

    FD_ZERO(&read);
    FD_SET(_dhcp_socket, &read);

    timeout.tv_sec = SERVER_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if(select(_dhcp_socket + 1, &read, NULL, NULL, &timeout) < 0)
    {
        perror("select");
        return -1;
    }
    if (FD_ISSET(_dhcp_socket, &read))
    {
        fprintf(stdout, "Data is available\n");
    }
    else
    {
        fprintf(stderr, "Server Timeout\n");
        return -1;
    }

    memset((void *)&dhcp_pack, 0, sizeof(dhcp_t));
    memset((void *)&source, 0, sizeof(source));

    address_size = sizeof(source);

    res = recvfrom(_dhcp_socket, &dhcp_pack, sizeof(dhcp_t), 0,
                 (struct sockaddr *)&source, &address_size);

//    fprintf(stdout, "dhcp source: %s\n", inet_ntoa(source.sin_addr));

    _client_ip = ntohl(dhcp_pack.yiaddr);
    _serveripaddress = ntohl(dhcp_pack.siaddr);

    dhcp_dump((unsigned char *)&dhcp_pack, res);

    fprintf(stdout,  "DHCP location: %d.%d.%d.%d\n",
            (_serveripaddress >> 24) & 0xFF,
            (_serveripaddress >> 16) & 0xFF,
            (_serveripaddress >>  8) & 0xFF,
            (_serveripaddress      ) & 0xFF);

    fprintf(stdout,  "New client IP: %d.%d.%d.%d\n",
            (_client_ip >> 24) & 0xFF,
            (_client_ip >> 16) & 0xFF,
            (_client_ip >>  8) & 0xFF,
            (_client_ip      ) & 0xFF);

    return 0;
}

int DHCP_Client::dhcp_setup()
{
    struct sockaddr_in name;
    int flag = 1;
    int res;

    struct ifreq interface;

    memset(&name, 0, sizeof(name));

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (fd < 0)
    {
        fprintf(stdout, "Error: Could not create HW socket!\n");
        return -1;
    }

    strncpy(interface.ifr_ifrn.ifrn_name, _dev_name.c_str(), IFNAMSIZ);

    res = ioctl(fd, SIOCGIFHWADDR, &interface);
    close(fd);

    if (res != 0)
    {
        perror("ioctl");
        return -1;
    }

    memset(_mac, 0, ETH_MAC_ADDR_LEN);
    memcpy((void *)_mac, interface.ifr_addr.sa_data, 6);

    _dhcp_client.sin_family = AF_INET;
    _dhcp_client.sin_addr.s_addr = INADDR_ANY;
    _dhcp_client.sin_port = htons(DHCP_CLIENT_PORT);
    memset(&_dhcp_client.sin_zero, 0, sizeof(_dhcp_client.sin_zero));

    _serveripaddress = ntohl(_dhcp_client.sin_addr.s_addr);

    if ((_dhcp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        perror("dhcp_socket/socket");
        return -1;
    }

    if(setsockopt(_dhcp_socket, SOL_SOCKET, SO_BINDTODEVICE,
                  (char *)&interface, sizeof(interface)) < 0)
    {
        fprintf(stdout, "Error: Could not bind socket to interface %s.  Check your privileges...\n", _dev_name.c_str());
        return -1;
    }

    flag = 1;
    if (setsockopt(_dhcp_socket, SOL_SOCKET, SO_REUSEADDR,
                    (char *)&flag, sizeof flag) < 0)
    {
        perror("dhcp_socket/setsockopt: SO_REUSEADDR");
        return -1;
    }

    if (setsockopt(_dhcp_socket, SOL_SOCKET, SO_BROADCAST, (char *)&flag,
        sizeof flag) < 0)
    {
        perror ("dhcp_socket/setsockopt: SO_BROADCAST");
        return -1;
    }

    if(bind(_dhcp_socket, (struct sockaddr *)&_dhcp_client,
            sizeof(_dhcp_client)) < 0)
    {
        fprintf(stdout, "Error: Could not bind to DHCP socket (port %d)!  Check your privileges...\n", DHCP_CLIENT_PORT);
        close(_dhcp_socket);
        return -1;
    }

    return 0;
}

int DHCP_Client::dhcp_request()
{
    fprintf(stdout, COLOR_YELLOW "\nREQUEST------------->\n" COLOR_NONE);

    dhcp_t dhcp;
    struct sockaddr_in sockaddr_broadcast;
    uint8_t option;
    int offset = 0;
    uint32_t req_ip;
    int packet_size = sizeof(dhcp_t);
    uint8_t parameter_req_list[] = {MESSAGE_TYPE_REQ_SUBNET_MASK,
                                    MESSAGE_TYPE_BROADCAST_ADDR,
                                    MESSAGE_TIME_OFFSET,
                                    MESSAGE_TYPE_ROUTER,
                                    MESSAGE_TYPE_DOMAIN_NAME,
                                    MESSAGE_TYPE_DNS,
                                    MESSAGE_TYPE_DOMAIN_SEARCH,
                                    MESSAGE_TYPE_HOST_NAME,
                                    MESSAGE_TYPE_NETBIOS_OVER_TCP_NAME,
                                    MESSAGE_TYPE_NETBIOS_OVER_TCP_SCOPE,
                                    MESSAGE_TYPE_INTERFACE_MTU,
                                    MESSAGE_TYPE_CLASSLESS_STATIC_ROUTE,
                                    MESSAGE_TYPE_NET_TIME_PROTO_SERV};

    memset(&dhcp, 0, sizeof(dhcp));

    dhcp.opcode = DHCP_BOOTREQUEST;
    dhcp.htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp.hlen = ETH_MAC_ADDR_LEN;
    memcpy(dhcp.chaddr, _mac, ETH_MAC_ADDR_LEN);
    srand(time(NULL));
    dhcp.xid = rand();
    dhcp.secs = 0x00;
    dhcp.flags = htons(DHCP_BROADCAST_FLAG);
    dhcp.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    // options
    option = DHCP_OPTION_REQUEST;
    offset += fill_dhcp_option(dhcp.p_options + offset, MESSAGE_TYPE_DHCP,
                               &option, sizeof(option));

    req_ip = htonl(_client_ip);
    offset += fill_dhcp_option(dhcp.p_options + offset, MESSAGE_TYPE_REQ_IP,
                            (u_int8_t *)&req_ip, sizeof(req_ip));

    offset += fill_dhcp_option(dhcp.p_options + offset,
                               MESSAGE_TYPE_PARAMETER_REQ_LIST,
                               (u_int8_t *)&parameter_req_list,
                               sizeof(parameter_req_list));

    dhcp.p_options[offset++] = MESSAGE_TYPE_END;

    packet_size -= (OPTIONS_MAX_SIZE - offset);

    dhcp_dump((unsigned char *)&dhcp, packet_size);

    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    memset(&sockaddr_broadcast.sin_zero, 0, sizeof(sockaddr_broadcast.sin_zero));

    char address[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &sockaddr_broadcast.sin_addr, address, INET_ADDRSTRLEN);

    fprintf(stdout, "DHCPREQUEST to %s port %d\n", address,
           ntohs(sockaddr_broadcast.sin_port));

    sendto(_dhcp_socket, (char *)&dhcp, packet_size, 0,
           (struct sockaddr *)&sockaddr_broadcast, sizeof(sockaddr_broadcast));

    return 0;
}

int DHCP_Client::dhcp_ack()
{
    fprintf(stdout, COLOR_GREEN "\nACK<-------------\n" COLOR_NONE);

    fd_set read;
    struct timeval timeout;
    struct sockaddr_in source;
    dhcp_t dhcp_pack;
    socklen_t address_size;
    int res;

    FD_ZERO(&read);
    FD_SET(_dhcp_socket, &read);

    timeout.tv_sec = SERVER_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if(select(_dhcp_socket + 1, &read, NULL, NULL, &timeout) < 0)
    {
        perror("select");
        return -1;
    }
    if (FD_ISSET(_dhcp_socket, &read))
    {
        fprintf(stdout, "Data is available\n");
    }
    else
    {
        fprintf(stderr, "Server Timeout\n");
        return -1;
    }

    memset((void *)&dhcp_pack, 0, sizeof(dhcp_t));
    memset((void *)&source, 0, sizeof(source));

    address_size = sizeof(source);

    res = recvfrom(_dhcp_socket, &dhcp_pack, sizeof(dhcp_t), 0,
                 (struct sockaddr *)&source, &address_size);

    fprintf(stdout, "dhcp source: %s\n", inet_ntoa(source.sin_addr));

    _client_ip = ntohl(dhcp_pack.yiaddr);
    _serveripaddress = ntohl(dhcp_pack.siaddr);

    dhcp_dump((unsigned char *)&dhcp_pack, res);

    if (_log_level)
    {
        fprintf(stdout,  "DHCP location: %d.%d.%d.%d\n",
                (_serveripaddress >> 24) & 0xFF,
                (_serveripaddress >> 16) & 0xFF,
                (_serveripaddress >>  8) & 0xFF,
                (_serveripaddress      ) & 0xFF);
        fprintf(stdout,  "New client IP: %d.%d.%d.%d\n",
                (_client_ip >> 24) & 0xFF,
                (_client_ip >> 16) & 0xFF,
                (_client_ip >>  8) & 0xFF,
                (_client_ip      ) & 0xFF);
    }

    return 0;
}

int DHCP_Client::dhcp_release()
{
    return 0;
}

int DHCP_Client::dhcp_inform()
{
    fprintf(stdout, COLOR_YELLOW "\nINFORM------------->\n" COLOR_NONE);

    dhcp_t dhcp;
    struct sockaddr_in sockaddr_broadcast;
    uint8_t option;
    int offset = 0;
    int packet_size = sizeof(dhcp_t);
    uint8_t parameter_req_list[] = {MESSAGE_TYPE_REQ_SUBNET_MASK,
                                    MESSAGE_TYPE_BROADCAST_ADDR,
                                    MESSAGE_TIME_OFFSET,
                                    MESSAGE_TYPE_ROUTER,
                                    MESSAGE_TYPE_DOMAIN_NAME,
                                    MESSAGE_TYPE_DNS,
                                    MESSAGE_TYPE_DOMAIN_SEARCH,
                                    MESSAGE_TYPE_HOST_NAME,
                                    MESSAGE_TYPE_NETBIOS_OVER_TCP_NAME,
                                    MESSAGE_TYPE_NETBIOS_OVER_TCP_SCOPE,
                                    MESSAGE_TYPE_INTERFACE_MTU,
                                    MESSAGE_TYPE_CLASSLESS_STATIC_ROUTE,
                                    MESSAGE_TYPE_NET_TIME_PROTO_SERV};

    memset(&dhcp, 0, sizeof(dhcp));

    dhcp.opcode = DHCP_BOOTREQUEST;
    dhcp.htype = DHCP_HARDWARE_TYPE_10_EHTHERNET;
    dhcp.hlen = ETH_MAC_ADDR_LEN;
    memcpy(dhcp.chaddr, _mac, ETH_MAC_ADDR_LEN);
    srand(time(NULL));
    dhcp.xid = rand();
    dhcp.secs = 0x00;
    dhcp.flags = htons(DHCP_BROADCAST_FLAG);
    dhcp.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    // options
    option = DHCP_OPTION_INFORM;
    offset += fill_dhcp_option(dhcp.p_options + offset, MESSAGE_TYPE_DHCP,
                               &option, sizeof(option));

//    req_ip = htonl(_client_ip);
//    offset += fill_dhcp_option(dhcp.p_options + offset, MESSAGE_TYPE_REQ_IP,
//                            (u_int8_t *)&req_ip, sizeof(req_ip));

    offset += fill_dhcp_option(dhcp.p_options + offset,
                               MESSAGE_TYPE_PARAMETER_REQ_LIST,
                               (u_int8_t *)&parameter_req_list,
                               sizeof(parameter_req_list));

    dhcp.p_options[offset++] = MESSAGE_TYPE_END;

    packet_size -= (OPTIONS_MAX_SIZE - offset);

    dhcp_dump((unsigned char *)&dhcp, packet_size);

    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    memset(&sockaddr_broadcast.sin_zero, 0, sizeof(sockaddr_broadcast.sin_zero));

    char address[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &sockaddr_broadcast.sin_addr, address, INET_ADDRSTRLEN);

    fprintf(stdout, "DHCPREQUEST to %s port %d\n", address,
           ntohs(sockaddr_broadcast.sin_port));

    sendto(_dhcp_socket, (char *)&dhcp, packet_size, 0,
           (struct sockaddr *)&sockaddr_broadcast, sizeof(sockaddr_broadcast));

    return 0;
}

void DHCP_Client::printip(unsigned char * buffer, const char *desc)
{
    fprintf(stdout, "%s %d.%d.%d.%d", desc,
            buffer[0], buffer[1], buffer[2], buffer[3]);
}

void DHCP_Client::dhcp_dump(unsigned char *buffer, int size)
{
    if (_log_level != LOG_VERBOSE)
    {
        return;
    }

    int j;
    uint32_t tmp_val;

    fprintf(stdout, "Packet %d bytes\n", size);
    hexDump("Packet", buffer, size, 0);

    if (size < 0)
    {
        fprintf(stdout, "Invalid size '%i'\n", size);
        return;
    }

    if (_log_level > 2)
    {
        fprintf(stdout, "opcode:\t%d (%s)\n", buffer[0], dhcp_op_code[buffer[0]]);
        fprintf(stdout, "htype:\t%d\n", buffer[1]);
        fprintf(stdout, "hlen:\t%d\n", buffer[2]);
        fprintf(stdout, "hops:\t%d\n", buffer[3]);

        fprintf(stdout, "xid:\t%02x%02x%02x%02x\n",
               buffer[4], buffer[5], buffer[6], buffer[7]);
        fprintf(stdout, "secs:\t%d\n", 255 * buffer[8] + buffer[9]);
        fprintf(stdout, "flags:\t%x\n", 255 * buffer[10] + buffer[11]);

        fprintf(stdout, "ciaddr:\t%d.%d.%d.%d\n",
               buffer[12], buffer[13], buffer[14], buffer[15]);
        fprintf(stdout, "yiaddr:\t%d.%d.%d.%d\n",
               buffer[16], buffer[17], buffer[18], buffer[19]);
        fprintf(stdout, "siaddr:\t%d.%d.%d.%d\n",
               buffer[20], buffer[21], buffer[22], buffer[23]);
        fprintf(stdout, "giaddr:\t%d.%d.%d.%d\n",
               buffer[24], buffer[25], buffer[26], buffer[27]);
        fprintf(stdout, "chaddr:\t%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
               buffer[28], buffer[29], buffer[30], buffer[31],
               buffer[32], buffer[33], buffer[34], buffer[35],
               buffer[36], buffer[37], buffer[38], buffer[39],
               buffer[40], buffer[41], buffer[42], buffer[43]);
        fprintf(stdout, "bp_sname:\t%s\n", buffer + 44);
        fprintf(stdout, "bp_file:\t%s\n", buffer + 108);
    }

    fprintf(stdout, "magic_cookie:\t%d.%d.%d.%d\n", buffer[236], buffer[237],
            buffer[238], buffer[239]);

    j = 240; // options
    fprintf(stdout, "Options\n\e[4mcode |          description          |    value\e[0m\n");
    while (j < size && buffer[j] != sizeof(dhcp_t))
    {
        fprintf(stdout, "%4d | %-29s |", buffer[j], dhcp_options[buffer[j]]);

        switch (buffer[j])
        {
            case 0:
                j = size;
                // end
                break;
            case 54:
            case 1:
            case 3:
            case 4:
            case 6:
            case 28:
            case 42:
            case 44:
            case 50:
            case 252:
                printip(&buffer[j + 2]);
                break;
            case 51:
                tmp_val = 0;
                memcpy(&tmp_val, &buffer[j + 2], sizeof(uint32_t));
                tmp_val = ntohl(tmp_val);
                fprintf(stdout, " %d min ( %d sec )",
                        tmp_val / 60, tmp_val);
                break;
            case 53:
                fprintf(stdout, " %d (%s)", buffer[j + 2],
                        dhcp_message_types[buffer[j + 2]]);
                break;
            case 55:
                fprintf(stdout, "\n");
                fprintf(stdout, "\t\e[4mcode | description\e[0m\n");
                for (int i = j + 2; i < j + buffer[j + 1] + 2;i++)
                {
                    fprintf(stdout, "\t%3d  | %s \n", buffer[i],
                           dhcp_options[buffer[i]]);
                }
                break;
            case 56:
                fprintf(stdout, " %.*s", 0xff & buffer[j + 1], &buffer[j + 2]);
                break;
            case 61:
                fprintf(stdout, "%02x%02x%02x%02x%02x%02x",
                       buffer[j + 2], buffer[j + 3], buffer[j + 4],
                       buffer[j + 5], buffer[j + 6], buffer[j + 7]);
                break;
            case 15:
                // cut next field
                fprintf(stdout, " %.*s", 0xff & buffer[j + 1], &buffer[j + 2]);
                break;
        }
        fprintf(stdout, "\n");

        /*
         *   // This might go wrong if a mallformed packet is received.
         *   // Maybe from a bogus server which is instructed to reply
         *   // with invalid data and thus causing an exploit.
         *   // My head hurts... but I think it's solved by the checking
         *   // for j<size at the begin of the while-loop.
         */
        j += buffer[j + 1] + 2;
    }
}


void DHCP_Client::dhcp_close()
{
    if (_dhcp_socket > 0)
    {
        close(_dhcp_socket);
    }
}

