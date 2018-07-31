
#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "dhcp_func.h"
#include "dhcp_options.h"

void doargs(int argc, char **argv, DHCP_Client *dhcl)
{
    char ch;

    if (argc == 1)
    {
        printf("SYNAPSIS: %s -d devname -c ciaddr -g giaddr -r reqip -s server -l loglevel -v\n", argv[0]);
        exit(1);
    }
    while ((ch = getopt(argc, argv, "c:g:h:s:vl:d:r:")) > 0)
    {
        switch (ch)
        {
            case 'c':
                dhcl->set_ci(optarg);
                break;
            case 'g':
                dhcl->set_gi(optarg);
                break;
            case 'r':
                dhcl->set_ri(optarg);
                break;
            case 's':
                dhcl->set_serveraddr(optarg);
                break;
            case 'v':
                dhcl->set_log_level(LOG_VERBOSE);
                break;
            case 'l':
                dhcl->set_log_level(atoi(optarg));
                break;
            case 'd':
                dhcl->set_dev_name(optarg);
                break;
        }
    }

    if (!dhcl->dev_is_set())
    {
        fprintf(stdout, "Device is not set\n");
        exit(1);
    }
}

int main(int argc,char **argv)
{
    DHCP_Client dhcpcl;

    __uid_t uid = geteuid();

    if (uid != 0)
    {
        printf("This program should only be ran by root or be installed as setuid root.\n");
        exit(1);
    }

    doargs(argc, argv, &dhcpcl);

    if (setuid(getuid()) != 0)
    {
        perror("setuid");
        printf("Can't drop privileges back to normal user, program aborted.\n");
        exit(1);
    }

    dhcpcl.dhcp_setup();
    dhcpcl.dhcp_discover();
    dhcpcl.dhcp_offer();
    dhcpcl.dhcp_request();
    dhcpcl.dhcp_ack();
//  dhcpcl.dhcp_inform();
//  dhcpcl.dhcp_ack();
    dhcpcl.dhcp_close();


    return 0;
}




