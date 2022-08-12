#include "mac.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 참고 mac: (https://url.kr/wt71i2)
// 참고 ip: (https://kldp.org/node/4039)

bool get_my_mac(char* macaddr,const char *if_name)
{
    struct ifreq ifr;
    unsigned char* mac = NULL;
    int socketd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketd < 0)
    {
        perror("socket");
        return false;
    }
    strcpy(ifr.ifr_name, if_name);
    if(ioctl(socketd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        return false;
    }
    mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(macaddr,"%02x:%02x:%02x:%02x:%02x:%02x",
		    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return true;
};

bool get_my_ip(char* ip, const char *if_name)
{
    struct ifreq ifr;
	int socketd = socket(AF_INET, SOCK_DGRAM, 0);
    if(socketd < 0)
    {
        perror("socker");
        return false;
    }
        
	strcpy(ifr.ifr_name, if_name);

	if (ioctl(socketd, SIOCGIFADDR, &ifr) < 0) 
    {
        perror("ioctl");
		return false;
	}
    sprintf(ip,"%s",inet_ntop(AF_INET, 
        ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr)));
	return true;
}
