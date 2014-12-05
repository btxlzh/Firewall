#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include "sniffer_ioctl.h"

static char * program_name;
static char * dev_file = "sniffer.dev";
struct hostent *host;
struct in_addr **addr_list;
void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "parameters: \n"
                "    --mode [enable|disable]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

char* chdown(char * s)
{
    int l = strlen(s);
    for(int i = 0; i < l; i++){
        if(s[i]>=97&&s[i]<=122)
            s[i]-=32;
    }
    return s;
}

int sniffer_send_command(struct flow_entry *flow)
{
    int fd;
    fd=open(dev_file,O_WRONLY);
    if(fd<0){
        printf(" open file err %x\n",fd);
        return 0;
    }
    ioctl(fd,flow->mode,flow);
    return 0;
}
void flow_entry_init(struct flow_entry* e){
    e->src_ip=0;
    e->src_port=0;
    e->dst_ip=0;
    e->dst_port=0;
    e->mode= FLOW_ENABLE;
    e->proto=0;
}
int main(int argc, char **argv)
{
    int c;
    program_name = argv[0];
    struct flow_entry e;
    flow_entry_init(&e);
    while(1) {
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"p", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;
        switch (c) {
        case 0:
            printf("option %d %s", option_index, long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");

            switch(option_index) {
            case 0:     // mode
                if(strcmp(chdown(optarg),"enable")==0){
                    e.mode=SNIFFER_FLOW_ENABLE;
                }else 
                if(strcmp(chdown(optarg),"disable")==0){
                    e.mode=SNIFFER_FLOW_DISABLE;
                }
                break;
            case 1:     // src_ip
                if(strcmp(optarg,"any")==0){
                    e.src_ip=0;
                }else {
                    if((host=gethostbyname(optarg))<=0){
                        printf("err\n");
                        return 0;
                    }
                   
                    addr_list = (struct in_addr **)host->h_addr_list;
                    int i=0;

                    for(i = 0; addr_list[i] != NULL; i++) {
                       printf("add address %x \n",addr_list[i]->s_addr);
                        e.src_ip=(addr_list[i]->s_addr);
                        break;
                    }
                }
                break;                break;
            case 2:     // src_port
                if(strcmp(optarg,"any")==0){
                    e.src_port=0;
                }else 
                    e.src_port=atoi(optarg);
                break;
            case 3:     // dst_ip

                if(strcmp(optarg,"any")==0){
                    e.dst_ip=0;
                }else 
                {
                    if((host=gethostbyname(optarg))<=0){
                        printf("err\n");
                        return 0;
                    }
                   
                    addr_list = (struct in_addr **)host->h_addr_list;
                    int i=0;

                    for(i = 0; addr_list[i] != NULL; i++) {
                       printf("add address %x \n",addr_list[i]->s_addr);
                        e.dst_ip=(addr_list[i]->s_addr);
                        break;
                    }
                }
                break;
            case 4:     // dst_port
                if(strcmp(optarg,"any")==0){
                    e.dst_port=0;
                }else 
                    e.dst_port=atoi(optarg);
                break;
            case 5:     // action
                if(strcmp(optarg,"ICMP")==0)
                    e.proto=ICMP;
                else if(strcmp(optarg,"UDP")==0)
                    e.proto=UDP;
                else if(strcmp(optarg,"TCP")==0)
                    e.proto=TCP;
                break;
            case 6:     // dev
                dev_file=optarg;
                break;
            }
            break;
        default:
            usage();
        }
    }
    sniffer_send_command(&e);
    return 0;
}
