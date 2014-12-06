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
#include <netinet/in.h>
#include <arpa/inet.h>

static char * program_name;
static char * dev_file = "sniffer.dev";
struct hostent *host;
struct in_addr **addr_list;
#define SRCIP 0
#define DSTIP 1

char* chdown(char * s)
{
    int l = strlen(s);
    int i;
    for(i = 0; i < l; i++){
        if(s[i]>=97&&s[i]<=122)
            s[i]-=32;
    }
    return s;
}


void parse_ip(struct flow_entry* e, char* ip, int type){
    int ip_i=0;
    int mark_i;
    struct in_addr addr;
    char * pch = strchr(ip,'/');
    if(pch == NULL){
        inet_aton(ip,&addr);
        if(type==SRCIP){
            e->src_ip = addr.s_addr; 
            e->src_ip_mark =32;
        }else{
            e->dst_ip = addr.s_addr;
            e->dst_ip_mark =32;
        }
    }else{
        *pch='\0';
        char * mark_s=pch+1;
        int mark = atoi(mark_s);
       // printf("%s:%d\n",ip,mark);
        inet_aton(ip,&addr);
        if(type==SRCIP){
            e->src_ip = addr.s_addr;
            e->src_ip_mark = mark;
        }else{
            e->dst_ip = addr.s_addr;
            e->dst_ip_mark = mark;
        }

    }


    return ;
}
void file_rule_process(char* rule){
    printf("rule : %s", rule);
    // make entry
    struct flow_entry e;
    flow_entry_init(&e);

    char * pch;
    char * arg;
    pch = strtok (rule," ");
    if(strcmp(chdown(pch),"enable")==0){
        e.mode=FLOW_ENABLE;
    }else 
        if(strcmp(chdown(pch),"disable")==0){
            e.mode=FLOW_DISABLE;
        }
    pch = strtok (NULL, " ");

    if(strcmp(chdown(pch),"tcp")==0){
        e.proto=TCP;
    }else if(strcmp(chdown(pch),"udp")==0){
        e.proto=UDP;
    }else if(strcmp(chdown(pch),"icmp")==0){
        e.proto=ICMP;
    }

    // ip port  start
    pch = strtok (NULL, " ");

    while (pch != NULL){
        //get arg
        arg = strtok (NULL, " ");
        //printf ("%s:%s\n",pch,arg);
        if(strcmp(arg,"any")!=0){

            if(strcmp(pch,"src_ip")==0){
                parse_ip(&e,arg,SRCIP);
            }else if(strcmp(pch,"dst_ip")==0){
                parse_ip(&e,arg,DSTIP);
            }else if(strcmp(pch,"src_port")==0){
                e.src_port=atoi(arg);
            }else if(strcmp(pch,"dst_port")==0){
                e.dst_port=atoi(arg);
            }
        }

        //next
        pch = strtok (NULL, " ");
    }

    sniffer_send_command(&e);
    return ;

}

void file_input(char* filename){
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen(filename, "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    while ((read = getline(&line, &len, fp)) != -1) {
        file_rule_process(line);
    }
    fclose(fp);
    if (line)
        free(line);
    exit(EXIT_SUCCESS);
}

void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
            "parameters: \n"
            "    --mode [enable|disable]\n"
            "    --src_ip [url|any] : default is any \n"
            "    --src_port [XXX|any] : default is any \n"
            "    --dst_ip [url|any] : default is any \n" 
            "    --dst_port [XXX|any] : default is any \n"
            "    --p [TCP|UDP|ICMP] : default is 0(TCP)\n"
            "    --i [filename] : input file", program_name);
    exit(EXIT_FAILURE);
}
int sniffer_send_command(struct flow_entry *flow)
{
    printf("mode:%d\n"
            "proto:%d\n"
            "src_ip:%d\n"
            "src_ip_mark:%d\n"
            "src_port:%d\n"
            "dst_ip:%d\n"
            "dst_ip_mark:%d\n"
            "dst_port:%d\n",flow->mode,flow->proto,flow->src_ip,flow->src_ip_mark,flow->src_port,flow->dst_ip,flow->dst_ip_mark,flow->dst_port);
    int shift = flow->src_ip_mark;
    uint32_t mark =((~0)<<(shift)) ;
    printf("%x,%x\n",mark,~mark);
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
    e->src_ip_mark=32;
    e->dst_ip=0;
    e->dst_port=0;
    e->dst_ip_mark=32;
    e->mode= FLOW_ENABLE;
    e->proto=TCP;
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
            {"i", required_argument, 0, 0},
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
                            e.mode=FLOW_ENABLE;
                        }else 
                            if(strcmp(chdown(optarg),"disable")==0){
                                e.mode=FLOW_DISABLE;
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
                    case 6:     // file input
                        file_input(optarg);
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
