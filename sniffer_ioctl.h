#ifndef __SNIFFER_IOCTL_
#define __SNIFFER_IOCTL__

struct flow_entry {
    int mode;
    uint32_t src_ip;
    uint32_t src_ip_mark;
    int src_port;
    uint32_t dst_ip;
    uint32_t dst_ip_mark;
    int dst_port;
    int proto; //0 = tcp; 1 = udp; 2 = icmp;
};

/* IP header */
struct zl_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    uint32_t ip_src,ip_dst;  /* source and dest address */
    uint8_t opt_data[0]; 
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct zl_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)              (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS                (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
    uint8_t data[0];
};

#define _IOC_MAGIC       'p'
#define FLOW_ENABLE     _IOW(_IOC_MAGIC, 0x1, struct flow_entry)
#define FLOW_DISABLE    _IOW(_IOC_MAGIC, 0x2, struct flow_entry)

#define _IOC_MAXNR   0x3


#define TCP     IPPROTO_TCP
#define UDP     IPPROTO_UDP
#define ICMP    IPPROTO_ICMP
//functions
void flow_entry_init(struct flow_entry* );
int sniffer_send_command(struct flow_entry *);
//hashtable
#ifndef _HASHTABLE_H
#define _HASHTABLE_H

typedef struct ht_key* ht_key;
typedef struct ht_elem* ht_elem;
typedef struct hash_table* ht;
typedef struct ht_data* ht_data;
ht ht_new (int init_size);
void* ht_insert(ht H, ht_elem e);
void ht_free(ht H);
int ht_equal(ht_key k1,ht_key k2);
u_int ht_hash(ht_elem);

/* chains */
typedef struct chain* chain;
chain chain_new(void);
void* chain_insert(chain C, ht_elem e);
void chain_free(chain C);

#define  HASH_TABLE_SIZE 204800
#endif // hash table
#endif /* __SNIFFER_IOCTL__ */
