
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/list.h>
#include "sniffer_ioctl.h"
#include "asm/spinlock.h"
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/irqflags.h>
#include <linux/textsearch.h>

MODULE_AUTHOR("");
MODULE_DESCRIPTION("CS5434 Packet Filter / Firewall");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain = NF_INET_PRE_ROUTING;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;
struct nf_hook_ops nf_hook_out;
// skb buffer between kernel and user space
struct list_head skbs;

// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};

struct rule{
    int mode;
    uint32_t src_ip;
    uint32_t src_ip_mark;
    int src_port;
    uint32_t dst_ip;
    uint32_t dst_ip_mark;
    int dst_port;
    int proto;
    struct list_head list;
};

static struct rule rules;
struct rule *r_tmp,*r_t;
int r_lock ;
wait_queue_head_t r_que;
static const char signature[] ="got";
#define SIG_LENGTH (ARRAY_SIZE(signature) - 1)
struct ts_config *conf;
struct ts_state state;
static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}
/* From kernel to userspace */
    static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    if(atomic_read(&refcnt)>0) return -1;
    atomic_inc(&refcnt);
    struct skb_list* tmp;
    int cnt=-1;
    wait_event_interruptible(r_que,!list_empty(&skbs));
    if(list_empty(&skbs)) return -1; 
    local_irq_save(r_lock);
    tmp = list_entry(skbs.next, struct skb_list, list);
    cnt=tmp->skb->len;
    printk(KERN_DEBUG"get %d byte\n",cnt);
    copy_to_user(buf, tmp->skb->data, tmp->skb->len);

    list_del(skbs.next);
    local_irq_restore(r_lock);
    atomic_dec(&refcnt);
    //printk(KERN_DEBUG "Read buff %d\n",cnt);
    return cnt;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);

    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}
int cmp(struct rule * l1,struct flow_entry * l2){
    return (l1->src_ip==l2->src_ip) && (l1->src_port == l2->src_port) 
        && (l1->dst_ip==l2->dst_ip) && (l1->dst_port == l2->dst_port);
}
static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long err =0 ;
    struct flow_entry* entry=(struct flow_entry*) arg;
    if (_IOC_TYPE(cmd) != _IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > _IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;

    switch(cmd) {
        case FLOW_ENABLE:
        case FLOW_DISABLE:
            list_for_each_entry(r_t, &rules.list, list){
                if(cmp(r_t,entry)){
                    r_t->mode = entry->mode;
                    r_t->proto = entry->proto;
                    break;
                }
            };
            r_tmp= vmalloc(sizeof(struct rule));
            memcpy(r_tmp,entry,sizeof(struct flow_entry));
            local_irq_save(r_lock);
            list_add(&(r_tmp->list), &(rules.list));
            local_irq_restore(r_lock);
            break;
        default:
            printk(KERN_DEBUG "Unknown command\n");
            err = -EINVAL;
    }

    return err;
}
void ip_rev(unsigned char * ret,uint32_t x){
    ret[3] = x & 0xff;
    ret[2] = (x >> 8) & 0xff ;
    ret[1] = (x >> 16) & 0xff ;
    ret[0] = (x >> 24) & 0xff ;
}
static int sniffer_proc_read(struct seq_file *output, void *v){
    struct rule* tmp;
    unsigned char ret[4];
    int id=0;
    seq_printf(output,"[command] [src_ip]          [src_port]  [dst_ip]          [dst_port] [ID]\n");
    list_for_each_entry(tmp, &rules.list, list){
        if(tmp->mode==FLOW_ENABLE)
            seq_printf(output," enable");
        else 
            seq_printf(output," disable");


        if(tmp->src_ip==0)
            seq_printf(output,"   any               ");
        else {
            ip_rev(ret,tmp->src_ip);
            seq_printf(output,"   %3d.%3d.%3d.%3d/%d",ret[3],ret[2],ret[1],ret[0],tmp->src_ip_mark);    
        }


        if(tmp->src_port==0)
            seq_printf(output,"    any");
        else
            seq_printf(output,"  %5d",tmp->src_port);


        if(tmp->dst_ip==0)
            seq_printf(output,"     any               ");
        else {
            ip_rev(ret,tmp->dst_ip);
            seq_printf(output,"     %3d.%3d.%3d.%3d/%d",ret[3],ret[2],ret[1],ret[0],tmp->dst_ip_mark); 
        }


        if(tmp->dst_port==0)
            seq_printf(output,"    any    ");
        else
            seq_printf(output,"  %5d    ",tmp->dst_port);

        /*seq_printf(output," ");
          if(tmp->action==SNIFFER_ACTION_CAPTURE)
          seq_printf(output,"capture");
          else if(tmp->action==SNIFFER_ACTION_DPI) 
          seq_printf(output,"dpi");
          else if(tmp->action==SNIFFER_ACTION_NULL) 
          seq_printf(output,"none");            
          */
        seq_printf(output,"  %d\n",id++);
    }       
    return 0;

}
static int sniffer_proc_open(struct inode *inode, struct file *file ){
    return single_open(file, sniffer_proc_read, NULL);
}

static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};
static struct file_operations sniffer_proc = {
    .open = sniffer_proc_open,
    .release = single_release,
    .read = seq_read,
    .llseek = seq_lseek,
    .owner = THIS_MODULE,
};
int cnt=0;
void save_skb(struct sk_buff* skb){
    struct skb_list* skb_tmp=kmalloc(sizeof(struct skb_list),GFP_ATOMIC);
    skb_tmp->skb=skb_copy(skb,GFP_ATOMIC);
    list_add_tail(&(skb_tmp->list), &(skbs));

}
int rule_match(struct rule* r,struct iphdr *iph){
    struct tcphdr *tcph = ip_tcp_hdr(iph);
    uint32_t s_ip,d_ip;
    int s_port=0,d_port=0;
    int proto=iph->protocol;
    s_ip=iph->saddr;
    d_ip=iph->daddr;
    s_port=ntohs(tcph->source);
    d_port=ntohs(tcph->dest);
    int shift = r->src_ip_mark;
    uint32_t s_ip_mark = ~((~0)<<shift) ;
    shift = r->dst_ip_mark;
    uint32_t d_ip_mark = ~((~0)<<shift) ;
    return    ( (   ((s_ip&s_ip_mark) == (r_t->src_ip&s_ip_mark)) || (r_t->src_ip==0))
        &&      (   ((d_ip&d_ip_mark) == (r_t->dst_ip&d_ip_mark)) || (r_t->dst_ip==0)) 
        &&      (d_port==r_t->dst_port || r_t->dst_port==0 ) 
        &&      (s_port==r_t->src_port || r_t->src_port ==0)    );
    
}
static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{
    struct iphdr *iph = ip_hdr(skb);
    printk(KERN_DEBUG "Get packet  cnt:%d\n",cnt++);
    local_irq_save(r_lock);
    list_for_each_entry(r_t, &rules.list, list){
        if(rule_match(r_t,iph)){
            if (r_t->mode==FLOW_ENABLE){
                printk(KERN_DEBUG "Accepted TCP Pkt src:%x  dst: %x",iph->saddr, iph->daddr);
                wake_up_interruptible(&r_que);
                save_skb(skb);
                local_irq_restore(r_lock);
                return NF_ACCEPT;
            }
            else{
                printk(KERN_DEBUG "Rejected TCP Pkt src:%x  dst: %x",iph->saddr, iph->daddr);
                local_irq_restore(r_lock);
                return NF_DROP;
            }
        }  		
    }   
    local_irq_restore(r_lock);
    printk(KERN_DEBUG "Rejected TCP Pkt src:%x  dst: %x ",iph->saddr, iph->daddr);
    return NF_DROP;
    save_skb(skb);
    return NF_ACCEPT;
}

static int __init sniffer_init(void)
{
    int status = 0;
    printk(KERN_DEBUG "sniffer_init\n");

    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    proc_create("sniffer", 0, NULL, &sniffer_proc);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;

    }

    atomic_set(&refcnt, 0);
    INIT_LIST_HEAD(&skbs);
    conf = textsearch_prepare("kmp",signature, SIG_LENGTH,GFP_KERNEL,TS_AUTOLOAD); 
    /* register netfilter hook */
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    nf_hook_ops.hook = sniffer_nf_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = hook_chain;
    nf_hook_ops.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }
    memset(&nf_hook_out, 0, sizeof(nf_hook_out));
    nf_hook_out.hook = sniffer_nf_hook;
    nf_hook_out.pf = PF_INET;
    nf_hook_out.hooknum = NF_INET_LOCAL_OUT;
    nf_hook_out.priority = hook_prio;
    status = nf_register_hook(&nf_hook_out);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }
    // my init
    INIT_LIST_HEAD(&rules.list);
    DEFINE_SPINLOCK(r_lock);
    init_waitqueue_head(&r_que);
    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{
    textsearch_destroy(conf);
    if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }
    if (nf_hook_out.hook) {
        nf_unregister_hook(&nf_hook_out);
        memset(&nf_hook_out, 0, sizeof(nf_hook_out));
    }
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
    remove_proc_entry("sniffer",NULL);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
