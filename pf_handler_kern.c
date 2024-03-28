// #include <uapi/linux/ptrace.h>
// #include <net/sock.h>
// #include <bcc/proto.h>
// //#define KBUILD_MODNAME "foo"
// #include <linux/ip.h>
// #include <linux/ipv6.h>
// #include <linux/tcp.h>
// #include <linux/skbuff.h>
// #include <linux/netfilter.h>
// #include <net/netfilter/nf_tables.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <uapi/linux/ptrace.h>  
#include <uapi/linux/bpf.h>  
#include <linux/sched.h>  
#include "bpf_helpers.h"


struct bpf_map_def SEC("maps") pf_num = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 100,
};



SEC("kprobe/do_page_fault")
int kprobe__do_page_fault(struct pt_regs *ctx){
        int key=0;
        int err,value=1;
        err=bpf_map_lookup_elem(&pf_num, &key,&value);
        if(err==0){
            value++;
            err=bpf_map_update_elem(&pf_num,&key,&value);
        }else{
            err=bpf_map_update_elem(&pf_num,&key,&value);
        }
        
        return 0;

}
char _license[] SEC("license") = "GPL"; 


