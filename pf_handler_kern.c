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
// #include <linux/types.h>
// #include <bpf/bpf.h>
#include <uapi/linux/ptrace.h>  
#include <uapi/linux/bpf.h>  
#include <linux/sched.h>  
#include "bpf_helpers.h"
#include <linux/mm.h>


struct bpf_map_def SEC("maps") pf_num = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 100,
};

struct page_fault_ctx{
    u64 __pad;
    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
};



SEC("tracepoint/exceptions/page_fault_kernel")
int kprobe__do_page_fault(struct page_fault_ctx *ctx){
        int key=0;
        int err;
        int *value;
        struct vm_area_struct *vma=0x12345678;
        value=bpf_map_lookup_elem(&pf_num, &key);
        remap_pfn_range(vma,ctx->address,0,8,vma->vm_page_prot);
        if(value!=NULL){
            (*value)++;
            bpf_map_update_elem(&pf_num,&key,value, BPF_ANY);
        }else{
            err=1;
            bpf_map_update_elem(&pf_num,&key,&err, BPF_ANY);
        }
        
        return 0;

}
char _license[] SEC("license") = "GPL"; 


