// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
// #include "bpf_load.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>


int main(int argc, char **argv)
{
        struct bpf_object *obj;
        int map_fd,prog_fd;
        char filename[256];
        int i, err;
        int key=0;
        int value=0;


        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

        if (bpf_prog_load(filename, BPF_PROG_TYPE_KPROBE,
                          &obj, &prog_fd)) {
                return 1;
        }
        map_fd = bpf_object__find_map_fd_by_name(obj, "pf_num");


        sleep(10);

        err=bpf_map_lookup_elem(map_fd,&key,&value);
        if(err==0)
        printf("pf_num: %d",value);

        return 0;
}