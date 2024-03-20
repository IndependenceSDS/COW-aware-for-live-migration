// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_load.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#define PARSE_IP 3
#define PARSE_IP_PROG_FD (prog_fd[0])
#define PROG_ARRAY_FD (map_fd[0])

int main(int argc, char **argv)
{
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
        char filename[256];
        int i, err;
        struct bpf_prog_info info = {};
        uint32_t info_len = sizeof(info);
        const char * mountpath = "/sys/fs/bpf/try";
        int pinned = 0;
        int key=0;
        int value=0;


        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
        setrlimit(RLIMIT_MEMLOCK, &r);

        if (load_bpf_file(filename)) {
                printf("%s", bpf_log_buf);
                return 1;
        }


        // pinned = bpf_obj_pin(map_fd[2], mountpath);
        // if (pinned < 0) {
        //         printf("Failed to pin map to the file system: %d (%s)\n", pinned, strerror(errno));
        //         return -1;
        // }

        /* Test fd array lookup which returns the id of the bpf_prog */
        // err = bpf_obj_get_info_by_fd(PARSE_IP_PROG_FD, &info, &info_len);
        // assert(!err);
        // err = bpf_map_lookup_elem(PROG_ARRAY_FD, &key, &id);
        // assert(!err);
        // assert(id == info.id);

        sleep(10);

        bpf_map_lookup_elem(PROG_ARRAY_FD.fd,&key,&value);

        printf("pf_num: %d",value);

        return 0;
}