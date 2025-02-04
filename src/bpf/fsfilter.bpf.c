#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
        __uint(type,BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct data_t {
	int fd;
	int dfd;
	char filename[256];
	struct open_how how;
};

SEC("fexit/do_sys_openat2")
int BPF_PROG(do_sys_openat2, int dfd, const char *filename,
             struct open_how *how, int fd)
{
        struct data_t *data;

        data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
                return 0;

        data->fd = fd;
        data->dfd = dfd;
        bpf_probe_read_user_str(data->filename, sizeof(data->filename), filename);
        data->how = *how;

        bpf_ringbuf_submit(data,0);
        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
