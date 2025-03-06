// ebpf-program/src/main.c
// eBPF program for Windows security monitoring

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Define a structure for the events we'll collect
struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    u32 dst_ip;
    u16 dst_port;
    u8 protocol;
};

// Create a map to share data with userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Function to track socket connections
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Check for new connections (TCP_ESTABLISHED)
    if (ctx->newstate != TCP_ESTABLISHED) 
        return 0;

    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) 
        return 0;

    // Collect process information
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Collect network information
    event->dst_ip = ctx->daddr;
    event->dst_port = ctx->dport;
    event->protocol = ctx->protocol;

    // Submit the event to userspace
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Function to monitor process creation
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) 
        return 0;

    // Collect process information
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Mark as process event (not network)
    event->dst_ip = 0;
    event->dst_port = 0;
    event->protocol = 0;

    // Submit the event to userspace
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";