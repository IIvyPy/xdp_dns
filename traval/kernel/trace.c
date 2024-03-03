//go:build ignore

#include "include/vmlinux.h"
#include "include/common.h"
#include "include/linux/if_ether.h"
#include "include/bpf/bpf_endian.h"

static __s32 parse_ethhdr(struct hdr_cursor *nh, struct ethhdr **ethhdr_l2)
{
    *ethhdr_l2 = nh->pos;
    if ((void *)(*ethhdr_l2 + 1) > nh->data_end)
    {
        return -1;
    }

    nh->pos += sizeof(struct ethhdr);

#ifdef DEBUG
    bpf_printk("receive proto is %d", (*ethhdr_l2)->h_proto);
    bpf_printk("receive source is %x%x%x%x", (*ethhdr_l2)->h_source[0], (*ethhdr_l2)->h_source[1], (*ethhdr_l2)->h_source[2], (*ethhdr_l2)->h_source[3]);
    bpf_printk("receive dest is %x%x%x%x", (*ethhdr_l2)->h_dest[0], (*ethhdr_l2)->h_dest[1], (*ethhdr_l2)->h_dest[2], (*ethhdr_l2)->h_dest[3]);
#endif
    return (*ethhdr_l2)->h_proto;
}

static __s32 parse_ipv4hdr(struct hdr_cursor *nh, struct iphdr **iphdr_l3)
{
    *iphdr_l3 = nh->pos;
    // 将此指针类型+1就是移一个以此结构体长度为长度的指针
    if ((void *)(*iphdr_l3 + 1) > nh->data_end)
    {
        return -1;
    }
    nh->pos += ((*iphdr_l3)->ihl << 2);

    return (*iphdr_l3)->protocol;
}

static __s32 parse_ipv6hdr(struct hdr_cursor *nh, struct ipv6hdr **ipv6hdr_l3)
{
    *ipv6hdr_l3 = nh->pos;
    if ((void *)(*ipv6hdr_l3 + 1) > nh->data_end)
    {
        return -1;
    }

    nh->pos += sizeof(struct ipv6hdr);

    return (*ipv6hdr_l3)->nexthdr;
}

static __s32 parse_udphdr(struct hdr_cursor *nh, struct udphdr **udphdr_l4)
{
    *udphdr_l4 = nh->pos;
    if ((void *)(*udphdr_l4 + 1) > nh->data_end)
    {
        return -1;
    }
    nh->pos += sizeof(struct udphdr);

    __s32 len = bpf_htons((*udphdr_l4)->len) - sizeof(struct udphdr);
    if (unlikely(len < 0))
    {
        return -1;
    }

    return len;
}

#ifdef EDNS0
static int parse_edns0_hdr(struct hdr_cursor *nh, struct dns_edns_hdr *ednshdr)
{
    ednshdr = nh->pos;
    if ((void *)(ednshdr + 1) > nh->data_end)
    {
        bpf_printk("parse_edns0_hdr error");
        return -1;
    }
    return 0;
}
#endif

// Parse query and return query length
static int parse_query_question(struct hdr_cursor *nh, struct lpm_name *query_name_key)
// static int parse_query_question(struct hdr_cursor *nh, struct dns_query_hdr *dnsqrhdr_l7, struct lpm_name *query_name_key)
{
    uint16_t i;
    void *cursor = nh->pos;
    int namepos = 0;

    // Fill dns_query.name with zero bytes
    // Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
    // memset(&dnsqrhdr_l7->name, 0, DNS_MAX_NAME_LEN);
    memset(&query_name_key->data, 0, DNS_MAX_NAME_LEN);
    query_name_key->prefixlen = 0;
    // Fill record_type and class with default values to satisfy verifier
    // dnsqrhdr_l7->qtype = 0;
    // dnsqrhdr_l7->qclass = 0;

    // We create a bounded loop of DNS_MAX_NAME_LEN (maximum allowed dns name size).
    // We'll loop through the packet byte by byte until we reach '0' in order to get the dns query name
    for (i = 0; i < DNS_MAX_NAME_LEN; i++)
    {

        // Boundary check of cursor. Verifier requires a +1 here.
        // Probably because we are advancing the pointer at the end of the loop
        if (cursor + 1 > nh->data_end)
        {
#ifdef DEBUG
            bpf_printk("Error: boundary exceeded while parsing DNS query name");
#endif
            break;
        }

        /*
        #ifdef DEBUG
        bpf_printk("Cursor contents is %u\n", *(char *)cursor);
        #endif
        */

        // If separator is zero we've reached the end of the domain query
        if (*(char *)(cursor) == 0)
        {

            // We've reached the end of the query name.
            // This will be followed by 2x 2 bytes: the dns type and dns class.
            if (cursor + 5 > nh->data_end)
            {
#ifdef DEBUG
                bpf_printk("Error: boundary exceeded while retrieving DNS record type and class");
#endif
            }
            else
            {
                // dnsqrhdr_l7->qtype = bpf_htons(*(uint16_t *)(cursor + 1));
                // dnsqrhdr_l7->qclass = bpf_htons(*(uint16_t *)(cursor + 3));
                query_name_key->data[namepos++] = 0;
                query_name_key->prefixlen = namepos;
                bpf_printk("receive namepos is %d\n", namepos);
            }  

            // Return the bytecount of (namepos + current '0' byte + dns type + dns class) as the query length.
            return namepos + 1 + 2 + 2;
        }

        // Read and fill data into struct
        // dnsqrhdr_l7->name[namepos] = *(char *)(cursor);
        query_name_key->data[namepos] = *(char *)(cursor);
        namepos++;
        cursor++;
    }

    return -1;
}

// Update IP checksum for IP header, as specified in RFC 1071
// The checksum_location is passed as a pointer. At this location 16 bits need to be set to 0.
static void update_ip_checksum(void *data, int len, uint16_t *checksum_location)
{
    uint32_t accumulator = 0;
    int i;
    for (i = 0; i < len; i += 2)
    {
        uint16_t val;
        // If we are currently at the checksum_location, set to zero
        if (data + i == checksum_location)
        {
            val = 0;
        }
        else
        {
            // Else we load two bytes of data into val
            val = *(uint16_t *)(data + i);
        }
        accumulator += val;
    }

    // Add 16 bits overflow back to accumulator (if necessary)
    uint16_t overflow = accumulator >> 16;
    accumulator &= 0x00FFFF;
    accumulator += overflow;

    // If this resulted in an overflow again, do the same (if necessary)
    accumulator += (accumulator >> 16);
    accumulator &= 0x00FFFF;

    // Invert bits and set the checksum at checksum_location
    uint16_t chk = accumulator ^ 0xFFFF;

#ifdef DEBUG
    bpf_printk("Checksum: %u", chk);
#endif

    *checksum_location = chk;
}

static void modify_dns_header_response(struct dns_hdr *dns_hdr)
{
    // Set query response
    dns_hdr->qr = 1;
    // Set truncated to 0
    // dns_hdr->tc = 0;
    // Set authorative to zero
    // dns_hdr->aa = 0;
    // Recursion available
    dns_hdr->ra = 1;
    // One answer
    dns_hdr->ans_count = bpf_htons(1);
}

// static inline int match_a_records(struct dns_query_hdr *dns_query, struct a_record *a_record){
//     #ifdef DEBUG
//     bpf_printk("receive query type: %d", dns_query->qtype);
//     bpf_printk("receive query class: %d", dns_query->qclass);
//     bpf_printk("receive query name: %s", dns_query->name);
//     #endif

//     struct a_record *record;
//     record = bpf_map_lookup_elem(&name_maps, dns_query);

//     if (record > 0)
//     {
//         a_record->ip_addr = record->ip_addr;
//         a_record->ttl = record->ttl;
//         return 0;
//     }

//     return -1;
// }
#ifdef EDNS0
static int create_edns0_response(char *dns_buffer, size_t *buf_size, struct dns_edns_hdr *ednshdr)
{
    if (ednshdr->type == bpf_htons(41))
    {
        struct dns_edns_hdr *edns_response = (struct dns_edns_hdr *)&dns_buffer[0];
        edns_response->name = 0;
        edns_response->type = bpf_htons(41);
        edns_response->size = bpf_htons(512);
        edns_response->ttl = 0;
        edns_response->rdata_len = 0;

        *buf_size += sizeof(struct dns_edns_hdr);
    }
    else
    {
        return -1;
    }

    return 0;
}
#endif

static void create_query_response(char *dns_buffer, size_t *buf_size, struct a_record *record)
{
    // Formulate a DNS response. Currently defaults to hardcoded query pointer + type a + class in + ttl + 4 bytes as reply.
    bpf_printk("record ttl: %d\n", bpf_ntohl(record->ttl));
    struct dns_response *response = (struct dns_response *)&dns_buffer[0];
    response->query_pointer = bpf_htons(0xc00c);
    response->record_type = bpf_htons(0x0001);
    response->class = bpf_htons(0x0001);
    response->ttl = record->ttl;
    response->data_length = bpf_htons((uint16_t)sizeof(struct in_addr));
    *buf_size += sizeof(struct dns_response);
    // Copy IP address
    memcpy(&dns_buffer[*buf_size], &(record->ip_addr.s_addr), sizeof(struct in_addr));
    *buf_size += sizeof(struct in_addr);
}

//__builtin_memcpy only supports static size_t
// The following function is a memcpy wrapper that uses __builtin_memcpy when size_t n is known.
// Otherwise it uses our own naive & slow memcpy routine
static void copy_to_pkt_buf(struct xdp_md *ctx, void *dst, void *src, size_t n)
{
// Boundary check
#ifdef DEBUG
    bpf_printk("ctx->data_end - dst is %d, n is %d", (void *)(long)ctx->data_end - dst, n);
#endif
    if ((void *)(long)ctx->data_end >= dst + n)
    {
        int i;
        char *cdst = dst;
        char *csrc = src;

        // For A records, src is either 16 or 27 bytes, depending if OPT record is requested.
        // Use __builtin_memcpy for this. Otherwise, use our own slow, naive memcpy implementation.
        switch (n)
        {
        case 16:
            __builtin_memcpy(cdst, csrc, 16);
            break;
        case 17:
            __builtin_memcpy(cdst, csrc, 17);
            break;
        case 18:
            __builtin_memcpy(cdst, csrc, 18);
            break;
        case 19:
            __builtin_memcpy(cdst, csrc, 19);
            break;
        case 20:
            __builtin_memcpy(cdst, csrc, 20);
            break;
        case 21:
            __builtin_memcpy(cdst, csrc, 21);
            break;
        case 22:
            __builtin_memcpy(cdst, csrc, 22);
            break;
        case 23:
            __builtin_memcpy(cdst, csrc, 23);
            break;
        case 24:
            __builtin_memcpy(cdst, csrc, 24);
            break;
        case 25:
            __builtin_memcpy(cdst, csrc, 25);
            break;
        case 26:
            __builtin_memcpy(cdst, csrc, 26);
            break;
        case 27:
            __builtin_memcpy(cdst, csrc, 27);
            break;
        default:
            for (i = 0; i < n; i += 1)
            {
                cdst[i] = csrc[i];
            }
        }
    }
}

static inline void swap_mac(uint8_t *src_mac, uint8_t *dst_mac)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        uint8_t tmp_src;
        tmp_src = *(src_mac + i);
        *(src_mac + i) = *(dst_mac + i);
        *(dst_mac + i) = tmp_src;
    }
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    struct hdr_cursor nh = {.pos = (void *)(long)ctx->data, .data = (void *)(long)ctx->data, .data_end = (void *)(long)ctx->data_end};

    struct ethhdr *ethhdr_l2;
    struct iphdr *iphdr_l3;
    struct ipv6hdr *ipv6hdr_l3;
    struct udphdr *udphdr_l4;
    struct dns_hdr *dnshdr_l7;
    char dns_buffer[512];

    // __u8 proto_type_l3 = 0;
    __s32 proto_type = parse_ethhdr(&nh, &ethhdr_l2);

    if (unlikely(proto_type) < 0)
    {
        return XDP_DROP;
    }
    else if (likely(bpf_htons(ETH_P_IP) == proto_type))
    {
        __s32 proto_type_l4 = parse_ipv4hdr(&nh, &iphdr_l3);
        if (unlikely(proto_type_l4 < 0))
        {
            return XDP_DROP;
        }

        if (likely(proto_type_l4 != IPPROTO_UDP))
        {
            return XDP_PASS;
        }
#ifdef DEBUG
        bpf_printk("ipv4 receive proto_type_l4 is %d", proto_type_l4);
#endif
    }
    else if (likely(bpf_htons(ETH_P_IPV6) == proto_type))
    {
        __s32 proto_type_l4 = parse_ipv6hdr(&nh, &ipv6hdr_l3);
        if (unlikely(proto_type_l4 < 0))
        {
            return XDP_DROP;
        }

        if (likely(proto_type_l4 != IPPROTO_UDP))
        {
            return XDP_PASS;
        }
#ifndef DEBUG
        bpf_printk("ipv6 receive proto_type_l4 is %d", proto_type_l4);
#endif
    }
    else
    {
#ifdef DEBUG
        bpf_printk("unknown packet proto type is %x, %d, %d, %d", proto_type, sizeof(proto_type), bpf_htons(ETH_P_IP), sizeof(bpf_htons(ETH_P_IP)));
#endif
        return XDP_PASS;
    }

    __s32 len = parse_udphdr(&nh, &udphdr_l4);
#ifdef DEBUG
    bpf_printk("receive dns package len is %u", len);
#endif
    if (unlikely(len < 0))
    {
        return XDP_DROP;
    }
#ifdef DEBUG
    bpf_printk("receive dns package dest bpf_ntohs is %u, bpf_htons is %u", udphdr_l4->dest, bpf_htons(udphdr_l4->dest));
    bpf_printk("receive dns package src bpf_ntohs is %u, bpf_htons is %u", udphdr_l4->source, bpf_htons(udphdr_l4->source));
#endif
    if (unlikely(bpf_ntohs(udphdr_l4->dest) != 53))
    {
        return XDP_PASS;
    }
#ifdef DEBUG
    bpf_printk("receive dns package dest port: %d, src port: %d", bpf_ntohs(udphdr_l4->dest), bpf_ntohs(udphdr_l4->source));
#endif
    dnshdr_l7 = nh.pos;
    if (unlikely((void *)(dnshdr_l7 + 1) > nh.data_end))
    {
        return XDP_DROP;
    }
#ifdef DEBUG
    bpf_printk("receive dns package qr is %u, opcode is %u", dnshdr_l7->qr);
#endif
    if (dnshdr_l7->qr != 0 || dnshdr_l7->opcode != 0)
    {
        return XDP_PASS;
    }
#ifdef DEBUG
    bpf_printk("DNS query transaction id %u", bpf_ntohs(dnshdr_l7->transaction_id));
#endif
    // struct dns_query_hdr dns_qrhdr_l7;
    struct lpm_name lpm_qname_key;

    nh.pos += sizeof(struct dns_hdr);

    // int query_len = parse_query_question(&nh, &dns_qrhdr_l7, &lpm_qname_key);
    int query_len = parse_query_question(&nh, &lpm_qname_key);
#ifdef DEBUG
    bpf_printk("receive query_len is %d", query_len);
#endif
    if (query_len < 0)
    {
        return XDP_DROP;
    }

    struct a_record record;
    struct in_addr ip_addr;
    ip_addr.s_addr = bpf_htonl(0x0011);
    record.ip_addr = ip_addr;
    record.ttl = bpf_htonl(0x0011);

    // Check if query matches a record in our hash table
    size_t buf_size = 0;
    // Change DNS header to a valid response header
    modify_dns_header_response(dnshdr_l7);

    bpf_printk("receive query name 1: %d%c%c\n", lpm_qname_key.data[0], lpm_qname_key.data[1], lpm_qname_key.data[2]);
    bpf_printk("receive query name 2: %c%c%c\n", lpm_qname_key.data[3], lpm_qname_key.data[4], lpm_qname_key.data[5]);
    bpf_printk("receive query name 2: %d%c%c\n", lpm_qname_key.data[6], lpm_qname_key.data[7], lpm_qname_key.data[8]);
    bpf_printk("receive query name 3: %c%d\n", lpm_qname_key.data[9], lpm_qname_key.data[10]);
    struct a_record *rd = bpf_map_lookup_elem(&lpm_name_maps, &lpm_qname_key);
    if (!rd)
    {
        bpf_printk("has no record for given query name\n");
        return XDP_PASS;
    }else{
        create_query_response(&dns_buffer[buf_size], &buf_size, rd);
    }

    // struct a_record *rd = bpf_map_lookup_elem(&name_maps, &dns_qrhdr_l7);
    // if (!rd)
    // {
    //     bpf_printk("got no cache\n");
    //     bpf_map_update_elem(&name_maps, &dns_qrhdr_l7, &record, BPF_ANY);
    // }

    // struct a_record *new_rd = bpf_map_lookup_elem(&name_maps, &dns_qrhdr_l7);
    // if (new_rd)
    // {
    //     // Create DNS response and add to temporary buffer.
    //     create_query_response(&dns_buffer[buf_size], &buf_size, new_rd);
    // }
    // else
    // {
    //     return XDP_ABORTED;
    // }

    // Start our response [query_length] bytes beyond the header
    nh.pos += query_len;

#ifdef EDNS0
    if (bpf_ntohs(dnshdr_l7->addi_count) > 0)
    {
        struct dns_edns_hdr ednshdr;
        if (parse_edns0_hdr(&nh, &ednshdr) != -1)
        {
            create_edns0_response(&dns_buffer[buf_size], &buf_size, &ednshdr);
        }
    }
#endif

    // Determine increment of packet buffer
    int tailadjust = nh.pos + buf_size - nh.data_end;
#ifdef DEBUG
    bpf_printk("tailadjust is %d, buf_size is %d\n", tailadjust, buf_size);
#endif
    // Adjust packet length accordingly
    if (bpf_xdp_adjust_tail(ctx, tailadjust))
    {
#ifdef DEBUG
        bpf_printk("Adjust tail fail");
#endif
    }
    else
    {
        // Because we adjusted packet length, mem addresses might be changed.
        // Reinit pointers, as verifier will complain otherwise.

        nh.data = (void *)(unsigned long)ctx->data;
        nh.data_end = (void *)(unsigned long)ctx->data_end;

        // Copy bytes from our temporary buffer to packet buffer
        copy_to_pkt_buf(ctx, nh.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr) + query_len, &dns_buffer[0], buf_size);
#ifdef DEBUG
        bpf_printk("copy_to_pkt_buf query size is %d, buf_size is %d\n", sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr) + query_len, buf_size);
#endif
        ethhdr_l2 = nh.data;
        iphdr_l3 = nh.data + sizeof(struct ethhdr);
        udphdr_l4 = nh.data + sizeof(struct ethhdr) + sizeof(struct iphdr);

        // Do a new boundary check
        if (nh.data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > nh.data_end)
        {
#ifdef DEBUG
            bpf_printk("Error: Boundary exceeded");
#endif
            return XDP_DROP;
        }

        // Adjust UDP length and IP length
        uint16_t iplen = (nh.data_end - nh.data) - sizeof(struct ethhdr);
        uint16_t udplen = (nh.data_end - nh.data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
        iphdr_l3->tot_len = bpf_htons(iplen);
        udphdr_l4->len = bpf_htons(udplen);

        // Swap eth macs
        swap_mac((uint8_t *)ethhdr_l2->h_source, (uint8_t *)ethhdr_l2->h_dest);

        // Swap src/dst IP
        uint32_t src_ip = iphdr_l3->saddr;
        iphdr_l3->saddr = iphdr_l3->daddr;
        iphdr_l3->daddr = src_ip;

        // Set UDP checksum to zero
        udphdr_l4->check = 0;

        // Swap udp src/dst ports
        uint16_t src_port = udphdr_l4->source;
        udphdr_l4->source = udphdr_l4->dest;
        udphdr_l4->dest = src_port;

        // Recalculate IP checksum
        update_ip_checksum(iphdr_l3, sizeof(struct iphdr), &iphdr_l3->check);

        bpf_tail_call(ctx, &prog_jumps, INX_1);

        // Emit modified packet
        return XDP_TX;
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_tx(struct xdp_md *ctx)
{
    __u32 arr_inx = 0;
    struct array_value *av = bpf_map_lookup_elem(&array, &arr_inx);
    if (unlikely(NULL == av))
    {
        bpf_printk("av is null");
        return XDP_DROP;
    }
    else
    {
        bpf_printk("av is not null, is %u\n", av->age);
        av->age = 1;
        bpf_map_update_elem(&array, &arr_inx, av, BPF_ANY);
    }

    bpf_printk("go here means xdp_tx 111111");

    bpf_tail_call(ctx, &prog_jumps, INX_2);
    return XDP_TX;
}

SEC("xdp")
int xdp_test(struct xdp_md *ctx)
{
    __u32 arr_inx = 0;
    struct array_value *av = bpf_map_lookup_elem(&array, &arr_inx);
    if (unlikely(NULL == av))
    {
        bpf_printk("av is null");
        return XDP_DROP;
    }
    else
    {
        if (av->age != 1)
        {
            bpf_printk("warning: should not be here av age is not 1, is %u\n", av->age);
            return XDP_DROP;
        }
        bpf_printk("av is not null, is %u\n", av->age);
    }

    bpf_printk("go here means xdp_test 222222");
    return XDP_TX;
}

char __license[] SEC("license") = "GPL";
