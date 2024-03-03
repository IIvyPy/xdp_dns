#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>

#ifndef __DNS_PROTO_H__
#define __DNS_PROTO_H__

#define QNAME_CONTAIN_INVALID_CHAR -2

// 24 hour
#define DNS_RR_MAX_TTL 86400

#define DNS_MAX_NAME_LABEL_NUM 128

#define DNS_MAX_NAME_LEN 256

// DNS FIXED value
#define IPv4_ADDR_SIZE 4
#define IPv6_ADDR_SIZE 16

#define DNS_FIXED_MIN_TTL 60

// RFC7871
#define SUBNET_FAMILY_NONE 0
#define SUBNET_FAMILY_IPv4 1
#define SUBNET_FAMILY_IPv6 2

#define EDNS0_OPTION_NUM 12

// DNSSEC OK
#define EDNS0_DNSSEC_DO 0x08000

// DNS TYPE
#define DNS_TYPE_A 0x0001
#define DNS_TYPE_AAAA 0x001C

// bpf_prog_inx
#define INX_1 1
#define INX_2 2

// likely optimization
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

struct lpm_name
{
    __u32 prefixlen;             // qname len
    char data[DNS_MAX_NAME_LEN]; // qname
};

struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_name);
    __type(value, struct a_record);
    __uint(max_entries, 65535);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_name_maps SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_query_hdr);
    __type(value, struct a_record);
    __uint(max_entries, 65535);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} name_maps SEC(".maps");

struct array_value {
    __u32 age;
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct array_value);
    __uint(max_entries, 1);
} array SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 100);
} prog_jumps SEC(".maps");

struct hdr_cursor
{
    void *pos;
    void *data;
    void *data_end;
    __u32 ofs;
};

enum dn_opt_code
{
    DNS_OPT_LLQ_CODE = 0x1,          // long lived queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
    DNS_OPT_UL_CODE = 0x2,           // update lease draft: http://files.dns-sd.org/draft-sekar-dns-ul.txt
    DNS_OPT_NSID_CODE = 0x3,         // nsid (See RFC 5001)
    DNS_OPT_DAU_CODE = 0x5,          // DNSSEC Algorithm Understood
    DNS_OPT_DHU_CODE = 0x6,          // DS Hash Understood
    DNS_OPT_N3U_CODE = 0x7,          // NSEC3 Hash Understood
    DNS_OPT_ECS_CODE = 0x0008,       // client-subnet (See RFC 7871)
    DNS_OPT_EXPIRE_CODE = 0x9,       // EDNS0 expire
    DNS_OPT_COOKIE_CODE = 0xa,       // EDNS0 Cookie
    DNS_OPT_TCPKEEPALIVE_CODE = 0xb, // EDNS0 tcp keep alive (See RFC 7828)
    DNS_OPT_PADDING_CODE = 0xc,      // EDNS0 padding (See RFC 7830)
    DNS_OPT_EDE_CODE = 0xf,          // EDNS0 extended DNS errors (See RFC 8914)
    // ...
};

enum dns_qr
{
    DNS_QR_QUERY = 0,
    DNS_QR_ANSWER = 1,
};

enum dns_class
{
    DNS_CLASS_IN = 0x0001,
};

enum dns_rcode
{
    DNS_RCODE_NO_ERR = 0,
    DNS_RCODE_FORMAT_ERR = 1,
    DNS_RCODE_SERVER_FAIL = 2,
    DNS_RCODE_NX_DOMAIN = 3,
    DNS_RCODE_NOT_IMPL = 4,
    DNS_RCODE_REFUSED = 5,
    DNS_RCODE_YXDOMAIN = 6,
    DNS_RCODE_YXRRSET = 7,
    DNS_RCODE_NXRRSET = 8,
    DNS_RCODE_NOTAUTH = 9,
    DNS_RCODE_NOTZONE = 10,

    DNS_RCODE_BADVERS = 16,
};

enum dns_rr_type
{
    DNS_RR_TYPE_A = 1, // A
    DNS_RR_TYPE_NS = 2,
    DNS_RR_TYPE_CNAME = 5,
    DNS_RR_TYPE_SOA = 6,
    DNS_RR_TYPE_PTR = 12,
    DNS_RR_TYPE_MX = 15,
    DNS_RR_TYPE_TXT = 16,
    DNS_RR_TYPE_AAAA = 28, // AAAA
    DNS_RR_TYPE_SRV = 33,
    DNS_RR_TYPE_A6 = 38,
    DNS_RR_TYPE_OPT = 41, // EDNS0
    DNS_RR_TYPE_SSHFP = 44,
    DNS_RR_TYPE_SPF = 99,
    DNS_RR_TYPE_AXFR = 252,
    DNS_RR_TYPE_ALL = 255
};

#pragma pack(push)
#pragma pack(1)

// 12 Byte
struct dns_hdr
{
    __u16 transaction_id;
    __u8 rd : 1;
    __u8 tc : 1;
    __u8 aa : 1;
    __u8 opcode : 4;
    __u8 qr : 1;
    __u8 rcode : 4;
    __u8 cd : 1;
    __u8 ad : 1;
    __u8 z : 1;
    __u8 ra : 1;

    __u16 q_count;    /* Number of questions */
    __u16 ans_count;  /* Number of answer RRs */
    __u16 auth_count; /* Number of authority RRs */
    __u16 addi_count; /* Number of resource RRs */
};

struct dns_query_hdr
{
    __u16 qtype;
    __u16 qclass;
    char name[DNS_MAX_NAME_LEN];
};

struct a_record
{
    struct in_addr ip_addr;
    uint32_t ttl;
};

// Used as a generic DNS response
struct dns_response
{
    uint16_t query_pointer;
    uint16_t record_type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_length;
} __attribute__((packed));

// --------- DNS opt begin

struct dns_edns_hdr_without_name
{
    __u16 type;
    __u16 class;
    __u32 ttl;
    __u16 rdata_len;
};

// 11 Byte
struct dns_edns_hdr
{
    __u8 name;   // must be 0
    __u16 type;  // must be 41
    __u16 size; // udp payload size
    __u32 ttl;
    __u16 rdata_len;
};

struct dns_opt_header
{
    __u16 code;
    __u16 len;
};

// subnet
struct dns_opt_ecs
{
    __u16 family;
    __u8 source_mask;
    __u8 scope_mask;
    __u8 addr[0];
};

#pragma pack(pop)

#endif
