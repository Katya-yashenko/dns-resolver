#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <sys/queue.h>

#ifndef min
#define min(a,b) (((a) > (b)) ? ((b)) : (a))
#endif

#define DNS_PORT 53
#define UP_DNS_IP 0xc0a80101 //192.168.1.1

#define ST_FLAGS_QUES         0x0100 // standart query
#define ST_FLAGS_RES          0x8180 // standart query response, no error
#define ST_QDCOUNT            0x0001
#define ST_ANS_QDCOUNT_QUES   0x0000
#define ST_ANS_QDCOUNT_RES    0x0001
#define ST_NSCOUNT            0x0000
#define ST_ARCOUNT            0x0000

#define TYPE_A   0x0001
#define CLASS_IN 0x0001
#define RDLEN    0x0004

struct __attribute__((packed)) dns_hdr
{
    uint16_t id; // identification number
    uint16_t flags; // differents field
    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
};

struct __attribute__((packed)) res_part
{
    uint16_t type;
    uint16_t clas;
    uint32_t ttl;
    uint16_t rdlen;
    uint32_t rdata;
};

bool check_res_is_ip(struct res_part *res)
{
    if(ntohs(res->type) == TYPE_A &&
       ntohs(res->clas) == CLASS_IN &&
       ntohs(res->rdlen) == RDLEN){
        return 1;
    }

    return 0;
}

bool check_hdr_ques_is_standard(struct dns_hdr *dns_hdr)
{
    if(ntohs(dns_hdr->flags) == ST_FLAGS_QUES &&
       ntohs(dns_hdr->q_count) == ST_QDCOUNT &&
       ntohs(dns_hdr->ans_count) == ST_ANS_QDCOUNT_QUES &&
       ntohs(dns_hdr->auth_count) == ST_NSCOUNT &&
       ntohs(dns_hdr->add_count) == ST_ARCOUNT){
        return 1;
    }

    return 0;
}

typedef struct _Hash
{
    LIST_ENTRY(_Hash) pointers;
    char name[65507];
    uint32_t nb_len;
    uint32_t ttl;
    uint32_t ip;
    time_t time;
    bool black;
} Hash;

struct Hash_elem
{
    char name[65507];
    uint32_t nb_len;
    uint32_t ttl;
    uint32_t ip;
    time_t time;
    bool black;
};

Hash *create_hash(struct Hash_elem elem)
{
    Hash *hash = (Hash *)malloc(sizeof(Hash));
    memcpy(hash->name, elem.name, elem.nb_len);
    hash->nb_len = elem.nb_len;
    hash->ttl = elem.ttl;
    hash->ip = elem.ip;
    hash->time = elem.time;
    hash->black = elem.black;

    return hash;
}

LIST_HEAD(hash_list, _Hash) hash_list;

int do_packet(char *packet, struct dns_hdr *ques_hdr, Hash *hash)
{
    struct res_part last;
    uint16_t lable_ref_name = htons(0xc00c);

    ques_hdr->flags = htons(ST_FLAGS_RES);
    ques_hdr->ans_count = htons(ST_ANS_QDCOUNT_RES);

    last.type = htons(TYPE_A);
    last.clas = htons(CLASS_IN);
    last.ttl = htonl(hash->ttl);
    if(hash->black == true)
        last.ttl = htonl(0x0100);
    last.rdlen = htons(RDLEN);
    last.rdata = htonl(hash->ip);

    memcpy(packet, ques_hdr, 12);
    memcpy(packet + 12, hash->name, hash->nb_len);
    memcpy(packet + 12 + hash->nb_len, &lable_ref_name, 2);
    memcpy(packet + 14 + hash->nb_len, &last, 14);

    return 28 + hash->nb_len;
}

uint32_t dns_format(char *url, char *buff)
{
    int i, c = 0;
    uint32_t len = strlen(url);
    uint16_t *qt = (uint16_t *)(buff + len + 2);
    uint16_t *qc = (uint16_t *)(buff + len + 4);

    buff[len+1] = 0;
    for(i = len-1; i >= 0; i--)
    {
        if(url[i] == '.')
        {
            buff[i+1] = c;
            c = 0;
        }
        else
        {
            buff[i+1] = url[i];
            c++;
        }
    }
    buff[0] = c;

    *qt = htons(TYPE_A);
    *qc = htons(CLASS_IN);

    return len + 6;
}

int fill_black_list()
{
    FILE *F;
    char url[65507];
    char buff[65507];
    char end[4] = "end";
    uint8_t a, b, c, d;
    struct Hash_elem elem;

    elem.black = true;

    if ((F = fopen("black.txt", "r")) == NULL)
    {
        perror("fopen");
        return -1;
    }

    while(memcmp(url, end, 3))
    {
        if (fscanf(F, "%s", url) == EOF) {
            perror("url read failure");
            return -1;
        }

        if(memcmp(url, end, 3) == 0) {
            break;
        }

        if (fscanf(F, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == EOF) {
            perror("ip read failure");
            return -1;
        }

        elem.nb_len = dns_format(url, buff);
        memcpy(elem.name, buff, elem.nb_len);
        elem.ttl = 0;
        elem.time = 0;
        elem.ip = d + c * 256 + b * 256 * 256 + a * 256 * 256 * 256;

        Hash *hash_name = create_hash(elem);
        LIST_INSERT_HEAD(&hash_list, hash_name, pointers);

    }
    fclose(F);

    return 0;
}

int init_and_bind()
{
    int sock;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(1);
    }
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    return sock;
}

int main()
{
    int rc;
    int sock = init_and_bind();
    struct sockaddr_in DNS_up_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(UP_DNS_IP),
    };
    char res_buff[65507];
    char ques_buff[65507];
    char packet[65507];
    struct sockaddr_in client_addr;
    struct sockaddr_in res_addr;
    socklen_t ques_addr_len = sizeof(client_addr);
    socklen_t res_addr_len = sizeof(res_addr);

    int ques_n, res_n, n, exp_n;
    time_t time_now;

    int offset;

    struct dns_hdr ques_hdr;
    struct dns_hdr res_hdr;
    struct res_part res_part;

    struct Hash_elem elem;

    LIST_INIT(&hash_list);
    rc = fill_black_list();
    if (rc != 0)
        return 0;

    elem.black = false;

    while (1)
    {
        bool res_recived = false;
        bool res_no_such_name = true;
        bool res_no_such_ip = true;
        bool sent = false;
        uint8_t ques_lable_len = 1;
        uint8_t ques_name_len = 0;
        uint8_t ques_lable_count = 0;

        ques_n = recvfrom(sock, ques_buff, 65506, 0,
                         (struct sockaddr*)&client_addr,
                          &ques_addr_len);
        if (ques_n <= 12)
            continue;

        offset = 12;
        memcpy(&ques_hdr, ques_buff, offset);
        if(!check_hdr_ques_is_standard(&ques_hdr))
            continue; // drop all unusual pacets

        while(ques_lable_len)
        {
            memcpy(&ques_lable_len, ques_buff + offset +
                   ques_name_len + ques_lable_count, 1);
            ques_lable_count++;
            ques_name_len += ques_lable_len;
        }

        elem.nb_len = ques_name_len + ques_lable_count +4;
        memcpy(elem.name, ques_buff + offset, elem.nb_len);

        Hash *hash;
        LIST_FOREACH(hash, &hash_list, pointers)
        {
/*
            hash->name[hash->nb_len] = '\0';
            printf("name = %s\n", hash->name);
            printf("name_len = %u\n", hash->nb_len);
            printf("ttl = %u\n", hash->ttl);
            printf("ip = %x\n", hash->ip);
            printf("time = %u\n", hash->time);
            printf("black = %s\n\n", hash->black ? "true" : "false");
*/
            if(!memcmp(hash->name, elem.name, min(hash->nb_len, elem.nb_len)))
            {

                time_now = time((time_t *)0);
                if(hash->black == true || (hash->time + hash->ttl) > time_now)
                {
                    exp_n = do_packet(packet, &ques_hdr, hash);
                    n = sendto(sock, packet, exp_n, 0,
                               (struct sockaddr *)&client_addr,
                               sizeof(client_addr));
                    if (n < 0)
                    {
                        perror("sendto");
                        break;
                    }
                    sent = true;
                    break;
                }
                else
                {
                    LIST_REMOVE(hash, pointers);
                    break;
                }
            }
        }

        if(sent)
            continue;

        offset += ques_name_len + ques_lable_count + 4; 

        n = sendto(sock, ques_buff, ques_n, 0,
                   (struct sockaddr *)&DNS_up_addr,
                   sizeof(DNS_up_addr));
        if (n < 0)
        {
            perror("sendto");
            break;
        }

        while(!res_recived)
        {
            res_n = recvfrom(sock, res_buff, 65506, 0,
                             (struct sockaddr*)&res_addr,
                             &res_addr_len);

            if(res_n <= offset)
                break;

            if(DNS_up_addr.sin_addr.s_addr != res_addr.sin_addr.s_addr)
                continue;

            memcpy(&res_hdr, res_buff, 12);
            if(ques_hdr.id == res_hdr.id)
            {
                res_recived = true;
                res_no_such_name = false;
            }
        }

        if(res_no_such_name)
            continue;

        while(offset < res_n)
        {
            uint8_t res_lable_len = 1;
            uint8_t res_name_len = 0;
            uint8_t res_lable_count = 0;
            uint8_t res_lable_type;

            while(res_lable_len)
            {
                memcpy(&res_lable_type, res_buff + offset +
                       res_name_len + res_lable_count, 1);
                res_lable_type = res_lable_type >> 6;

                if(res_lable_type == 3)
                {
                    res_name_len += 2;
                    break;
                }

                res_lable_count++;
                res_name_len += res_lable_len;
            }
            offset += res_name_len + res_lable_count;
            memcpy(&res_part, res_buff + offset, 14);
            if(check_res_is_ip(&res_part))
            {
                res_no_such_ip = false;
                break;
            }

            offset += 10 + ntohs(res_part.rdlen);
        }

        if(res_no_such_ip)
            continue;

        elem.ttl = ntohl(res_part.ttl);
        elem.ip = ntohl(res_part.rdata);
        elem.time = time((time_t *)0);

        Hash *hash_name = create_hash(elem);
        LIST_INSERT_HEAD(&hash_list, hash_name, pointers);

        exp_n = do_packet(packet, &ques_hdr, hash_name);
        n = sendto(sock, packet, exp_n, 0,
                   (struct sockaddr *)&client_addr,
                   sizeof(client_addr));
        if (n < 0)
            perror("sendto");
    }

    return 0;
}

