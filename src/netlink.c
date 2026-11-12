/*
 * Netlink route sockets, which Android half-refuses to apps: bind() and
 * RTM_GETLINK are EACCES, so getifaddrs(), if_nameindex() and the interface
 * lists of Qt, Dart and Go fail; RTM_GETADDR and the interface ioctls are
 * allowed.
 *
 * A socket refused so becomes Burrow's: a Unix datagram socket put in its
 * place, bound to an abstract name of ours that it sends the answers to.
 * Each request goes to the kernel on a netlink socket of its own, except
 * RTM_GETLINK, made up from the interfaces' addresses and ioctls. The name is
 * as long as a sockaddr_nl and its nl_pid bytes are zero: readers check that
 * answers come from the kernel by those (glibc, iproute2).
 */

#include "burrow.h"

#define NR_dup3 24
#define AF_UNIX 1
#define AF_INET 2
#define AF_NETLINK 16
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define MSG_DONTWAIT 0x40
#define SOL_SOCKET 1
#define SO_PROTOCOL 38
#define SO_DOMAIN 39
#define F_GETFD 1
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 04000
#define EAGAIN 11
#define ENODEV 19
#define EADDRINUSE 98
#define ENOTCONN 107

#define NLM_F_ACK 0x4
#define NLM_F_MULTI 0x2
#define NLM_F_DUMP 0x300
#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define RTM_NEWLINK 16
#define RTM_GETLINK 18
#define RTM_NEWADDR 20
#define RTM_GETADDR 22
#define IFLA_ADDRESS 1
#define IFLA_BROADCAST 2
#define IFLA_IFNAME 3
#define IFLA_MTU 4
#define IFLA_OPERSTATE 16
#define IFA_LABEL 3
#define IFF_LOOPBACK 0x8
#define IFF_RUNNING 0x40
#define SIOCGIFNAME 0x8910
#define SIOCGIFFLAGS 0x8913
#define SIOCGIFMTU 0x8921
#define SIOCGIFHWADDR 0x8927
#define BUFFER 32768
#define MAX_LINKS 32

struct nlmsghdr {
    uint32_t len;
    uint16_t type, flags;
    uint32_t seq, pid;
};

struct ifinfomsg {
    uint8_t family, pad;
    uint16_t type;
    int32_t index;
    uint32_t flags, change;
};

struct ifreq {
    char name[16];
    union {
        int32_t index, flags, mtu;
        struct {
            uint16_t family;
            uint8_t data[14];
        } hwaddr;
    };
    char pad[8];
};

struct link {
    int32_t index;
    char name[16];
};

static const char kernel[12] = {AF_NETLINK, 0}; /* sockaddr_nl of the kernel */

static uint32_t align4(uint32_t n) { return (n + 3) & ~3u; }

/* Whether @fd is one of our sockets; its name into @name (12 bytes) if so. */
static int ours(long fd, char* name) {
    char a[16];
    uint32_t n = sizeof(a);
    if (sys(NR_getsockname, fd, a, &n, 0) < 0 || n != 12) return 0;
    static const char mark[8] = {AF_UNIX, 0, 0, 'B', 0, 0, 0, 0};
    if (memcmp(a, mark, 8) != 0) return 0;
    memcpy(name, a, 12);
    return 1;
}

/* A refused netlink route socket @fd becomes ours; 0 if it is not one. */
static int adopt(long fd, char* name) {
    int domain = 0, protocol = -1;
    uint32_t n = sizeof(int);
    if (sys6(NR_getsockopt, fd, SOL_SOCKET, SO_DOMAIN, (long) &domain, (long) &n, 0) < 0 || domain != AF_NETLINK) return 0;
    n = sizeof(int);
    if (sys6(NR_getsockopt, fd, SOL_SOCKET, SO_PROTOCOL, (long) &protocol, (long) &n, 0) < 0 || protocol != 0) return 0;
    long s = sys(NR_socket, AF_UNIX, SOCK_DGRAM | O_CLOEXEC, 0, 0);
    if (s < 0) return 0;
    uint32_t unique = (uint32_t) sys(NR_getpid, 0, 0, 0, 0) * 64;
    long r = -EADDRINUSE;
    for (int i = 0; i < 64 && r == -EADDRINUSE; i++) {
        memset(name, 0, 12);
        name[0] = AF_UNIX, name[3] = 'B';
        uint32_t u = unique + (uint32_t) i;
        memcpy(name + 8, &u, 4);
        r = sys(NR_bind, s, name, 12, 0);
    }
    long fd_flags = sys(NR_fcntl, fd, F_GETFD, 0, 0), fl_flags = sys(NR_fcntl, fd, F_GETFL, 0, 0);
    if (r < 0 || fd_flags < 0 || fl_flags < 0 || sys(NR_dup3, s, fd, (fd_flags & 1) ? O_CLOEXEC : 0, 0) < 0) {
        sys(NR_close, s, 0, 0, 0);
        return 0;
    }
    sys(NR_close, s, 0, 0, 0);
    sys(NR_fcntl, fd, F_SETFL, fl_flags & O_NONBLOCK, 0);
    return 1;
}

/* Queues @n bytes of answer on our socket @fd, as one datagram. */
static void answer(long fd, const char* name, const void* buf, long n) {
    sys6(NR_sendto, fd, (long) buf, n, MSG_DONTWAIT, (long) name, 12);
}

/* An NLMSG_ERROR (an ACK if @error is 0) to the request @req. */
static void error_answer(long fd, const char* name, const struct nlmsghdr* req, int error, uint32_t pid) {
    struct {
        struct nlmsghdr h;
        int32_t error;
        struct nlmsghdr req;
    } m = {{sizeof(m), NLMSG_ERROR, 0, req->seq, pid}, error, *req};
    answer(fd, name, &m, sizeof(m));
}

/* Rewrites the answers in @buf (@n bytes) as ours: the kernel addressed them to its socket's port. */
static void set_pid(char* buf, long n, uint32_t pid, int* last) {
    for (long at = 0; at + (long) sizeof(struct nlmsghdr) <= n;) {
        struct nlmsghdr* h = (struct nlmsghdr*) (buf + at);
        if (h->len < sizeof(*h) || (long) h->len > n - at) break;
        h->pid = pid;
        if (h->type == NLMSG_DONE || h->type == NLMSG_ERROR) *last = 1;
        at += align4(h->len);
    }
}

/* Request @req to the kernel; its answers to our socket. */
static long forward(long fd, const char* name, const struct nlmsghdr* req, uint32_t pid) {
    long s = sys(NR_socket, AF_NETLINK, SOCK_RAW | O_CLOEXEC, 0, 0);
    if (s < 0) return s;
    long r = sys6(NR_sendto, s, (long) req, req->len, 0, (long) kernel, sizeof(kernel));
    char buf[BUFFER];
    /* A dump goes on as it is read; anything else is answered within sendto(). */
    int dump = (req->flags & NLM_F_DUMP) == NLM_F_DUMP, last = 0;
    while (r >= 0 && !last) {
        long n = sys6(NR_recvfrom, s, (long) buf, sizeof(buf), dump ? 0 : MSG_DONTWAIT, 0, 0);
        if (n == -EINTR) continue;
        if (n <= 0) break;
        set_pid(buf, n, pid, &last);
        answer(fd, name, buf, n);
    }
    sys(NR_close, s, 0, 0, 0);
    return r < 0 ? r : 0;
}

/* The interfaces that have an address, with their names: an IPv4 address's
 * label, else SIOCGIFNAME (refused on Android: those stay unnamed). */
static int links(struct link* out) {
    long s = sys(NR_socket, AF_NETLINK, SOCK_RAW | O_CLOEXEC, 0, 0);
    if (s < 0) return 0;
    struct {
        struct nlmsghdr h;
        uint8_t family, pad[7];
    } req = {{sizeof(req), RTM_GETADDR, 1 | NLM_F_DUMP, 1, 0}, 0, {0}};
    int count = 0, last = 0;
    char buf[BUFFER];
    if (sys6(NR_sendto, s, (long) &req, sizeof(req), 0, (long) kernel, sizeof(kernel)) < 0) last = 1;
    while (!last) {
        long n = sys6(NR_recvfrom, s, (long) buf, sizeof(buf), 0, 0, 0);
        if (n == -EINTR) continue;
        if (n <= 0) break;
        for (long at = 0; at + (long) sizeof(struct nlmsghdr) <= n;) {
            const struct nlmsghdr* h = (const struct nlmsghdr*) (buf + at);
            if (h->len < sizeof(*h) || (long) h->len > n - at) break;
            at += align4(h->len);
            if (h->type == NLMSG_DONE || h->type == NLMSG_ERROR) last = 1;
            if (h->type != RTM_NEWADDR || h->len < sizeof(*h) + 8) continue;
            int32_t index = *(const int32_t*) ((const char*) h + sizeof(*h) + 4);
            int i = 0;
            while (i < count && out[i].index != index) i++;
            if (i == count) {
                if (count == MAX_LINKS) continue;
                out[count].index = index;
                out[count++].name[0] = 0;
            }
            for (uint32_t a = sizeof(*h) + 8; a + 4 <= h->len;) {
                const uint16_t* rta = (const uint16_t*) ((const char*) h + a);
                if (rta[0] < 4 || a + rta[0] > h->len) break;
                if (rta[1] == IFA_LABEL && rta[0] > 4 && rta[0] - 4 <= 16 && !out[i].name[0])
                    memcpy(out[i].name, rta + 2, rta[0] - 4), out[i].name[15] = 0;
                a += align4(rta[0]);
            }
        }
    }
    sys(NR_close, s, 0, 0, 0);
    s = sys(NR_socket, AF_INET, SOCK_DGRAM | O_CLOEXEC, 0, 0);
    int named = 0;
    for (int i = 0; i < count; i++) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.index = out[i].index;
        if (!out[i].name[0] && s >= 0 && sys(NR_ioctl, s, SIOCGIFNAME, &ifr, 0) == 0) memcpy(out[i].name, ifr.name, 16);
        if (out[i].name[0]) out[named++] = out[i];
    }
    if (s >= 0) sys(NR_close, s, 0, 0, 0);
    return named;
}

static char* attribute(char* at, uint16_t type, const void* data, uint16_t length) {
    uint16_t* rta = (uint16_t*) at;
    rta[0] = (uint16_t) (4 + length), rta[1] = type;
    memcpy(at + 4, data, length);
    memset(at + 4 + length, 0, align4(4 + length) - 4 - length);
    return at + align4(4 + length);
}

/* An RTM_NEWLINK of @l at @at, from the interface ioctls; its end. */
static char* new_link(char* at, const struct link* l, long s, const struct nlmsghdr* req, uint16_t flags, uint32_t pid) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.name, l->name, 16);
    uint32_t if_flags = sys(NR_ioctl, s, SIOCGIFFLAGS, &ifr, 0) == 0 ? (uint32_t) ifr.flags & 0xffff : 0;
    uint32_t mtu = sys(NR_ioctl, s, SIOCGIFMTU, &ifr, 0) == 0 ? (uint32_t) ifr.mtu : 1500;
    /* Android refuses the hardware address: Ethernet's type and a zero one. */
    uint16_t type = (if_flags & IFF_LOOPBACK) ? 772 /* ARPHRD_LOOPBACK */ : 1 /* ARPHRD_ETHER */;
    uint8_t address[6] = {0}, broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (sys(NR_ioctl, s, SIOCGIFHWADDR, &ifr, 0) == 0) {
        type = ifr.hwaddr.family;
        memcpy(address, ifr.hwaddr.data, 6);
    }
    if (type == 772) memset(broadcast, 0, 6);
    uint8_t state = (if_flags & IFF_RUNNING) ? 6 /* IF_OPER_UP */ : 2 /* IF_OPER_DOWN */;
    struct nlmsghdr* h = (struct nlmsghdr*) at;
    struct ifinfomsg* ifi = (struct ifinfomsg*) (h + 1);
    *ifi = (struct ifinfomsg){0, 0, type, l->index, if_flags, 0};
    char* end = (char*) (ifi + 1);
    end = attribute(end, IFLA_IFNAME, l->name, (uint16_t) (length_of(l->name) + 1));
    end = attribute(end, IFLA_MTU, &mtu, 4);
    end = attribute(end, IFLA_ADDRESS, address, 6);
    end = attribute(end, IFLA_BROADCAST, broadcast, 6);
    end = attribute(end, IFLA_OPERSTATE, &state, 1);
    *h = (struct nlmsghdr){(uint32_t) (end - at), RTM_NEWLINK, flags, req->seq, pid};
    return end;
}

/* RTM_GETLINK: all the interfaces (a dump), or the one of the request's index or name. */
static void get_link(long fd, const char* name, const struct nlmsghdr* req, uint32_t pid) {
    struct link all[MAX_LINKS];
    int count = links(all);
    long s = sys(NR_socket, AF_INET, SOCK_DGRAM | O_CLOEXEC, 0, 0);
    char buf[MAX_LINKS * 128 + 64];
    char* at = buf;
    if ((req->flags & NLM_F_DUMP) == NLM_F_DUMP) {
        for (int i = 0; i < count; i++) at = new_link(at, &all[i], s, req, NLM_F_MULTI, pid);
        struct nlmsghdr* done = (struct nlmsghdr*) at;
        *done = (struct nlmsghdr){sizeof(*done) + 4, NLMSG_DONE, NLM_F_MULTI, req->seq, pid};
        memset(done + 1, 0, 4);
        answer(fd, name, buf, at + done->len - buf);
    } else {
        const struct ifinfomsg* ifi = (const struct ifinfomsg*) (req + 1);
        int32_t index = req->len >= sizeof(*req) + sizeof(*ifi) ? ifi->index : 0;
        const char* wanted = 0;
        for (uint32_t a = sizeof(*req) + sizeof(*ifi); a + 4 <= req->len;) {
            const uint16_t* rta = (const uint16_t*) ((const char*) req + a);
            if (rta[0] < 4 || a + rta[0] > req->len) break;
            if (rta[1] == IFLA_IFNAME && rta[0] > 4 && ((const char*) rta)[rta[0] - 1] == 0) wanted = (const char*) (rta + 2);
            a += align4(rta[0]);
        }
        int i = 0;
        while (i < count && !(index > 0 ? all[i].index == index : wanted && same(all[i].name, wanted))) i++;
        if (i == count) {
            error_answer(fd, name, req, -ENODEV, pid);
        } else {
            answer(fd, name, buf, new_link(buf, &all[i], s, req, 0, pid) - buf);
            if (req->flags & NLM_F_ACK) error_answer(fd, name, req, 0, pid);
        }
    }
    if (s >= 0) sys(NR_close, s, 0, 0, 0);
}

/* The requests in @buf (@n bytes), sent on our socket @fd. */
static long requests(long fd, const char* name, const char* buf, long n) {
    uint32_t pid = (uint32_t) sys(NR_getpid, 0, 0, 0, 0);
    for (long at = 0; at + (long) sizeof(struct nlmsghdr) <= n;) {
        const struct nlmsghdr* h = (const struct nlmsghdr*) (buf + at);
        /* The kernel stops there and takes the whole buffer (netlink_rcv_skb): iproute2 sends its
         * request structure whole, the message and zeros after it. */
        if (h->len < sizeof(*h) || (long) h->len > n - at) break;
        if (h->type == RTM_GETLINK) {
            get_link(fd, name, h, pid);
        } else {
            long r = forward(fd, name, h, pid);
            if (r < 0) return r;
        }
        at += align4(h->len);
    }
    return n;
}

/* Whether a call on @fd that failed with @r is one of ours, or a refused
 * netlink socket now made ours. A Unix socket refuses a netlink address
 * (EINVAL), and with none it is not connected. */
static int taken(long fd, long r, char* name) {
    if (r == -EACCES) return adopt(fd, name);
    return (r == -EINVAL || r == -ENOTCONN) && ours(fd, name);
}

long netlink_send(long fd, const void* buf, long n, long r) {
    char name[12];
    if (r >= 0 || n < 0 || !taken(fd, r, name)) return r;
    return requests(fd, name, buf, n);
}

long netlink_sendmsg(long fd, const void* vec, size_t count, long r) {
    const struct {
        const void* base;
        size_t len;
    }* iov = vec;
    char name[12], buf[8192];
    if (r >= 0 || !taken(fd, r, name)) return r;
    long n = 0;
    for (size_t i = 0; i < count; i++) {
        if (n + (long) iov[i].len > (long) sizeof(buf)) return -ENOMEM;
        memcpy(buf + n, iov[i].base, iov[i].len);
        n += (long) iov[i].len;
    }
    return requests(fd, name, buf, n);
}

long netlink_bind(long fd, long r) {
    char name[12];
    if (r >= 0 || !taken(fd, r, name)) return r;
    return 0;
}

/* Our socket's name in @a (@n bytes) as a netlink address: the socket's
 * own (@self, getsockname()) or the kernel's (the sender of answers). */
void netlink_name(char* a, uint32_t n, int self) {
    static const char mark[8] = {AF_UNIX, 0, 0, 'B', 0, 0, 0, 0};
    if (n != 12 || memcmp(a, mark, 8) != 0) return;
    uint32_t pid = self ? (uint32_t) sys(NR_getpid, 0, 0, 0, 0) : 0;
    memset(a, 0, 12);
    a[0] = AF_NETLINK;
    memcpy(a + 4, &pid, 4);
}
