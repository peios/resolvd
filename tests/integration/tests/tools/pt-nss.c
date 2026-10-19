/* pt-nss: drive libnss_peios_net.so.2 directly and through glibc, and
   trace what the module does on its sockets and files. See the Lua
   header for why it exists and how it is built. Ops are separated by
   "+"; NAME "@null" is a null pointer, "@hex:<bytes>" raw bytes. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SOCK_PATH "/run/resolvd/resolv.sock"

static int tracing, in_child;
static char tbuf[1 << 20];
static size_t tlen;
static char redirect[108];
static int socks[1024];

static void T(const char *fmt, ...) {
    if (!tracing || in_child) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tbuf + tlen, sizeof tbuf - tlen, fmt, ap);
    va_end(ap);
    if (n > 0 && tlen + n < sizeof tbuf) tlen += n;
}

static void Thex(const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) T("%02x", b[i]);
}

#define REAL(name)                                                                                 \
    static __typeof__(name) *real_##name;                                                          \
    if (!real_##name) real_##name = (__typeof__(name) *)dlsym(RTLD_NEXT, #name)

int socket(int d, int t, int p) {
    REAL(socket);
    int r = real_socket(d, t, p);
    int e = errno;
    if (tracing && !in_child) {
        T("t socket family=%d type=%d ret=%d\n", d, t & 0xf, r);
        if (r >= 0 && r < 1024) socks[r] = 1;
    }
    errno = e;
    return r;
}

int connect(int fd, const struct sockaddr *a, socklen_t l) {
    REAL(connect);
    struct sockaddr_un u;
    const struct sockaddr *use = a;
    socklen_t ul = l;
    char path[110] = "";
    if (a && a->sa_family == AF_UNIX) {
        const struct sockaddr_un *s = (const void *)a;
        size_t n = l > offsetof(struct sockaddr_un, sun_path)
                       ? l - offsetof(struct sockaddr_un, sun_path)
                       : 0;
        if (n > sizeof s->sun_path) n = sizeof s->sun_path;
        memcpy(path, s->sun_path, n);
        path[n] = 0;
        if (redirect[0] && strcmp(path, SOCK_PATH) == 0) {
            memset(&u, 0, sizeof u);
            u.sun_family = AF_UNIX;
            strcpy(u.sun_path, redirect);
            use = (void *)&u;
            ul = offsetof(struct sockaddr_un, sun_path) + strlen(redirect) + 1;
        }
    }
    int r = real_connect(fd, use, ul);
    int e = errno;
    if (a && a->sa_family == AF_UNIX)
        T("t connect fd=%d family=1 path=%s ret=%d errno=%d\n", fd, path, r, r ? e : 0);
    else T("t connect fd=%d family=%d ret=%d\n", fd, a ? a->sa_family : -1, r);
    errno = e;
    return r;
}

int close(int fd) {
    REAL(close);
    if (tracing && !in_child && fd >= 0 && fd < 1024 && socks[fd]) {
        T("t close fd=%d\n", fd);
        socks[fd] = 0;
    }
    return real_close(fd);
}

int setsockopt(int fd, int lvl, int opt, const void *v, socklen_t l) {
    REAL(setsockopt);
    if (lvl == SOL_SOCKET && (opt == SO_RCVTIMEO || opt == SO_SNDTIMEO) &&
        l >= (socklen_t)sizeof(struct timeval)) {
        const struct timeval *tv = v;
        T("t setsockopt fd=%d opt=%s sec=%ld usec=%ld\n", fd,
          opt == SO_RCVTIMEO ? "rcvtimeo" : "sndtimeo", (long)tv->tv_sec, (long)tv->tv_usec);
    } else {
        T("t setsockopt fd=%d level=%d opt=%d\n", fd, lvl, opt);
    }
    return real_setsockopt(fd, lvl, opt, v, l);
}

static int traced(int fd) {
    return tracing && !in_child && fd >= 0 && fd < 1024 && socks[fd];
}

static void out_bytes(const char *what, int fd, const void *b, ssize_t r) {
    if (r > 0) {
        T("t %s fd=%d hex=", what, fd);
        Thex(b, r);
        T("\n");
    } else T("t %s fd=%d ret=%zd errno=%d\n", what, fd, r, r < 0 ? errno : 0);
}

ssize_t write(int fd, const void *b, size_t n) {
    REAL(write);
    ssize_t r = real_write(fd, b, n);
    int e = errno;
    if (traced(fd)) out_bytes("send", fd, b, r);
    errno = e;
    return r;
}
ssize_t send(int fd, const void *b, size_t n, int f) {
    REAL(send);
    ssize_t r = real_send(fd, b, n, f);
    int e = errno;
    if (traced(fd)) out_bytes("send", fd, b, r);
    errno = e;
    return r;
}
ssize_t sendto(int fd, const void *b, size_t n, int f, const struct sockaddr *a, socklen_t l) {
    REAL(sendto);
    ssize_t r = real_sendto(fd, b, n, f, a, l);
    int e = errno;
    T("t sendto fd=%d family=%d ret=%zd\n", fd, a ? a->sa_family : -1, r);
    errno = e;
    return r;
}
ssize_t sendmsg(int fd, const struct msghdr *m, int f) {
    REAL(sendmsg);
    ssize_t r = real_sendmsg(fd, m, f);
    int e = errno;
    T("t sendmsg fd=%d ret=%zd\n", fd, r);
    errno = e;
    return r;
}
ssize_t writev(int fd, const struct iovec *v, int c) {
    REAL(writev);
    ssize_t r = real_writev(fd, v, c);
    int e = errno;
    if (traced(fd)) {
        T("t send fd=%d hex=", fd);
        ssize_t left = r;
        for (int i = 0; i < c && left > 0; i++) {
            size_t k = v[i].iov_len < (size_t)left ? v[i].iov_len : (size_t)left;
            Thex(v[i].iov_base, k);
            left -= k;
        }
        T("\n");
    }
    errno = e;
    return r;
}
ssize_t read(int fd, void *b, size_t n) {
    REAL(read);
    ssize_t r = real_read(fd, b, n);
    int e = errno;
    if (traced(fd)) {
        errno = e;
        out_bytes("recv", fd, b, r);
    }
    errno = e;
    return r;
}
ssize_t recv(int fd, void *b, size_t n, int f) {
    REAL(recv);
    ssize_t r = real_recv(fd, b, n, f);
    int e = errno;
    if (traced(fd)) {
        errno = e;
        out_bytes("recv", fd, b, r);
    }
    errno = e;
    return r;
}
ssize_t recvfrom(int fd, void *b, size_t n, int f, struct sockaddr *a, socklen_t *l) {
    REAL(recvfrom);
    ssize_t r = real_recvfrom(fd, b, n, f, a, l);
    int e = errno;
    if (traced(fd)) {
        errno = e;
        out_bytes("recv", fd, b, r);
    }
    errno = e;
    return r;
}
ssize_t recvmsg(int fd, struct msghdr *m, int f) {
    REAL(recvmsg);
    ssize_t r = real_recvmsg(fd, m, f);
    int e = errno;
    T("t recvmsg fd=%d ret=%zd\n", fd, r);
    errno = e;
    return r;
}
ssize_t readv(int fd, const struct iovec *v, int c) {
    REAL(readv);
    ssize_t r = real_readv(fd, v, c);
    int e = errno;
    T("t readv fd=%d ret=%zd\n", fd, r);
    errno = e;
    return r;
}

#define OPEN_WRAP(name)                                                                            \
    int name(const char *p, int fl, ...) {                                                         \
        REAL(name);                                                                                \
        mode_t m = 0;                                                                              \
        if (fl & (O_CREAT | O_TMPFILE)) {                                                          \
            va_list ap;                                                                            \
            va_start(ap, fl);                                                                      \
            m = va_arg(ap, int);                                                                   \
            va_end(ap);                                                                            \
        }                                                                                          \
        T("t open path=%s\n", p);                                                                  \
        return real_##name(p, fl, m);                                                              \
    }
OPEN_WRAP(open)
OPEN_WRAP(open64)
#define OPENAT_WRAP(name)                                                                          \
    int name(int d, const char *p, int fl, ...) {                                                  \
        REAL(name);                                                                                \
        mode_t m = 0;                                                                              \
        if (fl & (O_CREAT | O_TMPFILE)) {                                                          \
            va_list ap;                                                                            \
            va_start(ap, fl);                                                                      \
            m = va_arg(ap, int);                                                                   \
            va_end(ap);                                                                            \
        }                                                                                          \
        T("t open path=%s\n", p);                                                                  \
        return real_##name(d, p, fl, m);                                                           \
    }
OPENAT_WRAP(openat)
OPENAT_WRAP(openat64)
FILE *fopen(const char *p, const char *m) {
    REAL(fopen);
    T("t open path=%s\n", p ? p : "(null)");
    return real_fopen(p, m);
}
FILE *fopen64(const char *p, const char *m) {
    REAL(fopen64);
    T("t open path=%s\n", p ? p : "(null)");
    return real_fopen64(p, m);
}

/* ------------------------------------------------------------------ */

static void *module;
static size_t buflen = 65536;
static char *buf;
static double t0;
static int base_socks;
static int open_sockets(void);

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void begin(void) {
    tlen = 0;
    tbuf[0] = 0;
    memset(socks, 0, sizeof socks);
    free(buf);
    buf = malloc(buflen ? buflen : 1);
    memset(buf, 0xAA, buflen);
    base_socks = open_sockets();
    t0 = now_ms();
    tracing = 1;
}

static int open_sockets(void) {
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    struct dirent *e;
    char p[300], l[128];
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof p, "/proc/self/fd/%s", e->d_name);
        ssize_t k = readlink(p, l, sizeof l - 1);
        if (k > 0) {
            l[k] = 0;
            if (strncmp(l, "socket:", 7) == 0) n++;
        }
    }
    closedir(d);
    return n;
}

static void end(void) {
    tracing = 0;
    printf("elapsed_ms=%.0f\n", now_ms() - t0);
    fputs(tbuf, stdout);
    printf("sockets_left=%d\n", open_sockets() - base_socks);
}

static int inbuf(const void *p, size_t n) {
    return (const char *)p >= buf && (const char *)p + n <= buf + buflen;
}

static void *sym(const char *n) {
    if (!module) {
        const char *m = getenv("PTNSS_MODULE");
        module = dlopen(m ? m : "libnss_peios_net.so.2", RTLD_NOW | RTLD_GLOBAL);
        if (!module) {
            printf("error=dlopen %s\n", dlerror());
            exit(3);
        }
    }
    void *f = dlsym(module, n);
    if (!f) {
        printf("error=dlsym %s\n", n);
        exit(3);
    }
    return f;
}

static char namebuf[512];
static const char *name_arg(const char *a) {
    if (strcmp(a, "@null") == 0) return NULL;
    if (strncmp(a, "@hex:", 5) == 0) {
        const char *h = a + 5;
        size_t i = 0;
        for (; h[0] && h[1] && i < sizeof namebuf - 1; h += 2) {
            unsigned v;
            sscanf(h, "%2x", &v);
            namebuf[i++] = v;
        }
        namebuf[i] = 0;
        return namebuf;
    }
    return a;
}

static void addr_text(int af, const void *a, char *out) {
    if (!inet_ntop(af, a, out, INET6_ADDRSTRLEN)) strcpy(out, "?");
}

#define SENT (-77)

static void print_hostent(int st, int err, int herr, struct hostent *h, int ttl, char *canon) {
    printf("status=%d errno=%d herrno=%d ttl=%d\n", st, err, herr, ttl);
    if (st != NSS_STATUS_SUCCESS) return;
    int ok = inbuf(h->h_name, strlen(h->h_name) + 1) && inbuf(h->h_aliases, sizeof(char *)) &&
             inbuf(h->h_addr_list, sizeof(char *));
    printf("h_name=%s\n", h->h_name);
    printf("addrtype=%d length=%d\n", h->h_addrtype, h->h_length);
    int na = 0;
    for (char **a = h->h_aliases; a && *a; a++) {
        na++;
        ok = ok && inbuf(a + 1, sizeof(char *)) && inbuf(*a, strlen(*a) + 1);
        printf("alias=%s\n", *a);
    }
    printf("aliases=%d\n", na);
    for (char **a = h->h_addr_list; a && *a; a++) {
        char t[INET6_ADDRSTRLEN];
        ok = ok && inbuf(a + 1, sizeof(char *)) && inbuf(*a, h->h_length);
        addr_text(h->h_length == 16 ? AF_INET6 : AF_INET, *a, t);
        printf("addr=%s\n", t);
    }
    if (canon) printf("canon_is_h_name=%d\n", canon == h->h_name);
    printf("inbuf=%d\n", ok);
}

typedef enum nss_status (*fn4)(const char *, struct gaih_addrtuple **, char *, size_t, int *, int *,
                               int32_t *);
typedef enum nss_status (*fn3)(const char *, int, struct hostent *, char *, size_t, int *, int *,
                               int32_t *, char **);
typedef enum nss_status (*fn2)(const char *, int, struct hostent *, char *, size_t, int *, int *);
typedef enum nss_status (*fn1)(const char *, struct hostent *, char *, size_t, int *, int *);
typedef enum nss_status (*fa2)(const void *, socklen_t, int, struct hostent *, char *, size_t,
                               int *, int *, int32_t *);
typedef enum nss_status (*fa1)(const void *, socklen_t, int, struct hostent *, char *, size_t,
                               int *, int *);

static int op(char **a, int n) {
    const char *o = a[0];
    int err = SENT, herr = SENT;
    int32_t ttl = SENT;
    struct hostent h;
    memset(&h, 0, sizeof h);
    printf("op=%s\n", o);
    if (!strcmp(o, "n4") && n >= 2) {
        fn4 f = sym("_nss_peios_net_gethostbyname4_r");
        struct gaih_addrtuple *pat = NULL;
        begin();
        int st = f(name_arg(a[1]), &pat, buf, buflen, &err, &herr, &ttl);
        end();
        printf("status=%d errno=%d herrno=%d ttl=%d\n", st, err, herr, ttl);
        if (st == NSS_STATUS_SUCCESS) {
            int ok = 1, shared = 1;
            char *first = pat ? pat->name : NULL;
            if (first) {
                ok = inbuf(first, strlen(first) + 1);
                printf("name=%s\n", first);
            }
            for (struct gaih_addrtuple *t = pat; t; t = t->next) {
                char s[INET6_ADDRSTRLEN];
                ok = ok && inbuf(t, sizeof *t);
                if (t->name != first) shared = 0;
                addr_text(t->family, t->addr, s);
                printf("tuple family=%d addr=%s scopeid=%u\n", t->family, s, t->scopeid);
            }
            printf("name_shared=%d\ninbuf=%d\n", shared, ok);
        }
    } else if (!strcmp(o, "n3") && n >= 3) {
        fn3 f = sym("_nss_peios_net_gethostbyname3_r");
        char *canon = (char *)1;
        begin();
        int st = f(name_arg(a[1]), atoi(a[2]), &h, buf, buflen, &err, &herr, &ttl, &canon);
        end();
        print_hostent(st, err, herr, &h, ttl, canon);
    } else if (!strcmp(o, "n2") && n >= 3) {
        fn2 f = sym("_nss_peios_net_gethostbyname2_r");
        begin();
        int st = f(name_arg(a[1]), atoi(a[2]), &h, buf, buflen, &err, &herr);
        end();
        print_hostent(st, err, herr, &h, ttl, NULL);
    } else if (!strcmp(o, "n1") && n >= 2) {
        fn1 f = sym("_nss_peios_net_gethostbyname_r");
        begin();
        int st = f(name_arg(a[1]), &h, buf, buflen, &err, &herr);
        end();
        print_hostent(st, err, herr, &h, ttl, NULL);
    } else if ((!strcmp(o, "a2") || !strcmp(o, "a1")) && n >= 2) {
        unsigned char addr[16];
        int af = AF_INET, len = 4;
        const void *ap = addr;
        memset(addr, 0, sizeof addr);
        if (!strcmp(a[1], "@null")) ap = NULL;
        else if (inet_pton(AF_INET, a[1], addr) == 1) {
            af = AF_INET;
            len = 4;
        } else if (inet_pton(AF_INET6, a[1], addr) == 1) {
            af = AF_INET6;
            len = 16;
        } else {
            printf("error=bad address\n");
            return 2;
        }
        if (n >= 4) {
            af = atoi(a[2]);
            len = atoi(a[3]);
        }
        int st;
        if (!strcmp(o, "a2")) {
            fa2 f = sym("_nss_peios_net_gethostbyaddr2_r");
            begin();
            st = f(ap, len, af, &h, buf, buflen, &err, &herr, &ttl);
        } else {
            fa1 f = sym("_nss_peios_net_gethostbyaddr_r");
            begin();
            st = f(ap, len, af, &h, buf, buflen, &err, &herr);
        }
        end();
        print_hostent(st, err, herr, &h, ttl, NULL);
    } else if (!strcmp(o, "gai") && n >= 3) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = atoi(a[2]);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_CANONNAME;
        begin();
        int r = getaddrinfo(name_arg(a[1]), NULL, &hints, &res);
        end();
        printf("gai=%d gaistr=%s\n", r, gai_strerror(r));
        int k = 0;
        for (struct addrinfo *i = res; i; i = i->ai_next) {
            char s[INET6_ADDRSTRLEN];
            if (i->ai_canonname) printf("canon=%s\n", i->ai_canonname);
            if (i->ai_family == AF_INET)
                addr_text(AF_INET, &((struct sockaddr_in *)i->ai_addr)->sin_addr, s);
            else addr_text(AF_INET6, &((struct sockaddr_in6 *)i->ai_addr)->sin6_addr, s);
            printf("addr=%s\n", s);
            k++;
        }
        printf("count=%d\n", k);
        if (res) freeaddrinfo(res);
    } else if (!strcmp(o, "ghbn") && n >= 3) {
        struct hostent *res = NULL;
        int he = SENT;
        begin();
        int r = gethostbyname2_r(name_arg(a[1]), atoi(a[2]), &h, buf, buflen, &res, &he);
        end();
        printf("ret=%d herrno=%d found=%d\n", r, he, res != NULL);
        h_errno = SENT;
        struct hostent *g = gethostbyname2(name_arg(a[1]), atoi(a[2]));
        int k = 0;
        if (g)
            for (char **x = g->h_addr_list; *x; x++) k++;
        printf("growing_found=%d growing_herrno=%d growing_count=%d\n", g != NULL, g ? 0 : h_errno,
               k);
    } else if (!strcmp(o, "ghba") && n >= 2) {
        unsigned char addr[16];
        int af = AF_INET, len = 4;
        if (inet_pton(AF_INET, a[1], addr) != 1) {
            af = AF_INET6;
            len = 16;
            inet_pton(AF_INET6, a[1], addr);
        }
        h_errno = SENT;
        begin();
        struct hostent *g = gethostbyaddr(addr, len, af);
        end();
        printf("found=%d herrno=%d\n", g != NULL, g ? 0 : h_errno);
        if (g) printf("h_name=%s\n", g->h_name);
    } else if (!strcmp(o, "cfg") && n >= 3) {
        printf("ret=%d\n", __nss_configure_lookup(a[1], a[2]));
    } else if (!strcmp(o, "identity")) {
        struct passwd *pw = getpwnam("pt-nss-user");
        if (!pw) {
            printf("error=no test passwd entry\n");
            return 2;
        }
        uid_t uid = pw->pw_uid;
        char *name = strdup(pw->pw_name);
        pw = getpwnam(name);
        printf("by_name=%d\n", pw && pw->pw_uid == uid);
        pw = getpwuid(uid);
        printf("by_id=%d\n", pw && !strcmp(pw->pw_name, name));
        free(name);
        struct group *gr = getgrnam("pt-nss-group");
        if (!gr) {
            printf("error=no test group entry\n");
            return 2;
        }
        gid_t gid = gr->gr_gid;
        name = strdup(gr->gr_name);
        gr = getgrnam(name);
        printf("group_by_name=%d\n", gr && gr->gr_gid == gid);
        gr = getgrgid(gid);
        printf("group_by_id=%d\n", gr && !strcmp(gr->gr_name, name));
        free(name);
        void *identity = dlopen("libnss_peios.so.2", RTLD_NOW | RTLD_NOLOAD);
        void *gcc = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_NOLOAD);
        printf("identity_loaded=%d gcc_loaded=%d\n", identity != NULL, gcc != NULL);
        if (identity) dlclose(identity);
        if (gcc) dlclose(gcc);
    } else if (!strcmp(o, "where")) {
        void *m = dlopen("libnss_peios_net.so.2", RTLD_NOW | RTLD_NOLOAD);
        void *c = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
        struct link_map *lm;
        if (m && dlinfo(m, RTLD_DI_LINKMAP, &lm) == 0) printf("module=%s\n", lm->l_name);
        else printf("module=(not loaded)\n");
        if (c && dlinfo(c, RTLD_DI_LINKMAP, &lm) == 0) printf("libc=%s\n", lm->l_name);
    } else if (!strcmp(o, "elf") && n >= 2) {
        FILE *f = fopen(a[1], "rb");
        if (!f) {
            printf("error=open %s\n", strerror(errno));
            return 2;
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz);
        if (fread(b, 1, sz, f) != (size_t)sz) {
            printf("error=read\n");
            return 2;
        }
        fclose(f);
        Elf64_Ehdr *e = (void *)b;
        Elf64_Shdr *s = (void *)(b + e->e_shoff);
        for (int i = 0; i < e->e_shnum; i++) {
            if (s[i].sh_type == SHT_DYNAMIC) {
                const char *str = (const char *)b + s[s[i].sh_link].sh_offset;
                for (Elf64_Dyn *d = (void *)(b + s[i].sh_offset); d->d_tag != DT_NULL; d++) {
                    if (d->d_tag == DT_NEEDED) printf("needed=%s\n", str + d->d_un.d_val);
                    if (d->d_tag == DT_SONAME) printf("soname=%s\n", str + d->d_un.d_val);
                }
            }
            if (s[i].sh_type == SHT_DYNSYM) {
                const char *str = (const char *)b + s[s[i].sh_link].sh_offset;
                Elf64_Sym *y = (void *)(b + s[i].sh_offset);
                size_t k = s[i].sh_size / sizeof *y;
                for (size_t j = 0; j < k; j++) {
                    int bind = ELF64_ST_BIND(y[j].st_info), type = ELF64_ST_TYPE(y[j].st_info);
                    if (y[j].st_shndx != SHN_UNDEF && (bind == STB_GLOBAL || bind == STB_WEAK) &&
                        ELF64_ST_VISIBILITY(y[j].st_other) == STV_DEFAULT)
                        printf("export=%s type=%s\n", str + y[j].st_name,
                               type == STT_FUNC ? "func" : "other");
                }
            }
        }
        free(b);
    } else if (!strcmp(o, "wait") && n >= 2) {
        struct stat st;
        for (int i = 0; i < 600 && stat(a[1], &st) != 0; i++) usleep(50000);
        printf("waited=%d\n", stat(a[1], &st) == 0);
    } else if (!strcmp(o, "touch") && n >= 2) {
        FILE *f = fopen(a[1], "w");
        if (f) fclose(f);
        printf("touched=%d\n", f != NULL);
    } else if (!strcmp(o, "sleep") && n >= 2) {
        usleep(atoi(a[1]) * 1000);
    } else {
        printf("error=bad op\n");
        return 2;
    }
    fflush(stdout);
    return 0;
}

static pid_t fake_pid;
static char fake_path[108];

static void fake(const char *mode) {
    snprintf(fake_path, sizeof fake_path, "/tmp/ptnss-%d.sock", getpid());
    unlink(fake_path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un u;
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    strcpy(u.sun_path, fake_path);
    if (bind(ls, (void *)&u, sizeof u) || listen(ls, 8)) {
        printf("error=fake bind %s\n", strerror(errno));
        exit(3);
    }
    fflush(stdout);
    fake_pid = fork();
    if (fake_pid == 0) {
        in_child = 1;
        for (;;) {
            int c = accept(ls, NULL, NULL);
            if (c < 0) continue;
            unsigned char hdr[4];
            size_t got = 0;
            while (got < 4) {
                ssize_t r = read(c, hdr + got, 4 - got);
                if (r <= 0) break;
                got += r;
            }
            uint32_t len = hdr[0] | hdr[1] << 8 | hdr[2] << 16 | (uint32_t)hdr[3] << 24;
            char tmp[4096];
            while (got >= 4 && len > 0) {
                ssize_t r = read(c, tmp, len < sizeof tmp ? len : sizeof tmp);
                if (r <= 0) break;
                len -= r;
            }
            if (!strcmp(mode, "silent")) {
                sleep(60);
            } else if (!strncmp(mode, "hex:", 4)) {
                const char *h = mode + 4;
                size_t k = strlen(h) / 2;
                unsigned char *o = malloc(k + 1);
                for (size_t i = 0; i < k; i++) {
                    unsigned v;
                    sscanf(h + 2 * i, "%2x", &v);
                    o[i] = v;
                }
                size_t off = 0;
                while (off < k) {
                    ssize_t r = write(c, o + off, k - off);
                    if (r <= 0) break;
                    off += r;
                }
                free(o);
            }
            close(c);
        }
    }
    close(ls);
    strcpy(redirect, fake_path);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    if (getenv("PTNSS_BUF")) buflen = strtoul(getenv("PTNSS_BUF"), NULL, 0);
    if (getenv("PTNSS_FAKE")) fake(getenv("PTNSS_FAKE"));
    int rc = 0, i = 1;
    while (i < argc) {
        int j = i;
        while (j < argc && strcmp(argv[j], "+")) j++;
        rc |= op(argv + i, j - i);
        i = j + 1;
    }
    fflush(stdout);
    if (fake_pid > 0) {
        kill(fake_pid, SIGKILL);
        waitpid(fake_pid, NULL, 0);
        unlink(fake_path);
    }
    return rc;
}
