# Changelog

All notable changes to this fork are documented here. The base is **Mping v3.00 rc1** (UNINETT, 2005).

## [Unreleased] — portability, features, and hardening fork

### Build and packaging

- **Makefile** reworked for **macOS** and **Linux**: `PREFIX`, `DESTDIR`, `BINDIR`, `MANDIR`, `CC`, `CFLAGS`, `CPPFLAGS`, `LDFLAGS`, `PROG`; portable `install` (no GNU-only `install -D`); `man` under `share/man/man8`.
- **`CFLAGS`**: `-fno-common` to avoid macOS **ld** warning on `__DATA,__common` alignment.
- Link **`-lm`** moved from `CFLAGS` to **`LDFLAGS`**.
- **`make help`** target.

### Documentation

- **`README.md`**: project description, build/install, privileges, usage summary, file layout, license pointer.

### Portability (Linux and macOS)

- Feature macros and headers: **`_GNU_SOURCE` / `_DEFAULT_SOURCE`** on Linux; **`<signal.h>`** instead of `<sys/signal.h>`.
- **ICMP** naming: **`ICMP_UNREACH_NEEDFRAG`** alias for Linux **`ICMP_FRAG_NEEDED`**; portable “need frag” MTU print without relying on union field names.
- **`getopt`**: **`break`** after **`-i`** (interval) so it no longer fell through into **`-w`**.
- **`read_nodefile`**: **`fopen`** failure uses **`fh == NULL`**, not **`errno`**.
- **`SO_DONTROUTE`**: error check uses **`-1`**, not **`== 1`**.
- **Bitmask**: **`!(options & F_PACKED)`** where **`!options &`** was wrong.
- **`prettydate`**: **`time(NULL)`** instead of invalid **`time((time_t)NULL)`** (macOS error).
- **`pr_addr`**: correct **`getnameinfo`** socket lengths; **`snprintf`**; **`const void *`** API; ICMP redirect via **`sockaddr_in`** for gateway.
- **`pr_icmph`**: embedded IP / options handling guarded by length checks; bogus **`ip_hl`** / payload length rejected under **`-v`**.
- **Receive path**: **`recvmsg`** with control messages for **IPv6 hop limit** (`IPV6_RECVHOPLIMIT` / `IPV6_HOPLIMIT`), **IPv4 TTL** (`IP_RECVTTL` where available), and **kernel timestamps** (`SO_TIMESTAMP` + **`SCM_TIMESTAMP`**) when **`-k`** is set.
- **IPv6**: print **`hops=N`** from ancillary data; **`-k`** applies to IPv6 socket as well.
- **Send buffers**: single **heap** `outpack` buffer instead of three huge static arrays (smaller **.bss**).
- **`tvsub`**: ANSI prototype; **`fputs`** for usage/version strings; sign-compare casts; **`finish`**: **`freeaddrinfo(res)`** only if **`res != NULL`**.

### TODO / behavior (from original `TODO`)

- **DNS retry**: hosts that fail **`getaddrinfo`** at startup stay in the list; **periodic retry** (default **30 s**) on round-robin turns; message **“DNS unresolved, will retry”**; main loop **sleeps** if no raw sockets exist yet (all hosts pending).
- **`hostnameresolv`**: stores **`ai_canonname`** when present; PING line shows **`stdin [canonical]: … to <addr>`**.
- **Duplicate ICMP replies**: **`dupcheck()`** keyed by host index and sequence; prints **`(DUP!)`** and skips stat updates.
- **`pr_pack6`**: host index bounds use **`hnum >= nhosts`** (inclusive upper bound fix).

### Security hardening

- **Host labels**: **`MPING_HOST_LABEL_LEN` (256)** for **`hostname` / `hostnameresolv` / `hnamebuf`**; **`copy_hostname_slot()`** via **`snprintf`** with truncation error; failed slot frees **`packet_time`** and skips host.
- **IPv4 echo reply**: reject **negative or out-of-range** embedded host slot **`hnum`** before touching **`nreceived[]` / stats arrays**.
- **`-c`**: reject **`npackets > MAXCOUNT` (65535)**; safe **`size_t`** sizing and overflow check for **`packet_time`** allocation.
- **`getaddrinfo` result**: reject **`ai_addrlen`** outside **`(0, sizeof(sockaddr_storage)]`** before **`memcpy`** to **`whereto`**.
- **`pr_iph`**: require minimum ICMP payload before reading embedded IP; validate **`hlen`** and total length before option dump.
- **`pr_addr`**: **two** rotating 4 KiB buffers so two addresses in one **`printf`** do not alias.

### Not in scope (documented limitations)

- No **privilege drop** after opening raw sockets (still full root/capabilities for process lifetime).
- Signal handlers still use **async-signal-unsafe** **`stdio`** / **`ualarm`** (legacy style; refactor would be larger).

### Upstream reference

- Original copyright and license: **GPLv2+** (see **`mping.c`** / **`mping.h`**).
- Original **`Changelog`** and **`TODO`** in tree; **`TODO`** updated to reflect completed items.
