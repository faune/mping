# Changelog

All notable changes are documented here. This repository includes **Mping v3.00 rc1** (UNINETT, 2005) as the upstream baseline, plus a portability and hardening fork.

The **verbatim Norwegian** release notes from UNINETT are still in the file **`Changelog`** in the repository root. The section below records the **same items in English** so one file is enough for most readers.

---

## Mping v3.0 rc1 — upstream release (UNINETT, ~2005)

*Source: original `Changelog`.*

### Features and behaviour

- Timestamping for **individual packets** and for **bursts**; date format is easy to adjust in code.
- **Poisson-distributed** intervals with user-defined mean **m** and **truncation**; Poisson applies to bursts and/or packets so a poll window can run for a user-defined duration, with timestamps and longer gaps to improve **median** estimates.
- Dedicated **`poissonsleep`** routine for sleeping between events.
- **Pre-fire** (`-l`): send one packet to each host before statistics to reduce **ARP cache** effects on first RTT.
- **TTL / hop limit** for IPv4 and IPv6, with verbose ICMP/IP details (e.g. time exceeded). *(Original note: IPv6 TTL was not printed to stdout though the limit was applied; this fork later adds hop-limit printing via `recvmsg`.)*
- **Deadline** (`-w`): wall-clock limit on how long **mping** keeps polling.
- **Name resolution** reworked with a protocol-independent **`pr_addr`**-style path.
- Switched option parsing to **`getopt`** — more robust; options were **reorganised and regrouped** (**behaviour changed vs older releases**).
- Broader **error handling**, including reading the host list from a file (`-F`).
- **Standard deviation** replaces an older cube-sum approach (per Olav); includes a **integer square root** helper for stddev.
- **ICMP error types** for IPv4 and IPv6 fleshed out in verbose output.
- **`-4` / `-6`**: if the preferred family fails to resolve, **fall back** to the other (e.g. `-6` still tries IPv4 when no IPv6 exists).
- All declarations/definitions moved into **`mping.h`**; **dead/commented code** removed from the tree (historical versions in CVS).
- Timing display uses **milliseconds only** (no auto scaling to µs/s); older behaviour lived in CVS.
- **Man page** updated; sources stamped as **v3.0**.

<details>
<summary>Original Norwegian text (same as file <code>Changelog</code>)</summary>

```
Mping v3.0 rc1

- Støtte for tidsstempling av både enkeltpakker og burst
- Funksjon for tidsstempel implementert, der datoformat kan enkelt endres hvis ønskelig
- Poisson fordelte intervaller, med brukerdefinert m og trunkering
- Poisson-fordeling av både skurer og pakker
- Som betyr: En polleperiode kan vare i brukerdefinert tid, og gir både tidsstempling av pakker/bursts og
  lengre intervaller for bedre median-beregning.
- egen poissonsleep funksjon implementert for soverutine
- Pre-fire mot alle hosts før statistikksamling begynner - forhindre ARP cache påvirkning (?).
- TTL implementert for IPv4/IPv6, med verbose IP header info for time exceed bl.a. (Skriver ikke ut ttl for
  ipv6, men limiten virker...)
- Implementert deadline som spesifiserer hvor lenge mping skal polle
- Navnehåndtering og oppslag gjøres nå riktig(TM), med en egen protokolluavhengig funksjon.
- byttet til getopt for å lese inn opsjoner, så nå er denne biten mye mer robust og sikker. Mer vanskelig å manipulere opsjonshåndtering.
- samtidig med bytte til getopt, ble opsjoner ryddet opp i og kategorisert/gjort mer logisk.
  DETTE MEDFØRER AT NOE ER FORANDRET JFT TIDLIGERE!
- Lagt til bedre og mer robust feilhåndtering stort sett overalt, også for innlesing av hostliste for fil.
- Fjernet all utkommentert og gammel kode - hører hjemme i CVS, jfr. JK :)
- Lagt til standard-avvik istedet for cube-sum, jfr ønske fra Olav.
- Kvadratrot-funksjon for standard-avvik beregning.
- Implementerte resterende ICMP header feilmeldinger for IPv4/6
- Fikset bug der en -6 eller -4 opsjon kun pinget oppgitte hosts som resolvet til oppgitt protokollversjon. Hvis man
  nå sier at man primært ønsker IPv6 addresser, med -6 opsjon, så vil mping prøve med IPv4 for addresser som ikke har
  en gyldig IPv6 addresse.
- Flyttet alle funksjonersinitialiseringer og definisjoner til en egen mping.h header fil
- Fjernet autoskalering av tid til usec/msec/sec til fordel for bare msec (mer ryddig, og nytteverdien var lav da msec er defacto std.
  Bruk CVS-koden for eldre versjon hvis dette ønskes tilbake.
- Oppdaterte man-siden og stemplet koden som v3.0
```

</details>

---

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
- **Duplicate ICMP replies**: an earlier **`dupcheck()`** (mod-100 hash) was **removed** — it collided across different `(host, seq)` pairs and could mark **legitimate** replies as duplicates, inflating **packet loss**. True duplicates are uncommon for this tool’s use case.
- **`pr_pack6`**: host index bounds use **`hnum >= nhosts`** (inclusive upper bound fix).
- **Per-host `nsent[]`**: statistics use **actual successful `sendto` count** per host for **loss %** (not `ntransmitted` alone). Summary line clarifies **poll rounds** vs **sent** counts.
- **`ntransmitted--` on `EAGAIN`**: **removed** — it decremented the **round** counter and corrupted **ICMP sequence** and loss math.

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
- Original Norwegian **`Changelog`** file retained; its entries are summarized in English under **Mping v3.0 rc1 — upstream release** above.
- Original **`TODO`** remains in tree; items completed in this fork are noted in **`TODO`** and here.
