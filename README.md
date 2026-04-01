# mping

**mping** is a command-line tool that sends **ICMP echo requests** to **many hosts in round-robin** (up to 500), using **IPv4 and/or IPv6**. It was developed by **UNINETT** (Norway) and released as free software (GPLv2+). This tree is **v3.00 rc1** (circa 2005), with small portability fixes so it builds cleanly on **macOS** and **Linux**.

Unlike the usual `ping`, mping multiplexes one (or two) raw ICMP sockets across a whole host list and prints per-reply lines plus **per-host statistics** (loss, RTT min/avg/max/stddev, optional median or percentiles).

## Requirements

- A **C compiler** (`cc`, `clang`, or `gcc`)
- **Raw ICMP** access: on most systems you must run as **root** or grant **`CAP_NET_RAW`** (Linux) / equivalent, or use macOS mechanisms appropriate for your OS version for ICMP sockets.

## Build

```sh
make
```

This produces the `mping` binary in the source directory.

Optional overrides (same Makefile works on macOS and Linux):

```sh
make CC=gcc CFLAGS='-O2 -Wall -Wextra'
make PROG=mping-custom   # different output binary name
```

## Install

```sh
sudo make install
```

Default layout:

- Binary: `$(PREFIX)/bin/mping` — default `PREFIX` is `/usr/local`
- Manual: `$(PREFIX)/share/man/man8/mping.8`

Staging and custom prefixes:

```sh
make install DESTDIR=/tmp/stage PREFIX=/usr
make install PREFIX="$HOME/.local"
```

Uninstall:

```sh
sudo make uninstall
```

`make help` lists variables and targets.

## Usage (summary)

Full detail is in **`mping.8`** (`man ./mping.8` from the source tree, or `man mping` after install).

```text
mping [-hrln46ktTqvSmfV] [-c count] [-i interval] [-s packetsize] [-w deadline]
      [-W waittime] [-e ttl] [-p|-P -a mean -b truncated] [-F hostfile] host1 host2 ...
```

**Examples**

```sh
# Ping three hosts (often requires root)
sudo ./mping -c 5 example.com 127.0.0.1 ::1

# Host list from file, numeric output only, 200 ms between sends
sudo ./mping -n -i 200 -F hosts.txt

# IPv6 only, quiet, with deadline
sudo ./mping -6 -q -w 30 host1 host2

# Help
./mping -h
```

Notable options (see the man page for the full list):

| Option | Meaning |
|--------|---------|
| `-h` | Print usage and exit |
| `-c count` | Stop after *count* echo requests **per host** |
| `-i msec` | Milliseconds between packets (default 100) |
| `-w sec` | Wall-clock deadline before exit |
| `-W sec` | Seconds to wait for stray replies after the last send (`alarm(3)`; see man page) |
| `-n` | Numeric addresses only (no reverse DNS) |
| `-4` / `-6` | Use **only** IPv4 or **only** IPv6 when resolving. With neither, if both exist, the **first IPv4** result is used (often closer to plain `ping` on dual-stack names such as `.local`). |
| `-F file` | Read hostnames/addresses from file (lines, `#` comments ok) |
| `-m` / `-f` | Median or percentile-style RTT summaries |
| `-q` / `-v` | Quiet or verbose |
| `-V` | Print version and exit |

## Behaviour (high level)

This tree includes fixes beyond the original UNINETT 3.0 rc1 tarball: for example **IPv6 hop limit** and **IPv4 TTL** on receive (via `recvmsg` control messages), **kernel timestamps** when `-k` is set, **retry of failed `getaddrinfo`** for hosts that start unresolved, **non-blocking raw sockets** with receive **draining** after `select`, **per-host send counts** for loss statistics, and **IPv6 echo payload layout** aligned with IPv4 when timing is enabled. **CHANGELOG.md** has the full list.

## Optional / future work

Ideas not implemented here; contributions welcome:

- Clearer display when **user-supplied names**, **canonical names**, and **resolved addresses** differ.
- **Packed output** (`-S`) could include **IPv6 hop count** for parity with the IPv4 TTL field.
- **Safe duplicate reply detection** (e.g. per-host sequence tracking) without the old mod-100 hash that could mis-classify distinct replies.

## Project layout

| File | Purpose |
|------|---------|
| `mping.c` | Implementation |
| `mping.h` | Headers and constants |
| `mping.8` | Manual page |
| `Makefile` | Build and install |
| `CHANGELOG.md` | Changes in this tree versus the v3.0 rc1 baseline |

## License

GPLv2 or later — see the copyright blocks in `mping.c` and `mping.h`.
