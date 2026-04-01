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
mping [-rln46ktTqvSmfV] [-c count] [-i interval] [-s packetsize] [-w deadline]
      [-W waittime] [-e ttl] [-p|-P -a mean -b truncated] [-F hostfile] host1 host2 ...
```

**Examples**

```sh
# Ping three hosts (often requires root)
sudo ./mping -c 5 example.com 127.0.0.1 ::1

# Host list from file, numeric output only, 200 ms between sends
sudo ./mping -n -i 200 -F hosts.txt

# Prefer IPv6, quiet, with deadline
sudo ./mping -6 -q -w 30 host1 host2
```

Notable options (see the man page for the full list):

| Option | Meaning |
|--------|---------|
| `-c count` | Stop after *count* echo requests **per host** |
| `-i msec` | Milliseconds between packets (default 100) |
| `-w sec` | Wall-clock deadline before exit |
| `-W msec` | Wait for stray replies after the last send |
| `-n` | Numeric addresses only (no reverse DNS) |
| `-4` / `-6` | Prefer IPv4 or IPv6 when resolving names |
| `-F file` | Read hostnames/addresses from file (lines, `#` comments ok) |
| `-m` / `-f` | Median or percentile-style RTT summaries |
| `-q` / `-v` | Quiet or verbose |
| `-V` | Print version and exit |

## Project layout

| File | Purpose |
|------|---------|
| `mping.c` | Implementation |
| `mping.h` | Headers and constants |
| `mping.8` | Manual page |
| `Makefile` | Build and install |
| `Changelog`, `TODO` | Historical project notes |

## License

GPLv2 or later — see the copyright blocks in `mping.c` and `mping.h`.
