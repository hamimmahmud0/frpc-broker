# Release binaries

The agent is a C program, so publishing a service normally means compiling one.
That is a real barrier: it needs a toolchain, and it needs OpenSSL 3.2, which
Ubuntu 24.04 LTS and Debian 12 do not ship. Release tarballs remove it — they
hold statically linked binaries that run on any Linux with a matching CPU.

## Building them

```bash
sudo ./scripts/build-release.sh                 # host architecture
sudo ./scripts/build-release.sh x86_64 aarch64  # both
```

Output lands in `dist/`:

```
tunnelmate-0.1.0-linux-x86_64.tar.gz
tunnelmate-0.1.0-linux-aarch64.tar.gz
SHA256SUMS
```

Each tarball contains `tunnelmate-agent`, `tunnelmate-peer`, `tunnelmated`,
`LICENSE` and a README.

Root is required because the build runs inside a throwaway Alpine chroot under
`dist/work/`, which is deleted afterwards. Nothing is installed on the host.
Set `TUNNELMATE_VERSION` to change the version in the filenames.

Each chroot is a few hundred megabytes with the toolchain unpacked, so run this
from a checkout on real disk. A checkout under a small `tmpfs` — `/tmp` is one
on many systems, often under 1 GB — fails partway through `apk add` with
"No space left on device".

### Why musl, not glibc

A statically linked *glibc* binary still `dlopen`s NSS modules inside
`getaddrinfo()`. It resolves nothing on a machine whose glibc differs from the
build host's — which is most of them — so `agent.broker_host` fails unless it
is a bare IP. musl resolves DNS in-process, so a musl static binary is portable
in the way the word implies.

This is what `-DTUNNELMATE_STATIC=ON` configures: static OpenSSL and libuv,
`-static` at link time, and archives-only library lookup so a stray `.so`
cannot sneak onto the link line.

### Cross-architecture

Building for an architecture other than the host's is emulated and needs
`qemu-user` (Debian/Ubuntu: `qemu-user` or `qemu-user-static`). The script
registers the binfmt handler itself if the distro has not. It is slow — a full
aarch64 build on an x86_64 box takes several minutes — but needs no
cross-toolchain.

The script never bind-mounts `/sys` into the chroot, and marks its `/dev` bind
`rslave`. Both matter: unmounting a bind-mounted `/sys` propagates back to the
host and takes cgroup2 with it, which stops systemd from starting any new unit
until it is remounted.

## Publishing them from a broker

Copy the tarballs and `SHA256SUMS` into the directory named by
`TUNNELMATE_RELEASE_DIR` (default `/var/lib/tunnelmate/releases`), readable by
the API user:

```bash
sudo install -m 0644 dist/*.tar.gz dist/SHA256SUMS /var/lib/tunnelmate/releases/
```

They are then served at:

```
GET /v1/downloads            JSON index: name, size, absolute url
GET /v1/download/{name}      one file
```

Both are public and unauthenticated, which is the point — the binaries are what
a new user needs before they have any credential at all.

`/llms.txt` picks this up automatically. It reads the directory when it renders
and names the exact files present, so the setup instructions cannot advertise a
download that does not exist. Publish nothing and the document tells readers to
build from source instead.

### What the download endpoint will not serve

The filename comes from the URL, so it is matched against
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` before it is joined to the release
directory, and the resolved path must be a direct child of that directory. That
rejects traversal, dotfiles, subdirectories, and a symlink pointing out of the
release directory.

Keep the release directory to release files. Everything in it that matches the
name pattern is public.
