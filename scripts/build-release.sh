#!/usr/bin/env bash
# Build portable release tarballs for TunnelMate.
#
#   sudo ./scripts/build-release.sh                    # host architecture
#   sudo ./scripts/build-release.sh x86_64 aarch64     # both
#
# Each tarball holds tunnelmate-agent, tunnelmate-peer and tunnelmated linked
# fully statically against musl, so they run on any Linux with a matching CPU:
# no libuv, no OpenSSL, no glibc version to match.
#
# musl rather than glibc because a statically linked glibc binary still dlopens
# NSS modules inside getaddrinfo(), so it cannot resolve a hostname on a host
# whose glibc differs from the build machine's. musl resolves DNS in-process.
#
# The build runs inside a throwaway Alpine chroot under work/, which is deleted
# afterwards; nothing is installed on the host. Building for an architecture
# other than the host's needs qemu-user (Debian/Ubuntu: qemu-user, or
# qemu-user-static) and is emulated, so it is slow but needs no cross-toolchain.
set -euo pipefail

VERSION="${TUNNELMATE_VERSION:-0.1.0}"
ALPINE_BRANCH="${TUNNELMATE_ALPINE:-v3.22}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$REPO_ROOT/dist"
WORK="$DIST/work"

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root: the build uses chroot" >&2
  exit 1
fi

SOURCE_URL="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
SOURCE_URL="${SOURCE_URL:-https://github.com/hamimmahmud0/frpc-broker}"

cleanup() {
  # Order matters and lazy is deliberate: a chroot that is still busy would
  # otherwise leave the bind mounts behind.
  for m in dev proc; do
    umount -lf "$ROOTFS/$m" 2>/dev/null || true
  done
}
trap cleanup EXIT

register_binfmt() {
  local arch="$1" magic mask
  [ -e "/proc/sys/fs/binfmt_misc/qemu-$arch" ] && return 0
  case "$arch" in
    aarch64)
      magic='\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00'
      mask='\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff'
      ;;
    *)
      echo "no binfmt recipe for $arch; install a distro qemu-user-binfmt package" >&2
      return 1
      ;;
  esac
  command -v "qemu-$arch" >/dev/null || {
    echo "qemu-$arch not found; install qemu-user" >&2
    return 1
  }
  # OCF: O=open the interpreter now, C=credentials from the target, F=keep the
  # interpreter fd. F is what lets it run binaries inside a chroot that has no
  # copy of qemu in it.
  printf ':qemu-%s:M::%s:%s:%s:OCF\n' "$arch" "$magic" "$mask" "$(command -v "qemu-$arch")" \
    > /proc/sys/fs/binfmt_misc/register
}

write_readme() {
  local path="$1" arch="$2"
  # Shipped inside the tarball: someone who downloads it months from now has
  # only what is in it, so it repeats the essentials rather than linking out.
  cat > "$path" <<README
# TunnelMate $VERSION — linux-$arch

Static binaries. They depend on nothing: no libuv, no OpenSSL, no glibc
version to match. Any Linux kernel on $arch will run them.

| Binary | Who needs it |
|---|---|
| \`tunnelmate-agent\` | Anyone publishing a local service through a broker. |
| \`tunnelmate-peer\` | Anyone consuming a **closed** tunnel. Open tunnels need no client at all. |
| \`tunnelmated\` | Only the operator of a broker. |

## Install

    sudo install -m 0755 tunnelmate-agent tunnelmate-peer /usr/local/bin/

Verify the download first, from the directory holding SHA256SUMS:

    sha256sum -c --ignore-missing SHA256SUMS

## Use

Point them at a broker; a broker's own \`/llms.txt\` carries the full setup:

    curl -fsS http://YOUR-BROKER/llms.txt

The agent takes a config file and nothing else — the flag is \`-c\`, with one
dash, and secrets never go on the command line because any local user can read
\`/proc/PID/cmdline\`.

    tunnelmate-agent -c ./agent.conf

## Source

$SOURCE_URL

Built against Alpine $ALPINE_BRANCH (musl) with \`-DTUNNELMATE_STATIC=ON\`.
README
}

build_one() {
  local arch="$1"
  ROOTFS="$WORK/$arch"
  cleanup
  rm -rf "$ROOTFS"
  mkdir -p "$ROOTFS"

  if [ "$arch" != "$(uname -m)" ]; then
    echo ">>> $arch is not the host architecture; registering qemu"
    register_binfmt "$arch"
  fi

  local base="https://dl-cdn.alpinelinux.org/alpine/$ALPINE_BRANCH/releases/$arch"
  local tarball
  tarball=$(curl -fsS "$base/" \
    | grep -o "alpine-minirootfs-[0-9.]*-$arch\.tar\.gz" | sort -V | tail -1)
  [ -n "$tarball" ] || { echo "no minirootfs for $arch" >&2; return 1; }
  echo ">>> $arch: $tarball"
  curl -fsSL "$base/$tarball" | tar -xz -C "$ROOTFS"

  cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
  mount -t proc none "$ROOTFS/proc"
  mount --rbind /dev "$ROOTFS/dev"
  # Without this the later umount propagates back through the bind and tears
  # down the host's own mounts. /sys is deliberately never bound for the same
  # reason: unmounting a bound /sys takes cgroup2 with it and breaks systemd.
  mount --make-rslave "$ROOTFS/dev"

  mkdir -p "$ROOTFS/build"
  for item in CMakeLists.txt common broker agent peer LICENSE; do
    cp -r "$REPO_ROOT/$item" "$ROOTFS/build/"
  done

  # A file rather than a here-doc on stdin, so this still works when the caller
  # invoked us through something that owns stdin.
  cat > "$ROOTFS/build/inner.sh" <<'INNER'
set -eu
apk add --no-cache build-base cmake pkgconf linux-headers \
    openssl-dev openssl-libs-static libuv-dev libuv-static file
cd /build
cmake -S . -B out -DCMAKE_BUILD_TYPE=Release -DTUNNELMATE_STATIC=ON \
    -DCMAKE_EXE_LINKER_FLAGS=-s
cmake --build out --parallel "$(nproc)"
for b in out/broker/tunnelmated out/agent/tunnelmate-agent out/peer/tunnelmate-peer; do
  file "$b"
  # A binary that kept an interpreter would fail on the user's machine rather
  # than here, which is far more expensive to discover.
  file "$b" | grep -q "statically linked" || { echo "NOT STATIC: $b" >&2; exit 1; }
done
# Passing here means the static OpenSSL and libuv are functional, not merely
# present, and that the binaries can actually start.
ctest --test-dir out --output-on-failure
out/agent/tunnelmate-agent --unknown-flag 2>&1 | grep -q usage
out/peer/tunnelmate-peer 2>&1 | grep -qi usage
INNER
  chroot "$ROOTFS" /bin/sh /build/inner.sh

  local name="tunnelmate-$VERSION-linux-$arch"
  local stage="$DIST/$name"
  rm -rf "$stage"; mkdir -p "$stage"
  cp "$ROOTFS/build/out/broker/tunnelmated" \
     "$ROOTFS/build/out/agent/tunnelmate-agent" \
     "$ROOTFS/build/out/peer/tunnelmate-peer" "$stage/"
  cp "$REPO_ROOT/LICENSE" "$stage/LICENSE"
  write_readme "$stage/README.md" "$arch"
  chmod 0755 "$stage"/tunnelmated "$stage"/tunnelmate-agent "$stage"/tunnelmate-peer
  chmod 0644 "$stage/LICENSE" "$stage/README.md"

  tar -C "$DIST" -czf "$DIST/$name.tar.gz" "$name"
  rm -rf "$stage"
  cleanup
  # Each rootfs is several hundred MB with the toolchain in it, so drop this
  # one before starting the next architecture rather than at the very end.
  rm -rf "$ROOTFS"
}

arches=("$@")
if [ ${#arches[@]} -eq 0 ]; then
  arches=("$(uname -m)")
fi

rm -rf "$DIST"
mkdir -p "$WORK"
for arch in "${arches[@]}"; do
  build_one "$arch"
done
rm -rf "$WORK"

# Relative paths, so `sha256sum -c` works from inside the download directory.
(cd "$DIST" && sha256sum ./*.tar.gz > SHA256SUMS)

echo
echo "dist/:"
ls -l "$DIST"
cat "$DIST/SHA256SUMS"
