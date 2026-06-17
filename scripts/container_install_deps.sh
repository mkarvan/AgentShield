#!/bin/sh
# =============================================================================
# AgentShield e2e harness — dependency installer
# =============================================================================
# Installs everything `scripts/container_e2e_test.sh` needs to exercise EVERY
# enforcement layer without environment-gated skips:
#
#   base system (via the distro package manager):
#     - C toolchain (cc/gcc + make)   -> execve interceptor build
#     - bash                          -> PATH-shim wrapper scripts (#!/usr/bin/env bash)
#     - python3 + pip                 -> CLI + plugin/DB drivers
#     - node + npm                    -> npm-family managers
#     - ruby (gem), go                -> unverifiable-manager coverage
#     - git, curl, ca-certificates, tar, unzip, xz
#
#   language-ecosystem tools (via official cross-distro installers):
#     - rust/cargo (rustup), uv, bun, yarn, pnpm, pipx, poetry, micromamba
#
# Distro-aware: detects apk / apt-get / dnf / yum / pacman / zypper and uses the
# right one for base packages. Language tools use their official installers so
# they work regardless of distro/version.
#
# Usage:
#   sh scripts/container_install_deps.sh                 # run inside the container
#   container exec -i <id> sh < scripts/container_install_deps.sh   # -i is REQUIRED when piping over stdin
#
# Notes:
#   * Idempotent — already-present tools are skipped.
#   * Run as root (or with sudo) so the package manager can install.
#   * Prints an INSTALLED / SKIPPED / FAILED summary and exits non-zero if a
#     HARD requirement (C compiler, bash, python3) is missing at the end.
#   * Some tools need glibc and will be skipped on musl (Alpine): notably `bun`
#     and `micromamba`/conda. The script detects this and reports it clearly.
# =============================================================================

set -eu

# ----------------------------------------------------------------------------
# Pretty output
# ----------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$(printf '\033[31m'); GRN=$(printf '\033[32m'); YEL=$(printf '\033[33m')
    CYN=$(printf '\033[36m'); BLD=$(printf '\033[1m'); RST=$(printf '\033[0m')
else
    RED=''; GRN=''; YEL=''; CYN=''; BLD=''; RST=''
fi
log()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "$CYN" "$RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '%s[err]%s %s\n' "$RED" "$RST" "$*" >&2; }

INSTALLED=""
SKIPPED=""
FAILED=""
add_installed() { INSTALLED="$INSTALLED $1"; }
add_skipped()   { SKIPPED="$SKIPPED $1"; }
add_failed()    { FAILED="$FAILED $1"; }

have() { command -v "$1" >/dev/null 2>&1; }

# A sudo shim when not root.
SUDO=""
if [ "$(id -u 2>/dev/null || echo 0)" != "0" ] && have sudo; then
    SUDO="sudo"
fi

# ----------------------------------------------------------------------------
# Detect distro / package manager / arch / libc
# ----------------------------------------------------------------------------
OS_ID=""; OS_NAME=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release 2>/dev/null || true
    OS_ID="${ID:-}"; OS_NAME="${PRETTY_NAME:-${NAME:-}}"
fi

PM=""
for c in apk apt-get dnf yum pacman zypper; do
    if have "$c"; then PM="$c"; break; fi
done

ARCH="$(uname -m 2>/dev/null || echo unknown)"
# libc: musl (Alpine) vs glibc — affects bun / micromamba.
LIBC="glibc"
if have ldd && ldd --version 2>&1 | grep -qi musl; then LIBC="musl"; fi
[ "$OS_ID" = "alpine" ] && LIBC="musl"

info "Distro     : ${OS_NAME:-unknown} (ID=${OS_ID:-?})"
info "Pkg manager: ${PM:-NONE FOUND}"
info "Arch / libc: $ARCH / $LIBC"

if [ -z "$PM" ]; then
    err "No supported package manager found (apk/apt-get/dnf/yum/pacman/zypper)."
    err "Install these manually, then re-run the harness:"
    err "  C toolchain (cc+make), bash, python3+pip, nodejs+npm, ruby, go, git, curl, tar, unzip, xz"
    exit 2
fi

# ----------------------------------------------------------------------------
# Package-manager wrappers
# ----------------------------------------------------------------------------
pm_update() {
    case "$PM" in
        apk)    $SUDO apk update ;;
        apt-get) $SUDO apt-get update ;;
        dnf)    $SUDO dnf -y makecache || true ;;
        yum)    $SUDO yum -y makecache || true ;;
        pacman) $SUDO pacman -Sy --noconfirm ;;
        zypper) $SUDO zypper --non-interactive refresh ;;
    esac
}

# pm_install <pkg...> : install packages, return non-zero on failure
pm_install() {
    case "$PM" in
        apk)    $SUDO apk add --no-cache "$@" ;;
        apt-get) DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y --no-install-recommends "$@" ;;
        dnf)    $SUDO dnf install -y "$@" ;;
        yum)    $SUDO yum install -y "$@" ;;
        pacman) $SUDO pacman -S --needed --noconfirm "$@" ;;
        zypper) $SUDO zypper --non-interactive install -y "$@" ;;
    esac
}

# Resolve a generic dependency group to distro-specific package names.
pkgs_for() {
    group="$1"
    case "$group" in
        toolchain)
            case "$PM" in
                apk)     echo "build-base" ;;
                apt-get) echo "build-essential" ;;
                dnf|yum) echo "gcc gcc-c++ make" ;;
                pacman)  echo "base-devel" ;;
                zypper)  echo "gcc gcc-c++ make" ;;
            esac ;;
        bash)   echo "bash" ;;
        python)
            case "$PM" in
                apk)     echo "python3 py3-pip" ;;
                apt-get) echo "python3 python3-pip python3-venv" ;;
                dnf|yum) echo "python3 python3-pip" ;;
                pacman)  echo "python python-pip" ;;
                zypper)  echo "python3 python3-pip" ;;
            esac ;;
        node)
            case "$PM" in
                apt-get) echo "nodejs npm" ;;
                *)       echo "nodejs npm" ;;
            esac ;;
        ruby)
            case "$PM" in
                apt-get) echo "ruby-full" ;;
                *)       echo "ruby" ;;
            esac ;;
        go)
            case "$PM" in
                apt-get|dnf|yum) echo "golang" ;;
                *)               echo "go" ;;
            esac ;;
        utils)
            case "$PM" in
                apk)     echo "git curl ca-certificates tar unzip xz bash" ;;
                apt-get) echo "git curl ca-certificates tar unzip xz-utils" ;;
                dnf|yum) echo "git curl ca-certificates tar unzip xz" ;;
                pacman)  echo "git curl ca-certificates tar unzip xz" ;;
                zypper)  echo "git curl ca-certificates tar unzip xz" ;;
            esac ;;
    esac
}

# Install a base group unless its sentinel command is already present.
# $1 = group name, $2 = sentinel command to test idempotency
ensure_group() {
    group="$1"; sentinel="$2"
    if have "$sentinel"; then
        add_skipped "$group($sentinel present)"
        return 0
    fi
    plist="$(pkgs_for "$group")"
    info "Installing $group: $plist"
    # shellcheck disable=SC2086
    if pm_install $plist; then
        if have "$sentinel"; then add_installed "$group"; else add_installed "$group(no $sentinel?)"; fi
    else
        warn "Failed to install $group ($plist)"
        add_failed "$group"
    fi
}

# ----------------------------------------------------------------------------
# Base system packages
# ----------------------------------------------------------------------------
info "Refreshing package index…"
pm_update || warn "package index refresh failed (continuing)"

ensure_group utils      curl
ensure_group toolchain  cc
# some distros provide the compiler only as 'gcc' (no 'cc' symlink)
if ! have cc && have gcc; then
    info "Linking cc -> gcc"
    $SUDO ln -sf "$(command -v gcc)" /usr/local/bin/cc 2>/dev/null || true
fi
ensure_group bash       bash
ensure_group python     python3
# ensure pip is usable
if have python3 && ! python3 -m pip --version >/dev/null 2>&1; then
    python3 -m ensurepip --upgrade >/dev/null 2>&1 || true
fi
ensure_group node       node
[ ! "$(command -v node 2>/dev/null)" ] && have nodejs && $SUDO ln -sf "$(command -v nodejs)" /usr/local/bin/node 2>/dev/null || true
ensure_group ruby       gem
ensure_group go         go

# ----------------------------------------------------------------------------
# Language-ecosystem tools via official cross-distro installers
# ----------------------------------------------------------------------------
# Make freshly-installed user-local bins visible for verification.
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.bun/bin:$HOME/bin:/usr/local/bin:$PATH"

# run a soft (best-effort) installer; never aborts the script
soft() {  # name sentinel  -- then reads the install command from stdin
    name="$1"; sentinel="$2"
    if have "$sentinel"; then add_skipped "$name($sentinel present)"; return 0; fi
    info "Installing $name…"
    if sh -c "$(cat)" >/dev/null 2>&1 && have "$sentinel"; then
        add_installed "$name"
    else
        warn "$name install failed or not on PATH"
        add_failed "$name"
    fi
}

# rust / cargo via rustup
soft rust cargo <<'INS'
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
. "$HOME/.cargo/env" 2>/dev/null || true
INS

# uv (Astral) — official installer
soft uv uv <<'INS'
curl -LsSf https://astral.sh/uv/install.sh | sh
INS

# yarn + pnpm via npm (needs npm)
if have npm; then
    if have yarn; then add_skipped "yarn(present)"; else
        info "Installing yarn (npm -g)…"
        if $SUDO npm install -g yarn >/dev/null 2>&1 || npm install -g yarn >/dev/null 2>&1; then add_installed yarn; else add_failed yarn; fi
    fi
    if have pnpm; then add_skipped "pnpm(present)"; else
        info "Installing pnpm (npm -g)…"
        if $SUDO npm install -g pnpm >/dev/null 2>&1 || npm install -g pnpm >/dev/null 2>&1; then add_installed pnpm; else add_failed pnpm; fi
    fi
else
    add_failed "yarn(no npm)"; add_failed "pnpm(no npm)"
fi

# pipx + poetry
if have pipx; then add_skipped "pipx(present)"; else
    info "Installing pipx…"
    if python3 -m pip install --user pipx >/dev/null 2>&1 || \
       python3 -m pip install --user --break-system-packages pipx >/dev/null 2>&1; then
        python3 -m pipx ensurepath >/dev/null 2>&1 || true
        export PATH="$HOME/.local/bin:$PATH"
        have pipx && add_installed pipx || add_failed pipx
    else
        add_failed pipx
    fi
fi
if have poetry; then add_skipped "poetry(present)"; else
    if have pipx; then
        info "Installing poetry (pipx)…"
        if pipx install poetry >/dev/null 2>&1; then add_installed poetry; else add_failed poetry; fi
    else
        add_failed "poetry(no pipx)"
    fi
fi

# bun — needs glibc; skip on musl/Alpine
if have bun; then
    add_skipped "bun(present)"
elif [ "$LIBC" = "musl" ]; then
    warn "Skipping bun — requires glibc, not available on musl/Alpine."
    add_skipped "bun(musl/glibc-only)"
else
    info "Installing bun…"
    if curl -fsSL https://bun.sh/install | bash >/dev/null 2>&1; then
        export PATH="$HOME/.bun/bin:$PATH"
        have bun && add_installed bun || add_failed bun
    else
        add_failed bun
    fi
fi

# micromamba (conda alternative). Official builds are glibc; flag on musl.
if have micromamba || have conda; then
    add_skipped "conda/micromamba(present)"
else
    case "$ARCH" in
        x86_64|amd64) MM_ARCH="linux-64" ;;
        aarch64|arm64) MM_ARCH="linux-aarch64" ;;
        *) MM_ARCH="" ;;
    esac
    if [ -z "$MM_ARCH" ]; then
        warn "micromamba: unsupported arch $ARCH — skipping."
        add_skipped "micromamba(arch $ARCH)"
    elif [ "$LIBC" = "musl" ]; then
        warn "micromamba/conda: official builds are glibc-only; on Alpine install 'gcompat' or use a glibc base image. Skipping."
        add_skipped "micromamba(musl/glibc-only)"
    else
        info "Installing micromamba ($MM_ARCH)…"
        if curl -Ls "https://micro.mamba.pm/api/micromamba/$MM_ARCH/latest" | tar -xj -C "$HOME" bin/micromamba >/dev/null 2>&1; then
            export PATH="$HOME/bin:$PATH"
            have micromamba && add_installed micromamba || add_failed micromamba
        else
            add_failed micromamba
        fi
    fi
fi

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
printf '\n%s==== dependency summary ====%s\n' "$BLD" "$RST"
printf '%sinstalled:%s %s\n' "$GRN" "$RST" "${INSTALLED:- none}"
printf '%sskipped  :%s %s\n' "$YEL" "$RST" "${SKIPPED:- none}"
printf '%sfailed   :%s %s\n' "$RED" "$RST" "${FAILED:- none}"

printf '\n%stool availability:%s\n' "$BLD" "$RST"
for t in cc gcc make bash python3 pip3 node npm yarn pnpm bun cargo uv pipx poetry gem go conda micromamba; do
    if have "$t"; then printf '  %sok %s%s\n' "$GRN" "$RST" "$t"; else printf '  %s-- %s%s\n' "$YEL" "$RST" "$t"; fi
done

printf '\n%sPATH additions you may need in your shell profile:%s\n' "$BLD" "$RST"
printf '  export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.bun/bin:$HOME/bin:$PATH"\n'

# Hard requirements for the harness to run at all.
HARD_OK=yes
for t in cc bash python3; do
    have "$t" || { err "HARD requirement missing: $t"; HARD_OK=no; }
done
if [ "$HARD_OK" != yes ]; then
    err "Hard requirements unmet — the harness cannot fully run."
    exit 1
fi
printf '\n%sReady.%s Now run: sh scripts/container_e2e_test.sh\n' "$GRN" "$RST"
