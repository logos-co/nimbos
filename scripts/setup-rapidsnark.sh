#!/usr/bin/env bash
#
# Setup script for the prebuilt rapidsnark Groth16 prover libraries.
#
# Usage: ./setup-rapidsnark.sh [VERSION] [INSTALL_DIR]
#
# Arguments:
#   VERSION      - Optional. rapidsnark version to install (default: v0.0.8)
#   INSTALL_DIR  - Optional. Installation directory.
#                  Default follows the XDG Base Directory Spec:
#                    Linux:  $XDG_DATA_HOME/rapidsnark/<VERSION>
#                            ($HOME/.local/share/... if XDG_DATA_HOME is unset)
#                    macOS:  $XDG_DATA_HOME/rapidsnark/<VERSION>
#                            ($HOME/Library/Application Support/... if unset)
#
# The archives are the ones the reference node links through rust-rapidsnark:
#   - macOS:  iden3's upstream release
#   - Linux:  the Logos fork's -fPIC rebuilds (upstream Linux archives are
#             non-PIC and built against a newer glibc)
# There is no Windows archive. On Windows this script prints a notice and
# exits 0; the Nim prover compiles as a stub there.
#
# The installed layout is <INSTALL_DIR>/lib/{librapidsnark,libfr,libfq,libgmp}.a
# plus <INSTALL_DIR>/VERSION. The Linux archives ship no headers; Nim declares
# the FFI by layout and needs none.

set -e

VERSION="${1:-v0.0.8}"

case "${XDG_DATA_HOME}" in
    /*) ;;
    *)  XDG_DATA_HOME="" ;;
esac
case "$(uname -s)" in
    Darwin*) DEFAULT_DATA_ROOT="${XDG_DATA_HOME:-$HOME/Library/Application Support}" ;;
    *)       DEFAULT_DATA_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}" ;;
esac
DEFAULT_INSTALL_DIR="$DEFAULT_DATA_ROOT/rapidsnark/$VERSION"
INSTALL_DIR="${2:-$DEFAULT_INSTALL_DIR}"

IDEN3_BASE="https://github.com/iden3/rapidsnark/releases/download/$VERSION"
FORK_BASE="https://github.com/logos-blockchain/logos-blockchain-rust-rapidsnark/releases/download/rapidsnark-pic-$VERSION"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}ℹ${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error()   { echo -e "${RED}✗${NC} $1"; }

# Map host OS + CPU to the release asset name and its base URL.
select_asset() {
    local os arch
    case "$(uname -s)" in
        Linux*)  os="linux";;
        Darwin*) os="macos";;
        MINGW*|MSYS*|CYGWIN*)
            print_warning "No rapidsnark archive exists for Windows; the prover is a stub there."
            exit 0;;
        *) print_error "Unsupported operating system: $(uname -s)"; exit 1;;
    esac
    case "$(uname -m)" in
        x86_64)        arch="x86_64";;
        aarch64|arm64) arch="aarch64";;
        *) print_error "Unsupported architecture: $(uname -m)"; exit 1;;
    esac

    case "$os-$arch" in
        linux-x86_64)  ASSET="rapidsnark-linux-x86_64-pic-$VERSION";  BASE_URL="$FORK_BASE";;
        linux-aarch64) ASSET="rapidsnark-linux-aarch64-pic-$VERSION"; BASE_URL="$FORK_BASE";;
        macos-aarch64) ASSET="rapidsnark-macOS-arm64-$VERSION";       BASE_URL="$IDEN3_BASE";;
        macos-x86_64)  ASSET="rapidsnark-macOS-x86_64-$VERSION";      BASE_URL="$IDEN3_BASE";;
    esac
    print_info "Detected platform: $os-$arch"
}

check_existing_installation() {
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Installation directory already exists: $INSTALL_DIR"
        if [ -f "$INSTALL_DIR/VERSION" ]; then
            print_info "Currently installed version: $(cat "$INSTALL_DIR/VERSION")"
        fi
        if [ ! -t 0 ]; then
            print_info "Non-interactive environment detected, automatically overwriting..."
        else
            echo
            read -p "Do you want to overwrite it? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_info "Installation cancelled."
                exit 0
            fi
        fi
        print_info "Removing existing installation..."
        rm -rf "$INSTALL_DIR"
    fi
}

download_release() {
    local url="$BASE_URL/$ASSET.zip"
    local temp_dir
    temp_dir=$(mktemp -d)

    print_info "Downloading rapidsnark ${VERSION} ($ASSET)..."
    print_info "URL: $url"

    # -f: fail on HTTP errors instead of saving the error page.
    if ! curl -fL --retry 3 --retry-all-errors -o "$temp_dir/$ASSET.zip" "$url"; then
        print_error "Failed to download release archive"
        print_error "Please check that version ${VERSION} exists for this platform"
        rm -rf "$temp_dir"
        exit 1
    fi
    print_success "Download complete"

    print_info "Extracting to ${INSTALL_DIR}..."
    mkdir -m 0700 -p "$INSTALL_DIR"
    if ! unzip -qo "${temp_dir}/${ASSET}.zip" -d "${temp_dir}/x"; then
        print_error "Failed to extract archive"
        rm -rf "$temp_dir"
        exit 1
    fi

    # Archives extract to <ASSET>/{lib,include,bin}; only lib/ (and include/) is kept.
    local src="${temp_dir}/x/${ASSET}"
    if [ ! -d "$src/lib" ]; then
        print_error "Archive has no lib/ directory: $src"
        rm -rf "$temp_dir"
        exit 1
    fi
    mkdir -p "$INSTALL_DIR/lib"
    cp "$src/lib/"*.a "$INSTALL_DIR/lib/"
    if [ -d "$src/include" ]; then
        mkdir -p "$INSTALL_DIR/include"
        cp "$src/include/"* "$INSTALL_DIR/include/"
    fi
    echo "$VERSION" > "$INSTALL_DIR/VERSION"

    rm -rf "$temp_dir"
    print_success "Extraction complete"
}

main() {
    print_info "Setting up rapidsnark ${VERSION}"
    print_info "Installation directory: $INSTALL_DIR"
    echo

    select_asset
    check_existing_installation
    download_release

    echo
    print_success "Installation complete!"
    print_info "rapidsnark ${VERSION} is now installed at: $INSTALL_DIR"
    print_info "Static libraries:"
    for f in "$INSTALL_DIR"/lib/*.a; do
        echo "  • $(basename "$f")"
    done
}

main
