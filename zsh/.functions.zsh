function customs() {
    echo "Aliases defined:"
    echo "Name"
    echo "-----------------"
    grep '^alias ' ~/.aliases.zsh | awk -F'=' '{print $1}' | sed 's/alias //'
    echo ''
    echo "Functions defined:"
    echo "Name"
    echo "-----------------"
    grep '^function ' ~/.functions.zsh | sed -n 's/function \(.*\)() {.*/\1/p'
}
function dockershellshhere() {
    # Function to run docker shell in current directory with /bin/sh
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/sh -v `pwd`:/${dirname} -w /${dirname} "$@"
}

function dockershellhere() {
    # Function to run docker shell in current directory with /bin/bash
    dirname=${PWD##*/}
    sudo docker run --rm -it --entrypoint=/bin/bash -v `pwd`:/${dirname} -w /${dirname} "$@"
}
function ffuf_vhost() {
    if [ "$#" -ne 3 ]; then
        echo "[i] Usage: ffuf_vhost <http|https> <domain> <fs>"
        return 1
    fi

    protocol=$1
    domain=$2
    fs_value=$3

    if [ "$protocol" != "http" ] && [ "$protocol" != "https" ]; then
        echo "[i] Invalid protocol. Use 'http' or 'https'."
        return 1
    fi

    ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -H "Host: FUZZ.$domain" -u $protocol://$domain -fs $fs_value
}
function ffuf_vhost_quick() {
    if [ "$#" -ne 3 ]; then
        echo "[i] Usage: ffuf_vhost_fast <http|https> <domain> <fs>"
        return 1
    fi

    protocol=$1
    domain=$2
    fs_value=$3

    if [ "$protocol" != "http" ] && [ "$protocol" != "https" ]; then
        echo "[i] Invalid protocol. Use 'http' or 'https'."
        return 1
    fi

    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$domain" -u $protocol://$domain -fs $fs_value
}
function rock_john() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: rock_john [hash] (options)"
    else
      john "${@}" --wordlist=/usr/share/wordlists/rockyou.txt
  fi
}
function ips() {
  ip a show scope global | awk '/^[0-9]+:/ { sub(/:/,"",$2); iface=$2 } /^[[:space:]]*inet / { split($2, a, "/"); print "[\033[96m" iface"\033[0m] "a[1] }'
}
function nmap_default() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: nmap_default ip (options)"
    else
      [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
      sudo nmap -sCV -T4 --min-rate 10000 "${@}" -v -oA nmap/tcp_default
  fi
}
function nmap_udp() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: nmap_udp ip (options)"
    else
      [ ! -d "./nmap" ] && echo "[i] Creating $(pwd)/nmap..." && mkdir nmap
      sudo nmap -sUCV -T4 --min-rate 10000 "${@}" -v -oA nmap/udp_default
  fi
}
function crawl() {
    if [[ -z "$1" ]]; then
        echo "[i] Usage: crawl <URL>"
        return 1
    fi
    echo "[i] Crawling subdomains for: $1"
    gospider -s $1 -d 5 -t 10 --include-subs -o files | awk '/^\[subdomains\]/ { print "\033[1;31m" $0 "\033[0m" } !/^\[subdomains\]/ { print }'
}
function export-krbcc() {
  export KRB5CCNAME=$(realpath "$1")
}
function rdp() {
    usage() {
        echo "[i] Usage: rdp -i '10.129.16.128' -u 'Administrator' -p 'P@s\$w0rd!' [-H 'NTLMHash']" >&2
    }

    if [ $# -eq 0 ]; then
        usage
        return
    fi

    local OPTIND host user pass hash

    while getopts ':i:u:p:H:' OPTION; do
        case "$OPTION" in
            i) host="$OPTARG" ;;
            u) user="$OPTARG" ;;
            p)
                pass="$OPTARG"
                xfreerdp /v:$host /u:$user /p:$pass /cert:ignore /dynamic-resolution +clipboard
                ;;
            H)
                hash="$OPTARG"
                xfreerdp /v:$host /u:$user /pth:$hash /cert:ignore /dynamic-resolution +clipboard
                ;;
            ?)
                usage
                ;;
        esac
    done

    shift "$(($OPTIND -1))"
}
function rdp_noauth() {
    if [ $# -eq 0 ]; then
        echo "[i] Usage: rdp_noauth <IP Address>"
        return
    fi

    local ip=$1

    xfreerdp /v:$ip /size:1920x1080 /tls-seclevel:0 -sec-nla
}
function ligolo-server() {
    if ! ip link show ligolo &>/dev/null; then
        sudo ip tuntap add user kali mode tun ligolo
        sudo ip link set ligolo up
    fi

    /opt/ligolo-ng/proxy -selfcert
}
function timesync() {
    sudo date --set="`curl {$1} -I | grep Date | cut -d ',' -f2`"
}
function flagrep() {
    grep -r -E -n --color=auto "^(HTB|VL){(.{32}|\w+)}$" "$1" 2>/dev/null
}