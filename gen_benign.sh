#!/bin/bash
# Benign background traffic using several different TLS clients, so the lab has several JA3 fingerprints.
# Run inside a Mininet host, e.g.:  pc0 ./gen_benign.sh &
HERE=$(dirname "$(readlink -f "$0")")
DNS=203.0.113.11
WEB=203.0.113.10
NAMES=(www.lab news.lab mail.lab video.lab shop.lab docs.lab)
PATHS=(/ /index.html /small.txt /video.bin /page.html)

# one HTTPS visit with a randomly chosen client
fetch() {
  local name=$1 path=$2
  case $(( RANDOM % 5 )) in
    0) curl -sk --max-time 10 --resolve "$name:443:$WEB" "https://$name$path" -o /dev/null ;;
    1) curl -sk --max-time 10 --tls-max 1.2 --resolve "$name:443:$WEB" "https://$name$path" -o /dev/null ;;
    2) curl -sk --max-time 10 --curves P-256 --resolve "$name:443:$WEB" "https://$name$path" -o /dev/null ;;
    3) python3 "$HERE/py_client.py" "$WEB" "$name" "$path" > /dev/null 2>&1 ;;
    4) echo | timeout 10 openssl s_client -connect "$WEB:443" -servername "$name" > /dev/null 2>&1 ;;
  esac
}

while true; do
  name=${NAMES[$RANDOM % ${#NAMES[@]}]}
  path=${PATHS[$RANDOM % ${#PATHS[@]}]}

  dig @"$DNS" +short +time=2 +tries=1 "$name" > /dev/null
  fetch "$name" "$path"

  if (( RANDOM % 10 == 0 )); then
    f=$(mktemp)
    head -c 2000 /dev/urandom > "$f"
    curl -sk --max-time 10 --resolve "$name:443:$WEB" --data-binary @"$f" "https://$name/upload" -o /dev/null
    rm -f "$f"
  fi

  sleep $(( (RANDOM % 8) + 1 ))
done
