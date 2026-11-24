#!/bin/bash
# Benign background traffic. Run inside a Mininet host, e.g.:  pc0 ./gen_benign.sh &
DNS=203.0.113.11
WEB=203.0.113.10
NAMES=(www.lab news.lab mail.lab video.lab shop.lab docs.lab)
PATHS=(/ /index.html /small.txt /video.bin /page.html)

while true; do
  name=${NAMES[$RANDOM % ${#NAMES[@]}]}
  path=${PATHS[$RANDOM % ${#PATHS[@]}]}

  dig @"$DNS" +short +time=2 +tries=1 "$name" > /dev/null
  curl -sk --max-time 10 --resolve "$name:443:$WEB" "https://$name$path" -o /dev/null

  if (( RANDOM % 10 == 0 )); then
    f=$(mktemp)
    head -c 2000 /dev/urandom > "$f"
    curl -sk --max-time 10 --resolve "$name:443:$WEB" --data-binary @"$f" "https://$name/upload" -o /dev/null
    rm -f "$f"
  fi

  sleep $(( (RANDOM % 8) + 1 ))
done
