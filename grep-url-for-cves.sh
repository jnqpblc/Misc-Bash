#!/bin/bash
EDB_INSTALL="git clone https://github.com/offensive-security/exploit-database.git /usr/share/exploit-database"
MSF_INSTALL="curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"

if [ -z "$3" ];then printf "\nSyntax: $0 <changelog-url|https://dlcdn.apache.org/httpd/CHANGES_2.4> <search-term|'Apache 2.4.41'> <mode|above|all>\n\n"
	else
EDB="/usr/share/exploit-database"; MSF="/opt/metasploit-framework/embedded/framework/modules"; URL=$1; QUERY=$2; MODE=$3;

if [ ! -d "$EDB" ]; then
  printf "\n$EDB DOES NOT exists. Please modify the script.\n\n...or run this: $EDB_INSTALL\n";
elif [ ! -d "$MSF" ]; then
  printf "\n$MSF DOES NOT exists. Please modify the script.\n\n...or run this: $MSF_INSTALL\n";
else
  if [ "$MODE" == "all" ]; then
    for CVE in $(curl -A '' "$URL" 2>/dev/null |grep -B1 "$QUERY" |egrep -o 'CVE-[0-9]{4}-[0-9]{4,5}' |sort -u |sed 's/CVE-//g;'); do
      echo "### CVE-$CVE";
      grep -r "$CVE"  $EDB/*;
      grep -r "$CVE"  $MSF/*;
    done
  elif [ "$MODE" == "above" ]; then
    for CVE in $(curl -A '' "$URL" 2>/dev/null |grep -B10000000000000 "$QUERY" |egrep -o 'CVE-[0-9]{4}-[0-9]{4,5}' |sort -u |sed 's/CVE-//g;'); do
      echo "### CVE-$CVE";
      grep -r "$CVE"  $EDB/*;
      grep -r "$CVE"  $MSF/*;
    done
  else
    printf '\nDammit Bobby! The mode can only be "above" or "all"\n'
  fi
fi
fi
