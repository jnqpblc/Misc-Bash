#!/bin/bash
EDB_INSTALL="git clone https://github.com/offensive-security/exploit-database.git /usr/share/exploit-database"
MSF_INSTALL="curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"

if [ -z "$1" ];then printf "\nSyntax: $0 <file_of_cves>\n\n"
	else
EDB="/usr/share/exploit-database"; MSF="/usr/share/metasploit-framework/modules"; FILE=$1;

if [ ! -d "$EDB" ]; then
  printf "\n$EDB DOES NOT exists. Please modify the script.\n\n...or run this: $EDB_INSTALL\n";
elif [ ! -d "$MSF" ]; then
  printf "\n$MSF DOES NOT exists. Please modify the script.\n\n...or run this: $MSF_INSTALL\n";
else
  for CVE in $(egrep -o 'CVE-[0-9]{4}-[0-9]{4,5}' $FILE |sort -u |sed 's/CVE-//g;'); do
    echo "### CVE-$CVE";
    grep -r "$CVE"  $EDB/*;
    grep -r "$CVE"  $MSF/*;
  done
fi
fi
