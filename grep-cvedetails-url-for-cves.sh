#!/bin/bash
EDB_INSTALL="git clone https://github.com/offensive-security/exploit-database.git /usr/share/exploit-database"
MSF_INSTALL="curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"

if [ -z "$1" ];then printf "\nSyntax: $0 <cvedetails_url|https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-66/version_id-40007/Apache-Http-Server-2.2.3.html>\n\n"
	else
EDB="/usr/share/exploit-database"; MSF="/usr/share/metasploit-framework"; URL=$1;

for CVE in $(curl -A '' "$URL" 2>/dev/null|egrep -o 'CVE-[0-9]{4}-[0-9]{4}'|sort -u|grep -v '2009-1234'|sed 's/CVE-//g;'); do
	echo "### CVE-$CVE"; grep -r "$CVE"  $MSF/modules/*;
done
for CVE in $(curl -A '' "$URL" 2>/dev/null|egrep -o 'CVE-[0-9]{4}-[0-9]{4}'|sort -u|grep -v '2009-1234'|sed 's/CVE-//g;'); do
	echo "### CVE-$CVE"; grep -r "$CVE"  $EDB/exploits/*;
done
fi
