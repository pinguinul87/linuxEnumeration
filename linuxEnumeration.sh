#!/bin/bash
: '
Script that enumerates system information, application version, files, environment variables, networking and private keys.
This script is used on locally on the target.
Post exploitaion.
' 

start(){
echo -e "\n\e[00;31m====================================\e[00m"
echo -e "\e[00;31m=\e[00m" "\e[00;33mRunning Linux Enumeration Script\e[00m" "\e[00;31m=\e[00m"
echo -e "\e[00;31m====================================\e[00m"
}

end(){
echo -e "\e[00;33m[+] Enumeration Complete =======================================\e[00m" 
}

#Script core

system_info() {
  echo -e "\e[00;33m[+] SYSTEM =======================================\e[00m"

  #basic kernel info
  unameinfo=$(uname -a 2>/dev/null)
  if [ "$unameinfo" ]; then
                echo -e "\e[00;31m[-] Kernel information:\e[00m\n$unameinfo"
                echo -e "\n"
  fi

  #proc version
  procver=$(cat /proc/version 2>/dev/null)
  if [ "$procver" ]; then
                echo -e "\e[00;31m[-] Kernel information (continued):\e[00m\n$procver"
                echo -e "\n"
  fi

  #search all *-release files for version info
  release=$(cat /etc/*-release 2>/dev/null)
  if [ "$release" ]; then
                echo -e "\e[00;31m[-] Specific release information:\e[00m\n$release"
                echo -e "\n"
  fi

  #target hostname info
  hostname=$(hostname 2>/dev/null)
  if [ "$hostname" ]; then
                echo -e "\e[00;31m[-] Hostname:\e[00m\n$hostname"
                echo -e "\n"
  fi
  
  #top 20 running processes sorted by CPU usage
  top20=$(ps -eo ppid,pid,cmd,user,%mem,%cpu --sort=-%cpu | head -n 20)
  if [ "$top20" ]; then
                echo -e "\e[00;31m[-] Top 20 processes sorted by CPU usage:\e[00m\n$top20"
                echo -e "\n"
  fi
  
}

user_info() {

echo -e "\e[00;33m[+] USER/GROUP INFO =======================================\e[00m" 

#current user details
currusr=$(id 2>/dev/null)
if [ "$currusr" ]; then
                echo -e "\e[00;31m[-] Current user/group info:\e[00m\n$currusr" 
                echo -e "\n"
fi

#last logged on user information
lastlogedonusrs=$(lastlog 2>/dev/null |grep -v "Never" 2>/dev/null)
if [ "$lastlogedonusrs" ]; then
                echo -e "\e[00;31m[-] Users that have previously logged onto the system:\e[00m\n$lastlogedonusrs" 
                echo -e "\n" 
fi

#who else is logged on
loggedonusrs=$(w 2>/dev/null)
if [ "$loggedonusrs" ]; then
                echo -e "\e[00;31m[-] Who else is logged on:\e[00m\n$loggedonusrs" 
                echo -e "\n"
fi

#lists all id's and respective group(s)
grpinfo=$(for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null)
if [ "$grpinfo" ]; then
                echo -e "\e[00;31m[-] Group memberships:\e[00m\n$grpinfo"
                echo -e "\n"
fi

#look for admin group
adm_users=$(echo -e "$grpinfo" | grep "(adm)")
if [[ ! -z $adm_users ]];then
                echo -e "\e[00;31m[-] It looks like we have some admin users:\e[00m\n$adm_users"
                echo -e "\n"
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=$(grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null)
if [ "$hashesinpasswd" ]; then
                echo -e "\e[00;33m[+] It looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd" 
                echo -e "\n"
fi

#contents of /etc/passwd
readpasswd=$(cat /etc/passwd 2>/dev/null)
if [ "$readpasswd" ]; then
                echo -e "\e[00;31m[-] Contents of /etc/passwd:\e[00m\n$readpasswd" 
                echo -e "\n"
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=$(cat /etc/master.passwd 2>/dev/null)
if [ "$readmasterpasswd" ]; then
                echo -e "\e[00;33m[+] We can read the master.passwd file!\e[00m\n$readmasterpasswd" 
                echo -e "\n"
fi

#all root accounts (uid 0)
rooty=$(grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null)
if [ "$rooty" ]; then
                echo -e "\e[00;31m[-] Super user account(s):\e[00m\n$superman"
                echo -e "\n"
fi

#pull out vital sudoers info
sudoers=$(grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null)
if [ "$sudoers" ]; then
                echo -e "\e[00;31m[-] Sudoers configuration (condensed):\e[00m$sudoers"
                echo -e "\n"
fi

#can we sudo without a password
sudoperms=$(echo '' | sudo -S -l -k 2>/dev/null)
if [ "$sudoperms" ]; then
                echo -e "\e[00;33m[+] We can sudo without a password! :D\e[00m\n$sudoperms" 
                echo -e "\n"
fi

#known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
sudopwnage=$(echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null)
if [ "$sudopwnage" ]; then
                echo -e "\e[00;33m[+] Possible sudo pwnage!\e[00m\n$sudopwnage" 
                echo -e "\n"
fi

#looks for hidden files
hiddenfiles=$(find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null)
if [ "$hiddenfiles" ]; then
                echo -e "\e[00;31m[-] Hidden files:\e[00m\n$hiddenfiles"
                echo -e "\n"
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
wrfileshm=$(find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null)
if [ "$wrfileshm" ]; then
                echo -e "\e[00;31m[-] World-readable files within /home:\e[00m\n$wrfileshm"
                echo -e "\n"
fi

#lists current user's home directory contents
homedircontents=$(ls -ahl ~ 2>/dev/null)
if [ "$homedircontents" ] ; then
                echo -e "\e[00;31m[-] Home directory contents:\e[00m\n$homedircontents" 
                echo -e "\n" 
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
sshfiles=$(find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;)
if [ "$sshfiles" ]; then
                echo -e "\e[00;31m[-] SSH keys/host information found in the following locations:\e[00m\n$sshfiles" 
                echo -e "\n"
fi

#is root permitted to login via ssh
sshrootlogin=$(grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}')
if [ "$sshrootlogin" = "yes" ]; then
                echo -e "\e[00;31m[-] Root is allowed to login via SSH:\e[00m" ; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" 
                echo -e "\n"
fi
}


environ_info(){

echo -e "\e[00;33m[+] ENVIRONMENTAL =======================================\e[00m" 

#env information
envinfo=$(env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null)
if [ "$envinfo" ]; then
                echo -e "\e[00;31m[-] Environment information:\e[00m\n$envinfo" 
                echo -e "\n"
fi

#check if selinux is enabled
sestatus=$(sestatus 2>/dev/null)
if [ "$sestatus" ]; then
                echo -e "\e[00;31m[-] SELinux seems to be present:\e[00m\n$sestatus"
                echo -e "\n"
fi

#current path configuration
pathinfo=$(echo $PATH 2>/dev/null)
if [ "$pathinfo" ]; then
                pathswriteable=$(ls -ld $(echo $PATH | tr ":" " "))
                echo -e "\e[00;31m[-] Path information:\e[00m\n$pathinfo" 
                echo -e "$pathswriteable"
                echo -e "\n"
fi

#lists available shells
shellinfo=$(cat /etc/shells 2>/dev/null)
if [ "$shellinfo" ]; then
                echo -e "\e[00;31m[-] Available shells:\e[00m\n$shellinfo" 
                echo -e "\n"
fi

#current umask value with both octal and symbolic output
umaskvalue=$(umask -S 2>/dev/null & umask 2>/dev/null)
if [ "$umaskvalue" ]; then
                echo -e "\e[00;31m[-] Current umask value:\e[00m\n$umaskvalue" 
                echo -e "\n"
fi

#umask value as in /etc/login.defs
umaskdef=$(grep -i "^UMASK" /etc/login.defs 2>/dev/null)
if [ "$umaskdef" ]; then
                echo -e "\e[00;31m[-] umask value as specified in /etc/login.defs:\e[00m\n$umaskdef" 
                echo -e "\n"
fi

#password policy information as stored in /etc/login.defs
logindefs=$(grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null)
if [ "$logindefs" ]; then
                echo -e "\e[00;31m[-] Password and storage information:\e[00m\n$logindefs" 
                echo -e "\n"
fi
}

networking_info(){

echo -e "\e[00;33m[+] NETWORKING  =======================================\e[00m" 

#network interface card information
nicinfo=$(/sbin/ifconfig -a 2>/dev/null)
if [ "$nicinfo" ]; then
                echo -e "\e[00;31m[-] Network and IP info:\e[00m\n$nicinfo" 
                echo -e "\n"
fi

#network interface card information (using ip)
nicinfoip=$(/sbin/ip a 2>/dev/null)
if [ ! "$nicinfo" ] && [ "$nicinfoip" ]; then
                echo -e "\e[00;31m[-] Network and IP info:\e[00m\n$nicinfoip" 
                echo -e "\n"
fi

arpinfo=$(arp -a 2>/dev/null)
if [ "$arpinfo" ]; then
                echo -e "\e[00;31m[-] ARP history:\e[00m\n$arpinfo" 
                echo -e "\n"
fi

arpinfoip=$(ip n 2>/dev/null)
if [ ! "$arpinfo" ] && [ "$arpinfoip" ]; then
                echo -e "\e[00;31m[-] ARP history:\e[00m\n$arpinfoip" 
                echo -e "\n"
fi

#dns settings
nsinfo=$(grep "nameserver" /etc/resolv.conf 2>/dev/null)
if [ "$nsinfo" ]; then
                echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfo" 
                echo -e "\n"
fi

nsinfosysd=$(systemd-resolve --status 2>/dev/null)
if [ "$nsinfosysd" ]; then
                echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfosysd" 
                echo -e "\n"
fi

#default route configuration
defroute=$(route 2>/dev/null | grep default)
if [ "$defroute" ]; then
                echo -e "\e[00;31m[-] Default route:\e[00m\n$defroute" 
                echo -e "\n"
fi

#default route configuration
defrouteip=$(ip r 2>/dev/null | grep default)
if [ ! "$defroute" ] && [ "$defrouteip" ]; then
                echo -e "\e[00;31m[-] Default route:\e[00m\n$defrouteip" 
                echo -e "\n"
fi

#listening TCP
tcpservs=$(netstat -ntpl 2>/dev/null)
if [ "$tcpservs" ]; then
                echo -e "\e[00;31m[-] Listening TCP:\e[00m\n$tcpservs" 
                echo -e "\n"
fi

#listening UDP
udpservs=$(netstat -nupl 2>/dev/null)
if [ "$udpservs" ]; then
                echo -e "\e[00;31m[-] Listening UDP:\e[00m\n$udpservs" 
                echo -e "\n"
fi
}

software_configs(){

echo -e "\e[00;33m[+] SOFTWARE =======================================\e[00m" 

#sudo version - check to see if there are any known vulnerabilities
sudover=$(sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null)
if [ "$sudover" ]; then
                echo -e "\e[00;31m[-] Sudo version:\e[00m\n$sudover" 
                echo -e "\n"
fi

#mysql details - if installed
mysqlver=$(mysql --version 2>/dev/null)
if [ "$mysqlver" ]; then
                echo -e "\e[00;31m[-] MYSQL version:\e[00m\n$mysqlver" 
                echo -e "\n"
fi

#checks to see if root/root will get us a connection
mysqlconnect=$(mysqladmin -uroot -proot version 2>/dev/null)
if [ "$mysqlconnect" ]; then
                echo -e "\e[00;33m[+] We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect" 
                echo -e "\n"
fi

#mysql version details
mysqlconnectnopass=$(mysqladmin -uroot version 2>/dev/null)
if [ "$mysqlconnectnopass" ]; then
                echo -e "\e[00;33m[+] We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass" 
                echo -e "\n"
fi

#postgres details - if installed
postgver=$(psql -V 2>/dev/null)
if [ "$postgver" ]; then
                echo -e "\e[00;31m[-] Postgres version:\e[00m\n$postgver" 
                echo -e "\n"
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=$(psql -U postgres -w template0 -c 'select version()' 2>/dev/null | grep version)
if [ "$postcon1" ]; then
                echo -e "\e[00;33m[+] We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1" 
                echo -e "\n"
fi

postcon11=$(psql -U postgres -w template1 -c 'select version()' 2>/dev/null | grep version)
if [ "$postcon11" ]; then
                echo -e "\e[00;33m[+] We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11" 
                echo -e "\n"
fi

postcon2=$(psql -U pgsql -w template0 -c 'select version()' 2>/dev/null | grep version)
if [ "$postcon2" ]; then
                echo -e "\e[00;33m[+] We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2" 
                echo -e "\n"
fi

postcon22=$(psql -U pgsql -w template1 -c 'select version()' 2>/dev/null | grep version)
if [ "$postcon22" ]; then
                echo -e "\e[00;33m[+] We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22" 
                echo -e "\n"
fi

#apache details - if installed
apachever=$(apache2 -v 2>/dev/null; httpd -v 2>/dev/null)
if [ "$apachever" ]; then
                echo -e "\e[00;31m[-] Apache version:\e[00m\n$apachever" 
                echo -e "\n"
fi

#what account is apache running under
apacheusr=$(grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null)
if [ "$apacheusr" ]; then
                echo -e "\e[00;31m[-] Apache user configuration:\e[00m\n$apacheusr" 
                echo -e "\n"
fi

#installed apache modules
apachemodules=$(apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null)
if [ "$apachemodules" ]; then
                echo -e "\e[00;31m[-] Installed Apache modules:\e[00m\n$apachemodules" 
                echo -e "\n"
fi

#htpasswd check
htpasswd=$(find / -name .htpasswd -print -exec cat {} \; 2>/dev/null)
if [ "$htpasswd" ]; then
                echo -e "\e[00;33m[-] htpasswd found - could contain passwords:\e[00m\n$htpasswd"
                echo -e "\n"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
apachehomedirs=$(ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null)
if [ "$apachehomedirs" ]; then
                echo -e "\e[00;31m[-] www home dir contents:\e[00m\n$apachehomedirs" 
                echo -e "\n"
fi
}

interesting_files(){

echo -e "\e[00;33m[+] INTERESTING FILES =======================================\e[00m" 

#look for private keys 
privatekeyfiles=$(grep -rl "PRIVATE KEY-----" /home 2>/dev/null)
if [ "$privatekeyfiles" ]; then
                echo -e "\e[00;33m[+] Private SSH keys found!:\e[00m\n$privatekeyfiles"
                echo -e "\n"
fi


#look for AWS keys 
awskeyfiles=$(grep -rli "aws_secret_access_key" /home 2>/dev/null)
if [ "$awskeyfiles" ]; then
                echo -e "\e[00;33m[+] AWS secret keys found!:\e[00m\n$awskeyfiles"
                echo -e "\n"
fi

#look for git credential files 
gitcredfiles=$(find / -name ".git-credentials" 2>/dev/null)
if [ "$gitcredfiles" ]; then
                echo -e "\e[00;33m[+] Git credentials saved on the machine!:\e[00m\n$gitcredfiles"
                echo -e "\n"
fi

#list all world-writable files excluding /proc and /sys
wwfiles=$(find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;)
if [ "$wwfiles" ]; then
                echo -e "\e[00;31m[-] World-writable files (excluding /proc and /sys):\e[00m\n$wwfiles" 
                echo -e "\n"
fi

#search for the word passowrd in all php files
phppass=$(find / -maxdepth 5 -name *.php -type f -exec grep -Hn password {} \; 2>/dev/null)
if [ "$phppass" ]; then
                echo -e "\e[00;31m[-] Php files containing the word password:\e[00m\n$phppass" 
                echo -e "\n"
fi
}

main(){
        start
        system_info
        user_info
        environ_info
        networking_info
        software_configs
        interesting_files
        end
}
main




