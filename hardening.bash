#!/bin/bash

# Declare commands paths.
c_echo=$(which echo)
c_cat=$(which cat)
c_apt=$(which apt)
c_modprobe=$(which modprobe)
c_systemctl=$(which systemctl)
c_egrep=$(which egrep)
c_cp=$(which cp)
c_grep=$(which grep)
c_sysctl=$(which sysctl)
c_chmod=$(which chmod)
c_chown=$(which chown)
c_touch=$(which touch)
c_find=$(which find)
c_sed=$(which sed)
c_userdel=$(which userdel)
c_a2enmod=$(which a2enmod)
c_aideinit=$(which aideinit)
c_iptables=$(which iptables)
c_augenrules=$(which augenrules)
c_pkill=$(which pkill)
c_test=$(which test)
c_id=$(which id)
c_mkdir=$(which mkdir)
c_awk=$(which awk)
c_ls=$(which ls)
c_tee=$(which tee)
c_exec=$(which exec)


# Define message colors.
typeset F_FGREEN="\033[1;42m"
typeset F_FRED="\033[1;41m"
typeset F_RED=$(tput setaf 1)
typeset F_WARNING=$(tput setaf 3)
typeset F_GREEN="\033[1;32m"
typeset F_BLUE=$(tput setaf 4)
typeset F_OFF="\033[0m"


fcheck_error(){
    errorControl=${1};
    msgError=${2};

    if [ ${errorControl} -eq 0 ];
    then
        ${c_echo} -e "`date +"%Y-%m-%d %H:%M:%S"` ${F_GREEN}OK${F_OFF}: ${msgError}" | ${c_tee} -a  Install_log_${now}.log;
    else
        ${c_echo} -e "`date +"%Y-%m-%d %H:%M:%S"` ${F_RED}ERROR${F_OFF} : ErrorCode ${errorControl} : ${msgError}:" | ${c_tee} -a  Install_log_${now}.log;
        ${c_echo} -e "`date +"%Y-%m-%d %H:%M:%S"` ${F_RED}Do you want continue? ${F_OFF}[Y/N]: ";
        read opcion
        case ${opcion} in
        S|s|Y|y)
                ${c_echo} -e "`date +"%Y-%m-%d %H:%M:%S"`${F_RED} Continue with issues...${F_OFF}" | ${c_tee} -a  Install_log_${now}.log;
                return 0;
                continue;;
        N|n)
                ${c_echo} -e `date +'%Y-%m-%d %H:%M:%S'` "Press any key to exit ..." | ${c_tee} -a  Install_log_${now}.log;
                read stop;
                exit 1;;
        Q|q|X|x)
                ${c_echo} -e "                     " | ${c_tee} -a  Install_log_${now}.log
                exit 0;;
        *)
                exit 1;;
        esac
    fi
}

fcheck_and_back(){
    local file=${1}
    if [ -f ${file} ];
    then
        grants=$(ls -l ${file})  > /dev/null 2>&1
        hash=$(md5sum ${file} | ${c_awk} '{print $1}') > /dev/null 2>&1
        ${c_echo} ${grants} ${hash} >> ${pathbackup}/files_modified.log
        ${c_cp} ${file} ${pathbackup}/  > /dev/null 2>&1
    else
    return 1
    fi


}

# Check root user
fcheck_root_user(){
    iduser=$(${c_id} | ${c_awk} -F'[=(]' '{print $2}') ;
    if [ ${iduser} -gt 0 ];
    then
        ${c_echo} -e "===== ${F_RED} YOU MUST BE ROOT FOR RUN THIS SCRIPT ${F_OFF} =====" | ${c_tee} -a  Install_log_${now}.log;
        exit 1;
    fi
}

# Package Instalation.
f_package_instalation(){
    ${c_echo} "Are you sure to install necesary packages and remove innecesary packages? [ Y/N ]";
    read answer
    case ${answer} in
        S|s|Y|y) 
            pinstall=$(${c_cat} ${packages} | ${c_grep} ^1 | ${c_sed} ':a;N;$!ba;s/\n/ /g' | ${c_sed} 's/1\://g')
            puninstall=$(${c_cat} ${packages} | ${c_grep} ^0 | ${c_sed} ':a;N;$!ba;s/\n/ /g' | ${c_sed} 's/0\://g')

            ${c_apt} update -y
            ${c_apt} upgrade -y

            ${c_apt} install -y ${pinstall}
            ${c_apt} remove -y ${puninstall}

            ${c_apt} autoremove
            ;; 
        N|n)
            ${c_echo} "Continue without install packages..." | ${c_tee} -a  Install_log_${now}.log;
            ;;
        Q|q|X|x)
            ${c_echo} -e "                     "| ${c_tee} -a  Install_log_${now}.log;
            exit 0
            ;;
        *)
            ${c_echo} "Insert a valid value" | ${c_tee} -a  Install_log_${now}.log;
            exit 1
            ;;
    esac
}

f_backup_files(){
    # Backup files
    ${c_echo} "Do you want to make backup files? [ Y/N ]";
    read answer
    
    case ${answer} in
            S|s|Y|y)
                if [ ! -d ${pathbackup} ];
                then
                    ${c_mkdir} ${pathbackup}
                fi
                for i in `${c_echo} "${files}"`;
                do
                    fcheck_and_back ${i};
                    fcheck_error ${?} "Backup file ${i} ";
                done;;
        N|n)
                ${c_echo} "Continue without backup files..." | ${c_tee} -a  Install_log_${now}.log;;
        Q|q|X|x)
                ${c_echo} -e "                     "
                exit 0;;
        *)
                ${c_echo} "Insert a valid value" | ${c_tee} -a  Install_log_${now}.log;
                exit 1;;
    esac
}

f_hardening(){
    # Hardening
    ${c_echo} "${F_RED}This procedure cannot be reversed${F_OFF}"
    ${c_echo} "Do you want to start the hardening? [ Y/N ]";
    read answer
    case ${answer} in
        S|s|Y|y) 
            # Kernel Parámeters.
            ## disable dccp
            ${c_modprobe} -n -v dccp | ${c_grep} "^install /bin/true$" || ${c_echo} "install dccp /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable DCCP"; 
            ## disable sctp
            ${c_modprobe} -n -v sctp | ${c_grep} "^install /bin/true$" || ${c_echo} "install sctp /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable SCTP";
            ## disable rds
            ${c_modprobe} -n -v rds | ${c_grep} "^install /bin/true$" || ${c_echo} "install rds /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable RDS";
            ## disable tipc
            ${c_modprobe} -n -v tipc | ${c_grep} "^install /bin/true$" || ${c_echo} "install tipc /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable TIPC";
            ## disable cramfs
            ${c_modprobe} -n -v cramfs | ${c_grep} "^install /bin/true$" || ${c_echo} "install cramfs /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable CRAMFS";
            ## disable freevxfs
            ${c_modprobe} -n -v freevxfs | ${c_grep} "^install /bin/true$" || ${c_echo} "install freevxfs /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable freevxfs";
            ## disable jffs2
            ${c_modprobe} -n -v jffs2 | ${c_grep} "^install /bin/true$" || ${c_echo} "install jffs2 /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable jffs2";
            ## disable hfs
            ${c_modprobe} -n -v hfs | ${c_grep} "^install /bin/true$" || ${c_echo} "install hfs /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable HFS";
            ## disable hfsplus
            ${c_modprobe} -n -v hfsplus | ${c_grep} "^install /bin/true$" || ${c_echo} "install hfsplus /bin/true" >> /etc/modprobe.d/disprotocols.conf
             fcheck_error ${?} "Disable hfsplus";
            ## disable squashfs
            ${c_modprobe} -n -v squashfs | ${c_grep} "^install /bin/true$" || ${c_echo} "install squashfs /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable squashfs";
            ## disable udf
            ${c_modprobe} -n -v udf | ${c_grep} "^install /bin/true$" || ${c_echo} "install udf /bin/true" >> /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable UDF";
            ## disable usb-storage
            ${c_modprobe} -n -v usb-storage | ${c_grep} "^install /bin/true$" || ${c_echo} "install usb-storage /bin/true" >>  /etc/modprobe.d/disprotocols.conf
            fcheck_error ${?} "Disable usb-storage";
            ## disable automount
            ${c_systemctl} disable autofs.service
            fcheck_error ${?} "Disable automount";
            ## Core Dumps restricted
            ${c_egrep} -q "^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$" /etc/security/limits.conf && ${c_sed} -ri "s/^(\s*)\*\s+hard\s+core\s+\S+(\s*#.*)?\s*$/\1* hard core 0\2/" /etc/security/limits.conf || ${c_echo} "* hard core 0" >> /etc/security/limits.conf
            fcheck_error ${?} "Disable Hard Core Dump";
            ${c_egrep} -q "^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && ${c_sed} -ri "s/^(\s*)fs.suid_dumpable\s*=\s*\S+(\s*#.*)?\s*$/\1fs.suid_dumpable = 0\2/" /etc/sysctl.conf || ${c_echo} "fs.suid_dumpable = 0" >> /etc/sysctl.conf
            fcheck_error ${?} "Disable SUID Dumps";
            ## Dmesg information restricted.
            ${c_echo} "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf;
            fcheck_error ${?} "Dmesg information restricted";
            ## Disable SysRq key
            ${c_echo} "kernel.sysrq = 0" >> /etc/sysctl.conf;
            fcheck_error ${?} "Disable SysRq key";
            ## Disable addresses from proc.
            ${c_echo} "kernel.kptr_restrict = 1"  >> /etc/sysctl.conf;
            fcheck_error ${?} "Disable address from proc";
            ## ASLR.
            ${c_egrep} -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && ${c_sed} -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || ${c_echo} "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
            fcheck_error ${?} "Randomize VA Scpace";


            # NETWORK
            ## IPv4 parameters.
            ${c_echo} "net.ipv4.ip_forward=0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.route.flush=1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf;
            fcheck_error ${?} "Configure IPv4 Parameters.";
            ## IPv6 parameters.
            ${c_echo} "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.route.flush=1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.all.accept_source_route = 0"  >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.default.accept_source_route = 0"  >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf;
            ${c_echo} "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf;
            fcheck_error ${?} "Configure IPv6 Parameters.";


            # PERMISSIONS
            ## Repository files.
            ${c_chmod} 644 /etc/apt/apt.conf.d/20auto-upgrades
            fcheck_error ${?} "Changed permissions to /etc/apt/apt.conf.d/20auto-upgrades";
            ${c_chmod} 644 /etc/apt/apt.conf.d/10periodic
            fcheck_error ${?} "Changed permissions to /etc/apt/apt.conf.d/10periodic";
            ${c_chown} root:root /etc/apt/sources.list;
            fcheck_error ${?} "Changed permissions to /etc/apt/sources.list";
            ${c_chmod} og-rwx /etc/apt/sources.list;
            fcheck_error ${?} "Changed permissions to /etc/apt/sources.list";
            ## Configure permissions on grub.
            ${c_chmod} 660 /boot/grub/grub.cfg
            fcheck_error ${?} "Changed permissions to /boot/grub/grub.cfg";
            ## motd (message of the day)
            #${c_chmod} -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/motd
            #fcheck_error ${?} "Changed permissions to /etc/motd ";
            ${c_chmod} -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/issue
            fcheck_error ${?} "Changed permissions to /etc/issue ";
            ${c_chmod} -t,u+r+w-x-s,g+r-w-x-s,o+r-w-x /etc/issue.net
            fcheck_error ${?} "Changed permissions to /etc/issue.net ";
            ## Shadow files
            ${c_chown} root:shadow /etc/gshadow-
            fcheck_error ${?} "Changed permissions to /etc/gshadow- ";
            ${c_chmod} 640 /etc/gshadow-
            fcheck_error ${?} "Changed permissions to /etc/gshadow- ";
            ${c_chown} root:shadow /etc/shadow-
            fcheck_error ${?} "Changed permissions to /etc/shadow- ";
            ${c_chmod} 640 /etc/shadow-
            fcheck_error ${?} "Changed permissions to /etc/shadow- ";
            ## Passw files
            ${c_chown} root. /etc/passwd*
            ${c_chmod} 644 /etc/passwd*
            fcheck_error ${?} "Changed permissions to /etc/passwd*";
            ${c_chown} root. /etc/group*
            ${c_chmod} 644 /etc/group*
            fcheck_error ${?} "Changed permissions to /etc/group* ";
            ## Wrappers files.
            ${c_chown} root:root /etc/hosts.allow
            fcheck_error ${?} "Changed permissions to /etc/hosts.allow ";
            ${c_chmod} 644 /etc/hosts.allow
            fcheck_error ${?} "Changed permissions to /etc/hosts.allow ";
            ${c_chown} root:root /etc/hosts.deny
            fcheck_error ${?} "Changed permissions to /etc/hosts.deny ";
            ${c_chmod} 644 /etc/hosts.deny
            fcheck_error ${?} "Changed permissions to /etc/hosts.deny ";
            ## Home directories (By default 755)
            ${c_ls} -d /home/* ${pathbackup}/files_modified.log;
            ${c_chmod} 700 /home/*
            fcheck_error ${?} "Changed permissions to /home directories ";
            ## /usr directories.
            ${c_ls} -d /usr/sbin ${pathbackup}/files_modified.log;
            ${c_chmod} 750 /usr/sbin;
            fcheck_error ${?} "Changed permissions to /usr/sbin ";
            ${c_ls} -d /usr/local/bin/ ${pathbackup}/files_modified.log;
            ${c_chmod} 750 /usr/local/bin/;
            fcheck_error ${?} "Changed permissions to /usr/local/bin/ ";
            ${c_ls} -d /usr/local/sbin ${pathbackup}/files_modified.log;
            ${c_chmod} 750 /usr/local/sbin
            fcheck_error ${?} "Changed permissions to /usr/local/sbin ";
            ## Cron files (By default 644 in cron.d and 755 in scripts).
            ${c_touch} /etc/cron.deny;
            fcheck_error ${?} "Created /etc/cron.deny file";
            ${c_touch} /etc/cron.allow;
            fcheck_error ${?} "Created /etc/cron.allow file";
            ${c_touch} /etc/at.allow;
            fcheck_error ${?} "Created /etc/at.allow file";
            ${c_ls} -d /etc/cron.* ${pathbackup}/files_modified.log;
            ${c_chmod} og-rwx /etc/crontab;
            fcheck_error ${?} "Changed permissions to /etc/crontab ";
            ${c_chmod} og-rwx /etc/cron.*;
            fcheck_error ${?} "Changed permissions to /etc/cron.* ";
            ${c_chmod} og-rwx /etc/cron.allow;
            fcheck_error ${?} "Changed permissions to /etc/cron.allow ";
            ${c_chmod} og-rwx /etc/cron.deny;
            fcheck_error ${?} "Changed permissions to /etc/cron.deny ";
            ${c_chmod} og-rwx /etc/at.allow;
            fcheck_error ${?} "Changed permissions to /etc/at.allow ";
            ## Log files
            ${c_find} /var/log -type f >> ${pathbackup}/files_modified.log
            ${c_find} /var/log -type f -exec chmod g-wx,o-rwx {} +;
            fcheck_error ${?} "Changed permissions to /var/log files ";
            ${c_find} /var/log/* -type d -exec chmod g-wx,o-rwx {} +;
            ${c_find} /var/log -type d >> ${pathbackup}/files_modified.log
            fcheck_error ${?} "Changed permissions to /var/log directories ";
            ${c_chmod} 750 /var/log
            fcheck_error ${?} "Changed permissions to /var/log directory ";
            ${c_chmod} 660 /var/log/wtmp
            fcheck_error ${?} "Changed permissions to /var/log/wtmp ";
            ## SSH Files
            ${c_chown} root:root /etc/ssh/sshd_config
            ${c_chmod} og-rwx /etc/ssh/sshd_config
            fcheck_error ${?} "Changed permissions to /etc/ssh/sshd_config ";
            ## /var/tmp
            ${c_chmod} o-w /var/tmp
            fcheck_error ${?} "Changed permissions to /var/tmp ";
            ## System.maps
            ${c_chmod} 600 /boot/System.map-*
            fcheck_error ${?} "Changed permissions to /boot/System.map-* ";


            # USERS
            ## Change first uid and first guid.
            ${c_sed} -i 's/1000/2000/g' /etc/adduser.conf
            fcheck_error ${?} "Changed first UID to 2000";
            ## Change permissions in dirmode. 
            ${c_sed} -ie '/^DIR_MODE=/ s/=[0-9]*\+/=700/' /etc/adduser.conf
            fcheck_error ${?} "Changed /home directory mode to 700 ";
            ## Change mask 
            ${c_sed} -ie '/^UMASK\s\+/ s/022/027/' /etc/login.defs
            fcheck_error ${?} "Changed umask to 027";
            ## Delete unnecesary.
            for i in games lp news uucp gnats irc list proxy; do ${c_userdel} -r $i 2> /dev/null; done;
            fcheck_error ${?} "Deleted unnecesary users";


            ## AIDE 
            ### --- Not Working with variables ----
            /bin/bash aideinit
            #${c_exec} ${c_aideinit}
            fcheck_error ${?} "Starting AIDE.";
            fcheck_error ${?} "Configuring AIDE.";
            ${c_cp} /var/lib/aide/aide.conf.autogenerated /etc/aide/aide.conf
            fcheck_error ${?} "Configuring AIDE..";
            ${c_echo} "05 4 * * 0 root /usr/bin/aide -c /etc/aide/aide.conf --check" >> /etc/crontab
            fcheck_error ${?} "Configuring AIDE...";
            ## Banners.
            ${c_echo} "== RESTRICTED SYSTEM ==" > /etc/issue
            ${c_echo} "== RESTRICTED SYSTEM ==" > /etc/issue.net
            fcheck_error ${?} "Changed banners";
            ## LOGROTATE
            ${c_sed} -i 's/664/660/g' /etc/logrotate.conf
            ${c_sed} -i 's/^#compress/compress/g' /etc/logrotate.conf
            fcheck_error ${?} "Configured logrotate";
            ## SSH config
            ${c_sed} -ie '/^#Banner none/ s/^#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Show Banner.";
            ${c_sed} -i '/ssh_host_ed25519_key/d' /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Disable Hotkeys";
            ${c_sed} -i '/ssh_host_dsa_key/d' /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Disable DSA key.";
            ${c_sed} -i '/^Ciphers/d' /etc/ssh/sshd_config
            ${c_echo} "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Config Ciphers to aes128-ctr,aes192-ctr,aes256-ctr";
            ${c_sed} -i '/^MACs/d' /etc/ssh/sshd_config
            ${c_echo} "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Config MAC algorithms ";
            ${c_sed} -i '/^Kexalgorithms/d' /etc/ssh/sshd_config
            ${c_echo} "Kexalgorithms diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" >>  /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Config Diffie Hellman groups ";
            ${c_sed} -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config || ${c_echo} "X11Forwarding no" >> /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Disable X11";
            ${c_sed} -i '/^#PermitRootLogin/d' /etc/ssh/sshd_config && ${c_echo} "PermitRootLogin no" >> /etc/ssh/sshd_config      
            fcheck_error ${?} "SSH: Disable root access";
            ${c_echo} "AddressFamily inet" >> /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Config AddressFamily to IPv4 only.";
            ${c_echo} "LoginGraceTime 55s" >> /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Change Login display time to 55\"";
    #       ${c_echo} "AllowGroups ${group}" >> /etc/ssh/sshd_config
    #       fcheck_error ${?} "SSH: Access only from sshaccess group.";
            ${c_echo} "Protocol 2" >> /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Forced to use Protocol v2 only";
            ${c_echo} "HostbasedAuthentication no" >> /etc/ssh/sshd_conf
            fcheck_error ${?} "SSH: Disable authentication with public key";
            ${c_echo} "IgnoreRhosts yes" >> /etc/ssh/sshd_config
            fcheck_error ${?} "SSH: Ignore .rhosts and .shosts files";
            ${c_echo} "UseDNS no" >>  /etc/ssh/sshd_config;
            fcheck_error ${?} "SSH: Disable DNS to SSH";
            ${c_echo} "MaxAuthTries 4" >> /etc/ssh/sshd_config;
            fcheck_error ${?} "SSH: Changed authentication tries to 4.";
            ${c_echo} "ClientAliveInterval 300" >> /etc/ssh/sshd_config;
            ${c_echo} "ClientAliveCountMax 0" >> /etc/ssh/sshd_config;
            fcheck_error ${?} "SSH: Limit SSH sesión to 300\"";
            ## Auditd.
            ## Copy example audit.rule to /etc/audit/rules.d/audit.rules
            ${c_augenrules}
            fcheck_error ${?} "AUDIT: Generated rules";
            fcheck_and_back /etc/audit/audit.rules;
            fcheck_error ${?} "Backup file /etc/audit/auditd.conf ";
            fcheck_and_back /etc/audit/auditd.conf;
            fcheck_error ${?} "Backup file /etc/audit/audit.rules ";
            ${c_echo} "-e 2" >> /etc/audit/audit.rules
            fcheck_error ${?} "AUDIT: Make audit rules immutable ";
            ${c_echo} "space_left_action = email" >> 	/etc/audit/auditd.conf
            ${c_echo} "action_mail_acct = root" >> 	/etc/audit/auditd.conf
            ${c_echo} "max_log_file_action = keep_logs" >> 	/etc/audit/auditd.conf
            fcheck_error ${?} "AUDIT: Config audit rules"
            ${c_sysctl} -p > /dev/null 2>&1 
            fcheck_error ${?} "Restart sysctl"
            ${c_echo} "${F_GREEN}---Hardening finished!---${F_OFF}"
            ;;
        N|n)
            ${c_echo} "...OK, exit";;
        Q|q|X|x)
            ${c_echo} -e "                     "
            exit 0;;
        *)
            ${c_echo} "Insert a valid value";
            exit 1;;
    esac
}

f_help(){
        echo -e "\n"
        echo "----------------------------------------------------------------------------------------------------------------"
        echo "                                          Ubuntu Hardening                                                      "
        echo "----------------------------------------------------------------------------------------------------------------"
        echo "Usage: /bin/bash ubuntuhard.bash [OPTIONS]                                                                      "
        echo "                                                                                                                "        
        echo "-a                       Do the complete procedure!                                                             "        
        echo "-b                       Harder it only!                                                                        "        
        echo "-f                       Do Backup files                                                                        "
        echo "-h                       Show help information.                                                                 "
        echo "-p                       The script installs and removes packages                                               "
        echo "                                                                                                                "        
        echo "                          Packelist content:                                                                    "
        echo "                              1:package = The Script will install the package.                                  "
        echo "                              0:package = The Script will remove the package.                                   "
        echo "                                                                                                                "        
        echo "-v                       Show version\'s script.                                                                "
        echo "----------------------------------------------------------------------------------------------------------------"
        echo -e "\n"

}

f_version(){
        echo "----------------------------------------------------------------------------------------------------------------"
        echo "                                          Ubuntu Hardening V 1.1                                                "
        echo "----------------------------------------------------------------------------------------------------------------"

}


fcheck_root_user

now=$(date +%Y%m%d)

while getopts 'bpvhfa' flag; do
  case "${flag}" in
  a)    
        files=$(${c_cat} files.txt)
        pathbackup="backupfiles"
        packages="packages.txt"
        f_package_instalation
        f_backup_files
        f_hardening 
  ;;

  b)    
        f_hardening
  ;;
  
  f) 
        files=$(${c_cat} files.txt)
        pathbackup="backupfiles"
        f_backup_files
  ;;

  h) 
        f_help
  ;;

  p)
        packages="packages.txt"
        f_package_instalation      
  ;; 
 
  v) 
        f_version
  ;;
  
  *) 
        f_help
  ;;
  esac
done