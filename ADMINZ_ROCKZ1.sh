#!/bin/bash

cyan=$( tput setaf 6 );
blue=$( tput setaf 4 );
red=$( tput setaf 1 );
yellow=$( tput setaf 3 );
green=$( tput setaf 2 );
normal=$( tput sgr 0 );
osName=$( cat /etc/*os-release | grep ^NAME | cut -d '"' -f 2 );
LSB=/usr/bin/lsb_release

# Checking if running as root. If yes, asking to change to a non-root user.
# This verifies that a non-root user is configured and is being used to run
# the script.

if [ ${UID} != 0  ]
then
  echo "${red}
  You're running this script as non-root user.
  Please use a root user or use sudo to run this
  script as a root user.
  enter sudo privileges when prompted.
  ${normal}"
  #Pause so user can see output
  sleep 1
  exit
fi

if [ "$osName" != "Red Hat Enterprise Linux" ] && [ "$osName" != "CentOS Linux" ] && [ "$osName" != "Ubuntu" ];
then

  echo "${red}
  I'm not sure what operating system you're running.
  This script has only been tested for CentOS / Red Hat
  and Ubuntu.
  Please run it only on those operating systems.
  ${normal}"
exit
fi


for (( ; ; ))
do


printf "${cyan}
                   ##    #####   #    #     #    #    #  ######
                  #  #   #    #  ##  ##     #    ##   #      #
                 #    #  #    #  # ## #     #    # #  #     #
                 ######  #    #  #    #     #    #  # #    #
                 #    #  #    #  #    #     #    #   ##   #
                 #    #  #####   #    #     #    #    #  ######


                                                         #####    ####    ####   #    #  ######
                                                         #    #  #    #  #    #  #   #       #
                                                         #    #  #    #  #       ####       #
                                                         #####   #    #  #       #  #      #
                                                         #   #   #    #  #    #  #   #    #
                                                         #    #   ####    ####   #    #  ######

${normal}"








printf "${blue}WELCOME TO ADMINZ ROCKZ PLEASE SELECT A OPTION ${normal}\n"

printf "${yellow}
                                               [1]BASIC SERVER CONFIGURATION/INSTALL THE REQUIRED PACKAGES

                                               [2]BASIC SECURITY CONFIGURATION

                                               [3]INFORMATION GRABBER

                                               [4]SECURITY AUDIT

                                               [5]NETWORK/SERVER MONITORING

                                               [6]EXIT
${normal}
\n"



read -p  'OPTION:' option

if [ "${option}" = 6 ]
        then
        echo "${cyan} THANK YOU FOR USING THIS TOOL ${normal}"
        break
        fi


if [ "${option}" == 5 ]

then
echo "${yellow} this option  will send an email to a specified email address when ping cannot reach its destination. System admin can execute this in script regularly with use of a cron sc>
 The script first uses ping command to ping host or IP supplied as an argument.
In case that destination is unreachable a mail command will be used to notify system administrator
about this event.${normal}"

read -p '${yellow} ENTER YOUR EMAIL WHERE YOU WANT TO RECIEVE NOTIFICATIIONS ${normal}' email1
crontab -l > mycron
echo "* */1 * * * for i in $@
do
ping -c 1 google.com &> /dev/null

if [ $? -ne 0 ]; then
        echo "`date`: ping failed, host is down!" | mail -s " host is down!" ${email1}
fi
done" >> mycron
crontab mycron
rm mycron
fi






if [ "$option" == 1 ] && [ "$osName" == "Ubuntu" ]
        then
        apt update
        echo "${green} system updated ${normal}"
        cat timezone.txt
        read -p 'SELECT YOUR TIMEZONE:' timezone
        timedatectl set-timezone "$timezone"
        fi

if [ "$option" = 1 ] && [ "$osName" == "CentOS Linux" ] || [ "$osName" == "Red Hat Enterprise Linux" ]
        then
        dnf update
        echo "${green} system updated ${normal}"
        cat timezone.txt
        read -p 'SELECT YOUR TIMEZONE:' timezone
        timedatectl set-timezone "$timezone"
        echo "${green} TIMEZONE HAS BEEN SET SUCSESSFULLY ${normal}"
        fi

if [ "$option" == 2 ] && [ "$osName" == "Ubuntu" ]

        then
# Determine OS name and store it in osName variable


#################################################
#                 Ubuntu Section                #
#################################################

# If OS is Ubuntu, apply the security settings for Ubuntu


  echo "${green}  You're running $osName Linux. $osName security
  first measures will be applied.
  You will be prompted for your sudo password.
  Please enter it when asked.
  ${normal}
  "
  ##############################################
  #            Ubuntu Firewall Section         #
  ##############################################

  # Enabling ufw firewall and making sure it allows SSH
  echo "${yellow}  Enabling ufw firewall. Ensuring SSH is allowed.
  ${normal}"
  sudo ufw allow ssh
  sudo ufw --force enable
  echo "${green}
  Done configuring ufw firewall.
  ${normal}"
  #Pausing so user can see output
  sleep 1

  ##############################################
  #              Ubuntu SSH Section            #
  ##############################################

  # Checking whether an authorized_keys file exists in logged in user's account.
  # If so, the assumption is that key based authentication is set up.
  if [ -f /home/"$USER"/.ssh/authorized_keys ]
  then
    echo "${yellow}
    Locking down SSH so it will only permit key-based authentication.
    ${normal}"
    echo -n "${red}
    Are you sure you want to allow only key-based authentication for SSH?
    PASSWORD AUTHENTICATION WILL BE DISABLED FOR SSH ACCESS!
    (y or n):${normal} "
    read -p  'y/n:' answer
    # Putting relevant lines in /etc/ssh/sshd_config.d/11-sshd-first-ten.conf file
    if [ "$answer" == "y" ] || [ "$answer" == "Y" ] ;
    then
      echo "${yellow}
      Adding the following lines to a file in sshd_config.d
      ${normal}"
      echo "DebianBanner no
DisableForwarding yes
PermitRootLogin no
IgnoreRhosts yes
PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/11-sshd-first-ten.conf
      echo "${yellow}
      Reloading ssh
      ${normal}"
      # Restarting ssh daemon
      sudo systemctl reload ssh
      echo "${green}
      ssh has been restarted.
      # Pause so user can see output
      sleep 1
      ${normal}"

    else
      # User chose a key other than "y" for configuring ssh so it will not be set up now
      echo "${red}
      You have chosen not to disable password based authentication at this time.
      Please do so yourself or re-run this script when you're prepared to do so.
      ${normal}"
      # Pausing so user can see output
      sleep 1
    fi

  else
    # The check for an authorized_keys file failed so it is assumed key based auth is not set up
    # Skipping this configuration and warning user to do it for herself
    echo "${red}
    It looks like SSH is not configured to allow key based authentication.
    Please enable it and re-run this script.${normal}"
  fi

  ##############################################
  #          Ubuntu fail2ban Section           #
  ##############################################

echo "${yellow}
  Do you want email notifications?
  ${normal}"

read -p "Y/N:" yes

if [ "$yes" == "y" ] || [ "$yes" == "Y" ]
then

echo "${yellow} IF YOU ARE USING THIS TOOL FOR THE FIRST TIME PLEASE CHECK THE README FILE FOR EMAIL NOTIFICATIONS ESPECIALLY IF YOU ARE ADDING GMAIL ${normal}"
sleep 2
sudo apt-get install ssmtp -y
sudo apt-get update -y
sudo apt install mailutils -y

echo "${yellow}
  Installing sSMTP for email notifications
  ${normal}"

        fi

  read -p  "are you gonna use GMAIL? Y/N:" y
  if [ "$y" == "y" ] || [ "$y" == "Y" ]
  then
  read -p "YOUR GMAIL:" email
  read -p "YOUR GMAIL PASSWORD:" password

   echo "mailhub=smtp.gmail.com:587
AuthUser=$email
AuthPass=$password
FromLineOverride=YES
UseSTARTTLS=YES" | sudo tee /etc/ssmtp/ssmtp.conf
fi
   if [ "$y" == "n" ] || [ "$y" == "N" ]
   then
  read  -p "ENTER YOUR DOMAIN NAME INCLUDING TLD:" domain
  read -p "ENTER YOUR EMAIL ADDRESS FOR SSH NOTIFICATION:" email
  read -p "ENTER THE PASSWORD OF THE EMAIL:" password

echo "mailhub=mail.$domain:587
FromLineOverride=YES
AuthUser=$email
AuthPass=$password
UseSTARTTLS=YES" | sudo tee /etc/ssmtp/ssmtp.conf
fi
 read -p "ENTER THE EMAIL WHERE YOU WANT TO GET THE NOTIFICATIONS:" dstemail

  # Installing fail2ban and networking tools (includes netstat)
  echo "${yellow}
  Installing fail2ban and networking tools.
  ${normal}"
  sudo apt install fail2ban net-tools -y
  echo "${green}
  fail2ban and networking tools have been installed.
  ${normal}"
  # Setting up the fail2ban jail for SSH
  echo "${yellow}
  Configuring fail2ban to protect SSH.
  Entering the following into /etc/fail2ban/jail.local
  ${normal}"
  echo "# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
[ssh]
enabled  = true
banaction = iptables-multiport
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
findtime = 43200
bantime = 86400
destemail = $dstemail
mta = mail
action = %(action_mwl)s" | sudo tee /etc/fail2ban/jail.local
  # Restarting fail2ban
  echo "${green}
  Restarting fail2ban
  ${normal}"
  sudo systemctl restart fail2ban
  echo "${green}
  fail2ban restarted
  ${normal}"
  # Tell the user what the fail2ban protections are set to
  echo "${green}
  fail2ban is now protecting SSH with the following settings:
  maxretry: 5
  findtime: 12 hours (43200 seconds)
  bantime: 24 hours (86400 seconds)
  ${normal}"
  # Pausing so user can see output
  sleep 1

  ##############################################
  #           Ubuntu Overview Section          #
  ##############################################

#Explain what was done
echo "${green}
Description of what was done:
1. Ensured a non-root user is set up.
2. Ensured non-root user also has sudo permission (script won't continue without it).
3. Ensured SSH is allowed.
4. Ensured firewlld firewall is enabled.
5. Locked down SSH if you chose y for that step.
   a. Set SSH not to display banner
   b. Disabled all forwarding
   c. Disabled root login over SSH
   d. Ignoring rhosts
   e. Disabled password authentication
6. Installed fail2ban and configured it to protect SSH.
[note] For a default Ubuntu server installation, automatic security updates are enabled so no action was taken regarding updates.
${normal}"

#################################################
#          CentOS / Red Hat Section             #
#################################################

elif [ "$option" == 2 ] && [ "$osName" == "CentOS Linux" ] && [ "$osName" == "Red Hat Enterprise Linux" ]
then

  echo "${green}  You're running $osName. $osName security first
  measures will be applied.
  You will be prompted for your sudo password.
  Please enter it when asked.
  ${normal}
  #Pause so user can see output
  sleep 1
  "
  ##############################################
  #            CentOS Firewall Section         #
  ##############################################

  # Enabling firewalld firewall and making sure it allows SSH
  echo "${yellow}  Enabling firewalld firewall. Ensuring SSH is allowed.
  ${normal}"

  echo "${yellow}  Configuring firewalld to disallow Zone Drifting
  ${normal}"
  sudo sed -i.bak 's/#\?\(AllowZoneDrifting*\).*$/\1=no/' /etc/firewalld/firewalld.conf

  OUTPUT=$(sudo firewall-cmd --permanent --list-all | grep services)
  if echo "$OUTPUT" | grep -q "ssh"; then
    echo "${green}
    firewalld is already configured to allow SSH
    ${normal}"
    echo "${yellow}
    Ensuring firewalld is running
    ${normal}"
    sudo systemctl start firewalld
    echo "${green}
    Done configuring firewalld
    ${normal}"
    #Pause so user can see output
    sleep 1
  else
    echo "${yellow}
    Adding SSH to allowed protocols in firewalld
    ${normal}"
    sudo firewall-cmd --permanent --add-service=ssh
    echo "${yellow}
    Restarting firewalld
    ${normal}"
    sudo systemctl restart firewalld
    echo "${green}
    Done configuring firewalld
    ${normal}"
    #Pause so user can see output
    sleep 1
  fi

  ##############################################
  #              CentOS SSH Section            #
  ##############################################

  # Checking whether an authorized_keys file exists in logged in user's account.
  # If so, the assumption is that key based authentication is set up.
  if [ -f /home/"$USER"/.ssh/authorized_keys ]
  then
    echo "${yellow}
    Locking down SSH so it will only permit key-based authentication.
    ${normal}"
    echo -n "${red}
    Are you sure you want to allow only key-based authentication for SSH?
    PASSWORD AUTHENTICATIN WILL BE DISABLED FOR SSH ACCESS!
    (y or n):${normal} "
    read -r answer
    # Putting relevant lines in /etc/ssh/sshd_config.d/11-sshd-first-ten.conf file
    if [ "$answer" == "y" ] || [ "$answer" == "Y" ] ;then
      echo "${yellow}
      Making modifications to /etc/ssh/sshd_config.
      ${normal}"
      # Making backup copy 1 of sshd_config
      sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.0
      echo "
# Disabling all forwarding.
# [note] This setting overrides all other forwarding settings!
# This entry was added by first-ten.sh
DisableForwarding yes" | sudo tee -a /etc/ssh/sshd_config
      sudo sed -i.bak -e 's/#IgnoreRhosts/IgnoreRhosts/' -e 's/IgnoreRhosts\s\no/IgnoreRhosts\s\yes/' /etc/ssh/sshd_config
      sudo sed -i.bak1 '/^PermitRootLogin/s/yes/no/' /etc/ssh/sshd_config
      sudo sed -i.bak2 '/^PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config
      echo "${yellow}
      Reloading ssh
      ${normal}"
      # Restarting ssh daemon
      sudo systemctl reload sshd
      echo "${green}
      ssh has been restarted.
      ${normal}"
      #Pause so user can see output
      sleep 1
    else
      # User chose a key other than "y" for configuring ssh so it will not be set up now
      echo "${red}
      You have chosen not to disable password based authentication at this time and
      not to apply the other SSH hardening steps.
      Please do so yourself or re-run this script when you're prepared to do so.
      ${normal}"
      #Pause so user can see output
      sleep 1
  fi

  else
    # The check for an authorized_keys file failed so it is assumed key based auth is not set up
    # Skipping this configuration and warning user to do it for herself
    echo "${red}
    It looks like SSH is not configured to allow key based authentication.
    Please enable it and re-run this script.${normal}"
    #Pause so user can see output
    sleep 1
  fi

  ##############################################
  #          CentOS fail2ban Section           #
  ##############################################

  # Installing fail2ban and networking tools (includes netstat)
  echo "${yellow}
    Installing fail2ban.
    ${normal}"
    sudo dnf install fail2ban -y
      echo "${green}
      fail2ban has been installed.
      ${normal}"
      # Setting up the fail2ban jail for SSH
      echo "${yellow}
      Configuring fail2ban to protect SSH.
      Entering the following into /etc/fail2ban/jail.local
      ${normal}"
      echo "# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
[ssh]
enabled  = true
banaction = iptables-multiport
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
findtime = 43200
bantime = 86400" | sudo tee /etc/fail2ban/jail.local
      # Restarting fail2ban
      echo "${green}
      Restarting fail2ban
      ${normal}"
      sudo systemctl restart fail2ban
      echo "${green}
      fail2ban restarted
      ${normal}"
      # Tell the user what the fail2ban protections are set to
      echo "${green}
      fail2ban is now protecting SSH with the following settings:
      maxretry: 5
      findtime: 12 hours (43200 seconds)
      bantime: 24 hours (86400 seconds)
      ${normal}"
      #Pause so user can see output
      sleep 1

  ##############################################
  #            CentOS Updates Section          #
  ##############################################

  # Configuring automatic updates for CentOS / Red Hat
  echo "${yellow}
  Running system update and upgrade.
  ${normal}"
  sudo dnf upgrade
  echo "${green}
  Upgrade complete.
  ${normal}"
  echo "${yellow}
  Installing Auto-upgrade (dnf-automatic)
  ${normal}"
  sudo dnf install dnf-automatic -y
  echo "${green}
  dnf-automatic installed.
  ${normal}"
  echo "${yellow}
  Enabling automatic updates (dnf-automatic.timer)
  ${normal}"
  sudo systemctl enable --now dnf-automatic.timer
  echo "${green}
  Automatic updates enabled.
  ${normal}"
  echo "${green}
  You can check timer by running:
  sudo systemctl status dnf-automatic.timer
  Look for \"loaded\" under the Loaded: line
  and \"active\" under the Active: line.
  ${normal}"
  #Pause so user can see output
  sleep 1


  ##############################################
  #           CentOS Overview Section          #
  ##############################################

#Explain what was done
echo "${green}
Description of what was done:
1. Ensured a non-root user is set up.
2. Ensured non-root user also has sudo permission (script won't continue without it).
3. Ensured SSH is allowed.
4. Ensured firewlld firewall is enabled.
5. Locked down SSH if you chose y for that step.
   a. Disabled all forwarding
   b. Disabled root login over SSH
   c. Ignoring rhosts
   d. Disabled password authentication
6. Installed fail2ban and configured it to protect SSH.
[note] For a default Ubuntu server installation, automatic security updates are enabled so no action was taken regarding updates.
${normal}"
        fi

if [ "${option}" = 3 ]
then
        echo "${yellow}                                  SYS INFO  ${normal}
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
"

                  echo " System information "
        echo "Operating system : $(uname)"
        [ -x $LSB ] && $LSB -a || echo "$LSB command is not insalled (set \$LSB variable)"




echo "${yellow}                                          HOST INF0
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 ${normal}"
 dnsips=$(sed -e '/^$/d' /etc/resolv.conf | awk '{if (tolower($1)=="nameserver") print $2}')
        echo " Hostname and DNS information "
        echo "Hostname : $(hostname -s)"
        echo "DNS domain : $(hostname -d)"
        echo "Fully qualified domain name : $(hostname -f)"
        echo "Network address (IP) :  $(hostname -i)"
        echo "DNS name servers (DNS IP) : ${dnsips}"


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        devices=$(netstat -i | cut -d" " -f1 | egrep -v "^Kernel|Iface|lo")
        write_header " Network information "
        echo "Total network interfaces found : $(wc -w <<<${devices})"

        echo "*** IP Addresses Information ***"
        ip -4 address show

        echo "***********************"
        echo "*** Network routing ***"
        echo "***********************"
        netstat -nr

        echo "**************************************"
        echo "*** Interface traffic information ***"
        echo "**************************************"
        netstat -i

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


write_header " Free and used memory "
        free -m

    echo "*********************************"
        echo "*** Virtual memory statistics ***"
    echo "*********************************"
        vmstat
    echo "***********************************"
        echo "*** Top 5 memory eating process ***"
    echo "***********************************"
        ps auxf | sort -nr -k 4 | head -5
fi



if [ "${option}" = 4 ]
then

#------------------------------------------------------------------------------------------------------------------------------
# LBSA - Linux Basic Security Audit script
#------------------------------------------------------------------------------------------------------------------------------
# (c) Neale Rudd, 2008-2014, All rights reserved
# Download latest version from http://wiki.metawerx.net/wiki/LBSA
# Version 1.0.49
# Last updated 31/03/2014 5:25AM
#
# License: GPL v3
# Language: Shell script (bash)
# Required permissions: root or equivalent
# Script type: Check and report (no modifications are made to your system)
# Expected output: System Checks Completed
#
#
#------------------------------------------------------------------------------------------------------------------------------
# GUIDE
#------------------------------------------------------------------------------------------------------------------------------
# This script runs a series of basic linux security checks for Continuous
# Policy Enforcement (CPE).  It is, and will always be, a work in progress.
# The script was originally designed for use on Ubuntu, but will most likely
# work with other distros.
#
# The checks are far from exhaustive, but can highlight some basic setup
# issues from default linux installs and continuously enforce policies that
# you require in your specific environment.
#
# These checks include a subset of setup policies which I use for hardening
# server configurations.  As such, not all checks may be suitable for your
# environment.  For example, I don't allow root to login over SSH.  This may
# cause issues in your environment, or may be too restrictive for home use in
# some cases.
#
# If your own settings are more restrictive than these, or you have your own
# opinions on the settings, then modify this script to suit your own purposes.
# The main idea is to have a script that can enforce your own policies, and to
# run it regularly.  It is not necessary to follow my policies line-by-line.
#
# That said, this script should be suitable for most servers and home users
# "as-is", and for other admins it should give you some ideas for your own
# script, or at very least should make for a good read :-)
#
# Usage notes
# Ideally, this script would be called by a wrapper script of your own, which
# implements other checks more specific to your environment.  For example,
# if you run Apache, you may want to also check various folder permissions
# for Apache, then call this script as the final step of your own script.
# The script should be called regularly by cron or another scheduler and mail
# results to the administrator for review if the output changes.
#
# Criticisms and Counter Arguments (Feb 2013)
# In a comment on reddit, someones mentioned I ought to be dunked in honey
# and given to a colony of ants for writing lines that are longer than 80
# characters.  I agree and I now have a new fear on ants, thank you.
# Many lines are still longer than 80 characters.  Sorry, they just are.
# They also commented that passwd -l root will lock the root account from
# accessing the console.  This may be correct but I still recommend it.
# They also commented that if there is proper configuration management, then
# checking folder and file permissions is unnecessary.  I respectully disagree.
# If a system is breached, folder and file permissions may be changed and
# continuous policy checking is one way to be alerted to such a change quickly.
# Finally, they commented that "moving the SSH port from 22, which is asinine
# and provides no actual protection, simply makes it more difficult for people
# to manage those systems."  I also respectfully disagree with that - Port
# scanning bots hit port 22 and changing the default port helps to reduce
# automated threats.  Using a different port than 22 does not make it more
# difficult to manage systems if you are using a configuration management
# system or only have a single server to worry about.
# Ref: http://wiki.centos.org/HowTos/Network/SecuringSSH
#
# Disclaimer
# This is a free script provided to the community.  I am not responsible
# for any changes you make to your own system.  All opinions expressed are my
# own and are not necessarily the opinion of my employer, any company or
# organisation, or anyone else.
#
# Recent changes:
# 1.0.49 - Modified the hashing time suggestion for password-based logins
# 1.0.48 - Added test to find SSH-key based logins in non-home folders
# 1.0.47 - Switched to octal permissions
# 1.0.47 - Added warnings for BlowFish and SHA256 (SHA512 is available)
# 1.0.47 - Added recommendations for multiple hashing rounds in /etc/shadow
# 1.0.47 - Fixed bug which caused script to wait when outputing MD5 warning
# 1.0.46 - Added GPL v3 License
# 1.0.46 - Switched to use of check_path function instead of all the loops
# 1.0.45 - Changed use of ls to stat for 25% speed improvement
# 1.0.45 - Removed UUOC (useless use of cat)
# 1.0.45 - Commenting changes, reduced header comments width to <80 chars
#
# Other useful tools:
# * Bastille - hardening toolkit which covers lots of things not covered here
# * AIDE - monitor for file changes
# * fail2ban - scan logs, ban IP addresses
#
#
#------------------------------------------------------------------------------------------------------------------------------
# HOW TO USE
#------------------------------------------------------------------------------------------------------------------------------
# First, change parameters in the SETTINGS section to suit your environment,
# or call this script from a wrapper script that sets these variables.
#
# The script should be executed as root with bash.
# eg:
#   export LBSA_PERMITTED_LOGIN_ACCOUNTS="nrudd|sjackson"
#   bash sec_lbsa.sh
#
# A series of checks are executed
# No modifications are performed
#
# Running this script should produce no result except the phrase
# "System Checks Completed", at position 0 of the output.
# If there is any other output, then one or more warnings have been issued
#
# This can be used in cron or another scheduler to send a mail using a command
# like the following:
#   export LBSA_PERMITTED_LOGIN_ACCOUNTS="nrudd|sjackson";
#   LBSA_RESULTS=`bash sec_lbsa.sh`;
#   if [ "$LBSA_RESULTS" != "System Checks Completed" ]; then {your sendmail command here}; fi
#
#
#------------------------------------------------------------------------------------------------------------------------------
# SETTINGS
#------------------------------------------------------------------------------------------------------------------------------
# Settings are in if-blocks in case you want to call this script from a
# wrapper-script to avoid modifying it.  This allows for easier upgrades.

# Permitted Login Accounts
#    Specify the list of permitted logins in quotes, separated by |
#    If there are none, just leave it blank.  root should not be listed here, as we don't want root logging in via SSH either.
#    Valid examples:
#    LBSA_PERMITTED_LOGIN_ACCOUNTS=""
#    LBSA_PERMITTED_LOGIN_ACCOUNTS="user1"
#    LBSA_PERMITTED_LOGIN_ACCOUNTS="user1|user2|user3"
if [ ! -n "$LBSA_PERMITTED_LOGIN_ACCOUNTS" ]; then
    LBSA_PERMITTED_LOGIN_ACCOUNTS=""
fi

# If you aren't worried about allowing any/all SSH port forwarding, change this to yes
if [ ! -n "$LBSA_ALLOW_ALL_SSH_PORT_FORWARDING" ]; then
    LBSA_ALLOW_ALL_SSH_PORT_FORWARDING=no
fi

# Set this to yes to provide additional SSH recommendations
if [ ! -n "$LBSA_INCLUDE_EXTRA_SSH_RECOMMENDATIONS" ]; then
    LBSA_INCLUDE_EXTRA_SSH_RECOMMENDATIONS=no
fi



#------------------------------------------------------------------------------------------------------------------------------
# FUNCTIONS
#------------------------------------------------------------------------------------------------------------------------------

# Check permissions, owner and group, output warnings if they do not match
check_path() {

        PERMS=$1                        # recommended perms, eg: 755 (rwxr-xr-x)
        OWNER=$2                        # recommended owner
        GROUP=$3                        # recommended group
        CHECKPATH=$4            # path to check

        if [ -e $CHECKPATH ]; then

                # Run commands
                CPERMS=`stat -L -c %a $CHECKPATH`
                COWNER=`stat -L -c %U $CHECKPATH`
                CGROUP=`stat -L -c %G $CHECKPATH`

                # Compare
            if [ "$CPERMS" != "$PERMS" ]; then
                echo "Permission recommendation for [$CHECKPATH] is [$PERMS].  Current setting is [$CPERMS]"
        fi
            if [ "$COWNER" != "$OWNER" ]; then
                echo "Owner recommendation for [$CHECKPATH] is [$OWNER].  Current setting is [$COWNER]"
        fi
            if [ "$CGROUP" != "$GROUP" ]; then
                echo "Group recommendation for [$CHECKPATH] is [$GROUP].  Current setting is [$CGROUP]"
                fi
        fi
}


#------------------------------------------------------------------------------------------------------------------------------
# PASSWORD-BASED LOGIN HASH CHECK
#------------------------------------------------------------------------------------------------------------------------------

# ACCT_HASHING
# Make sure no account is using MD5, they should be upgraded to use SHA-512
# On older installs, when accounts were set up MD5 was the default, and this cannot be auto-upgraded during Linux updates
# man crypt for details
# 1 MD5, 2a BlowFish, 5 SHA-256, 6 SHA-512
# Ref: http://linux.die.net/man/3/crypt
# This is only really important if the /etc/shadow file is compromised after a breakin

if [ "`chpasswd --help | grep -e " \-s, "`" = "" -o "`chpasswd --help | grep -e " \-c, "`" = "" ]; then
        echo "WARNING: Your version of chpasswd does not support crypt-method or sha-round. You cannot use the latest hashing algorithms."
        HASH=":\$1\$"
        if [ "`fgrep "$HASH" /etc/shadow`" != "" ]; then
                echo "WARNING: Your passwords are stored as MD5 hashes.  Upgrade your kernel and your chpasswd command to enable SHA-256/SHA-512 hashes.  See: http://en.wikipedia.org/wiki/MD5, http://en.wikipedia.org/wiki/Rainbow_table"
        fi
else
        # MD5 is trivial to dehash within seconds using a rainbow table website so your plaintext passwords will be immediately readable
        HASH=":\$1\$"
        if [ "`fgrep "$HASH" /etc/shadow`" != "" ]; then
                echo "Warning: 1 or more account passwords use MD5 hashing.  When these accounts were set up, MD5 may have been the default but it is now easily decodable.  See: http://en.wikipedia.org/wiki/MD5, http://en.wikipedia.org/wiki/Rainbow_table";
                echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `fgrep "$HASH" /etc/shadow | cut -d ":" -f 1`
                echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
        fi
        HASH=":\$2a\$"
        if [ "`fgrep "$HASH" /etc/shadow`" != "" ]; then
                echo "Warning: 1 or more account passwords use BlowFish hashing.  This is a hashing algorithm designed in 1993 which the creator now recommends against using.  See: http://en.wikipedia.org/wiki/Blowfish_(cipher)";
                echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `fgrep "$HASH" /etc/shadow | cut -d ":" -f 1`
                echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
        fi
        HASH=":\$5\$"
        if [ "`grep "$HASH" /etc/shadow`" != "" ]; then
                echo "Warning: 1 or more account passwords use SHA-256 hashing.  SHA-512 is now available and uses more rounds to encrypt.  See: http://en.wikipedia.org/wiki/SHA-2";
                echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `fgrep "$HASH" /etc/shadow | cut -d ":" -f 1`
                echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
        fi
        HASH=":\$[0-9]"
        if [ "`grep "$HASH" /etc/shadow | grep -v "\$rounds="`" != "" ]; then
                echo "Warning: 1 or more account passwords are using a single round of hashing.  By increasing the number of hashing rounds, the computational time to verify a login password will increase and so will the computational time to reverse your hashes in case of a break-in.  See: http://en.wikipedia.org/wiki/Key_stretching";
                echo "Update these accounts to SHA512*200000 or stronger with chpasswd or passwd: " `grep "$HASH" /etc/shadow | cut -d ":" -f 1`
                echo "eg: chpasswd -c SHA512 -s 200000 <<<'user:newPassword'"
                echo "To see the time overhead for 200000 rounds, use this command ..."
                echo "time chpasswd -S -c SHA512 -s 200000 <<<'testuser:testpass'"
                echo "... change the -s parameter until the time is acceptable (eg: 0.2-0.5s) then use the new value to change your password."
        fi
fi


#------------------------------------------------------------------------------------------------------------------------------
# LOGINS
#------------------------------------------------------------------------------------------------------------------------------

# ROOT_NOT_LOCKED
# Make sure root account is locked (no SSH login, no console logins)
if [ "$LBSA_ALLOW_ROOT_LOGIN" != "true" ]; then passwd -S root | grep -v " L " | xargs -r -iLINE echo -e "Warning: root account is not locked and may allow login over SSH or other services.  Warning: When locked, root will not be able to log in at the console - make sure you have another user configured with sudo access.  Use [passwd -dl root] and [chage -E-1 root] to ensure the root account is locked but can still run cron jobs. [LINE]\n"; fi
# Fix: passwd -dl root; chage -E-1 root;

# ROOT_PASS_TIMING
# Make sure root password is set to 0 min 99999 max 7 warning -1 inactivity
# This may occur with ROOT_PASS_EXPIRES
passwd -S root | grep -v "0 99999 7 -1" | xargs -r -iLINE echo -e "Warning: root account has non-standard min/max/wait/expiry times set.  If the root password expires, cron jobs and other services may stop working until the password is changed. [LINE]\n"
# Fix: chage -m 0 -M 99999 -W 7 -I -1 root

# ROOT_PASS_EXPIRES
# Make sure root password is set to never expire
# This will normally occur with ROOT_PASS_TIMING
chage -l root | grep "Password expires" | grep -v never | xargs -r -iLINE echo -e "Warning: root password has an expiry date.  If the root password expires, cron jobs and other services may stop working until the password is changed. [LINE]\n"
# Fix: chage -m 0 -M 99999 -W 7 -I -1 root

# ROOT_ACCT_EXPIRES
# Make sure root account is set to never expire
chage -l root | grep "Account expires" | grep -v never | xargs -r -iLINE echo -e "Warning: root account has an expiry date -- though Linux surely protects against it expiring automatically [recommend setting it to never expire]. [LINE]\n"
# Fix: chage -E-1 root

# UNEXPECTED_USER_LOGINS_PRESENT
# Make sure the users that can log in, are ones we know about
# First, get user list, excluding any we already have stated should be able to log in
if [ "$LBSA_PERMITTED_LOGIN_ACCOUNTS" = "" ]; then
    USERLIST=`cat /etc/passwd | cut -f 1 -d ":"`
else
    USERLIST=`grep -v -w -E "$LBSA_PERMITTED_LOGIN_ACCOUNTS" /etc/passwd | cut -f 1 -d ":"`
fi
# Find out which ones have valid passwords
LOGINLIST=""
for USERNAME in $USERLIST
do
    if [ "`passwd -S $USERNAME | grep \" P \"`" != "" ]; then
        if [ "$LOGINLIST" = "" ]; then
            LOGINLIST="$USERNAME"
        else
            LOGINLIST="$LOGINLIST $USERNAME"
        fi
    fi
done
# Report
if [ "$LOGINLIST" != "" ]; then
    echo "Warning: the following user(s) are currently granted login rights to this machine: [$LOGINLIST]."
    echo "If users in this list should be allowed to log in, please add their usernames to the LBSA_PERMITTED_LOGIN_ACCOUNTS setting in this script, or set the environment variable prior to calling this script."
    echo "If an account is only used to run services, or used in cron, the account should not be permitted login rights, so lock the account with [passwd -dl <username>] to help prevent it being abused."
    echo "Note: after locking the account, the account will also be marked as expired, so use [chage -E-1 <username>] to set the account to non-expired/never-expire, otherwise services or cron tasks that rely on the user account being active will fail."
    echo ""
fi
# Fix: lock the specified accounts then set them non-expired, or specify the users that are listed are ok to log in by
# adding them to LBSA_PERMITTED_LOGIN_ACCOUNTS


#------------------------------------------------------------------------------------------------------------------------------
# Key-based logins that are not in the /home folder
# - Comment this section out if you have a valid need for these
#------------------------------------------------------------------------------------------------------------------------------

# List anything that's not in the home folder (protected above)
RESULT1=`grep -v ':/home/' /etc/passwd | cut -d : -f 6 | xargs -r -IFOLDER ls -al FOLDER/.ssh/authorized_keys 2>/dev/null`
RESULT2=`grep -v ':/home/' /etc/passwd | cut -d : -f 6 | xargs -r -IFOLDER ls -al FOLDER/.ssh/authorized_keys2 2>/dev/null`
if [ "$RESULT1" != "" -o "$RESULT2" != "" ]; then
        echo "Warning: the following files allow key-based login to your system and are not inside your /home folder"
        echo "Unless you created these logins intentionally, this could indicate a back-door into your system"
        if [ "$RESULT1" != "" ]; then echo "$RESULT1"; fi
        if [ "$RESULT2" != "" ]; then echo "$RESULT2"; fi
fi


#--------------------------------------------------------------------------------------------------------------
# General
#--------------------------------------------------------------------------------------------------------------

# Ensure /etc/hosts contains an entry for this server name
export LBSA_HOSTNAME=`hostname`
if [ "`grep -w "$LBSA_HOSTNAME$" /etc/hosts | grep -v "^#"`" = "" ]; then
        echo "There is no entry for the server's name [`hostname`] in /etc/hosts.  This may cause unexpected performance problems for local connections and NFS issues.  Add the IP and name in /etc/hosts, eg: 192.168.0.1 `hostname`";
        echo;
fi


#--------------------------------------------------------------------------------------------------------------
# SSH Setup
#--------------------------------------------------------------------------------------------------------------

# Ensure SSHD config is set securely (we do use TcpForwarding, so allow TcpForwarding)
if [ "`grep -E ^Port /etc/ssh/sshd_config`"                     = "Port 22"                    ]; then echo "SSHD Config: Port is set to default (22).  Recommend change to a non-standard port to make your SSH server more difficult to find/notice.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^ListenAddress /etc/ssh/sshd_config`"            = ""                           -a "$LBSA_ALLOW_SSH_ALL_ADDRESSES" != "true" ]; then echo "SSHD Config: ListenAddress is set to default (all addresses).  SSH will listen on ALL available IP addresses.  Recommend change to a single IP to reduce the number of access points.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^PermitRootLogin /etc/ssh/sshd_config`"         != "PermitRootLogin no"         -a "$LBSA_ALLOW_ROOT_LOGIN" != "true" -a "$LBSA_ALLOW_ROOT_LOGIN_SSHCERT" != "true" ]; then echo "SSHD Config: PermitRootLogin should be set to no (prefer log in as a non-root user, then sudo/su to root).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^PermitEmptyPasswords /etc/ssh/sshd_config`"    != "PermitEmptyPasswords no"    ]; then echo "SSHD Config: PermitEmptyPasswords should be set to no (all users must use passwords/keys).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^UsePrivilegeSeparation /etc/ssh/sshd_config`"  != "UsePrivilegeSeparation yes" ]; then echo "SSHD Config: UsePrivilegeSeparation should be set to yes (to chroot most of the SSH code, unless on older RHEL).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^Protocol /etc/ssh/sshd_config`"                != "Protocol 2"                 ]; then echo "SSHD Config: Protocol should be set to 2 (unless older Protocol 1 is really needed).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^X11Forwarding /etc/ssh/sshd_config`"           != "X11Forwarding no"           ]; then echo "SSHD Config: X11Forwarding should be set to no (unless needed).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^StrictModes /etc/ssh/sshd_config`"             != "StrictModes yes"            ]; then echo "SSHD Config: StrictModes should be set to yes (to check file permissions of files such as ~/.ssh, ~/.ssh/authorized_keys etc).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^IgnoreRhosts /etc/ssh/sshd_config`"            != "IgnoreRhosts yes"           ]; then echo "SSHD Config: IgnoreRhosts should be set to yes (this method of Authentication should be avoided).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^HostbasedAuthentication /etc/ssh/sshd_config`" != "HostbasedAuthentication no" ]; then echo "SSHD Config: HostbasedAuthentication should be set to no (this method of Authentication should be avoided).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^RhostsRSAAuthentication /etc/ssh/sshd_config`" != "RhostsRSAAuthentication no" ]; then echo "SSHD Config: RhostsRSAAuthentication should be set to no (this method of Authentication should be avoided).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^GatewayPorts /etc/ssh/sshd_config`"            != ""                           ]; then echo "SSHD Config: GatewayPorts is configured.  These allow listening on non-localhost addresses on the server.  This is disabled by default, but has been added to the config file.  Recommend remove this setting unless needed.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
if [ "`grep -E ^PermitTunnel /etc/ssh/sshd_config`"            != ""                           ]; then echo "SSHD Config: PermitTunnel is configured.  This allows point-to-point device forwarding and Virtual Tunnel software such as VTun to be used.  This is disabled by default, but has been added to the config file.  Recommend remove this setting unless needed.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi

# Commenting out Subsystem sftp is fairly pointless, SCP can still be used and most tools fall back to SCP automatically.  Additionally, it's possible to copy files using just SSH and redirection.
# if [ "`grep -E "^Subsystem sftp" /etc/ssh/sshd_config`"      != ""                           ]; then echo "SSHD Config: Comment out Subsystem SFTP (unless needed).  While enabled, any user with SSH shell access can browse the filesystem and transfer files using SFTP/SCP.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi

if [ "$LBSA_ALLOW_ALL_SSH_PORT_FORWARDING" != "yes" ]; then
    if [ "`grep -E ^AllowTcpForwarding /etc/ssh/sshd_config`" != "" ]; then
        if [ "`grep -E ^AllowTcpForwarding /etc/ssh/sshd_config`" != "AllowTcpForwarding no" ]; then
            if [ "`grep -E ^PermitOpen /etc/ssh/sshd_config`" = "" ]; then
                echo "SSHD Config: AllowTcpForwarding has been explicitly set to something other than no, but no PermitOpen setting has been specified.  This means any user that can connect to a shell or a forced-command based session that allows open port-forwarding, can port forward to any other accessible host on the network (authorized users can probe or launch attacks on remote servers via SSH port-forwarding and make it appear that connections are coming from this server).  Recommend disabling this feature by adding [AllowTcpForwarding no], or if port forwarding is required, providing a list of allowed host:ports entries with PermitOpen.  For example [PermitOpen sql.myhost.com:1433 mysql.myhost.com:3306].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."
                echo "* Note: If this is ok for this machine, set LBSA_ALLOW_ALL_SSH_PORT_FORWARDING=yes in this script, or set the environment variable prior to calling this script."
                echo
            fi
        fi
    fi
    if [ "`grep -E ^AllowTcpForwarding /etc/ssh/sshd_config`" = "" ]; then
        if [ "`grep -E ^PermitOpen /etc/ssh/sshd_config`" = "" ]; then
            echo "SSHD Config: AllowTcpForwarding is not specified, so is currently set to the default (yes), but no PermitOpen setting has been specified.  This means any user that can connect to a shell or a forced-command based session that allows open port-forwarding, can port forward to any other accessible host on the network (authorized users can probe or launch attacks on remote servers via SSH port-forwarding and make it appear that connections are coming from this server).  Recommend disabling this feature by adding [AllowTcpForwarding no], or if port forwarding is required, providing a list of allowed host:ports entries with PermitOpen.  For example [PermitOpen sql.myhost.com:1433 mysql.myhost.com:3306].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."
            echo "* Note: If this is ok for this machine, set LBSA_ALLOW_ALL_SSH_PORT_FORWARDING=yes in this script, or set the environment variable prior to calling this script."
            echo
        fi
    fi
fi

# Additional recommendations (These are not critical, but helpful.  These are typically not specified so strictly by default
# so will almost definitely require the user to change some of the settings manually.  They are in an additional section
# because they are not as critical as the settings above.
if [ "$LBSA_INCLUDE_EXTRA_SSH_RECOMMENDATIONS" = "yes" ]; then

    # Specify DenyUsers/DenyGroups for extra protection against root login over SSH
    if [ "$LBSA_ALLOW_ROOT_LOGIN" != "true" ]; then
        if [ "`grep -E ^DenyUsers /etc/ssh/sshd_config | grep root`"  = "" ]; then echo "SSHD Config: (Extra Recommendation) DenyUsers is not configured, or is configured but has not listed the root user.  Recommend adding [DenyUsers root] as an extra protection against root login (allow only su/sudo to obtain root access).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
        if [ "`grep -E ^DenyGroups /etc/ssh/sshd_config | grep root`" = "" ]; then echo "SSHD Config: (Extra Recommendation) DenyGroup is not configured, or is configured but has not listed the root group.  This means that if a user is added to the root group and are able to log in over SSH, then that login is effectively the same as a root login anyway.  Recommend adding [DenyUsers root] as an extra protection against root login (allow only su/sudo to obtain root access).  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
    fi

    # Get rid of annoying RDNS lookups which can cause timeouts if RDNS fails
    if [ "`grep -E "^UseDNS no" /etc/ssh/sshd_config`" = "" ]; then echo "SSHD Config: (Extra Recommendation) Set UseDNS no.  This will stop RDNS lookups during authentication.  Advantage 1: RDNS can be spoofed, which will place an incorrect entry in auth.log causing problems with automated log-based blocking of brute-force attack sources.  This change will eliminate the problem of RDNS spoofing.  Advantage 2: If RDNS fails, timeouts can occur during SSH login, preventing access to the server in worst cases.  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi

        # Reduce timeouts, max attempts and max number of concurrent logins
        LoginGraceTime=`grep ^LoginGraceTime /etc/ssh/sshd_config | tr -s " " | cut -d " " -f 2`
        if [ "$LoginGraceTime" = "" ]; then LoginGraceTime=120; fi
        MaxAuthTries=`grep ^MaxAuthTries /etc/ssh/sshd_config | tr -s " " | cut -d " " -f 2`
        if [ "$MaxAuthTries" = "" ]; then MaxAuthTries=6; fi
        MaxStartups=`grep ^MaxStartups /etc/ssh/sshd_config | tr -s " " | cut -d " " -f 2`
        if [ "$MaxStartups" = "" ]; then MaxStartups=10; fi
        MaxConcurrent=`expr "$MaxStartups" "*" "$MaxAuthTries"`
        if [ "$LoginGraceTime" -gt 30 ]; then echo "SSHD Config: (Extra Recommendation) LoginGraceTime is set to [$LoginGraceTime].  This setting can be used to reduce the amount of time a user is allowed to spend logging in.  A malicious user can use a large time window to more easily launch DoS attacks or consume your resources.  Recommend reducing this to 30 seconds (or lower) with the setting [LoginGraceTime 30].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
        if [ "$MaxAuthTries" -gt 4 ]; then echo "SSHD Config: (Extra Recommendation) MaxAuthTries is set to [$MaxAuthTries].  This allows the user $MaxAuthTries attempts to log in per connection.  The total number of concurrent login attempts your machine provides are ($MaxAuthTries MaxAuthTries) * ($MaxStartups MaxStartups) = $MaxConcurrent.  Note that only half of these will be logged.  Recommend reducing this to 4 (or lower) with the setting [MaxAuthTries 4].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
        if [ "$MaxStartups" -gt 3 ]; then echo "SSHD Config: (Extra Recommendation) MaxStartups is set to [$MaxStartups].  This allows the user to connect with $MaxStartups connections at the same time, before authenticating.  The total number of concurrent login attempts your machine provides are ($MaxAuthTries MaxAuthTries) * ($MaxStartups MaxStartups) = $MaxConcurrent.  Note that only half of these will be logged.  Recommend reducing this to 3 (or lower) with the setting [MaxStartups 3].  (Remember to restart SSHD with /etc/init.d/ssh restart after making changes)."; echo; fi
fi


#------------------------------------------------------------------------------------------------------------------------------
# PERMISSIONS / OWNERS / GROUPS  -  LINUX TOP LEVEL FOLDER
#------------------------------------------------------------------------------------------------------------------------------

check_path 755 root root /bin
check_path 755 root root /boot
check_path 755 root root /dev
check_path 755 root root /etc
check_path 755 root root /home
check_path 755 root root /lib
check_path 755 root root /lib64
check_path 755 root root /media
check_path 755 root root /mnt
check_path 755 root root /opt
check_path 555 root root /proc
check_path 700 root root /root
check_path 755 root root /run
check_path 755 root root /sbin
check_path 755 root root /srv
if [ "`stat -L -c %a /sys | grep -v "555"`" = "" ]; then
        # Allow sys to be 555 on newer distros like 12.10 onwards
        check_path 555 root root /sys
else
        check_path 755 root root /sys
fi
check_path 1777 root root /tmp
check_path 755 root root /usr
check_path 755 root root /var


#------------------------------------------------------------------------------------------------------------------------------
# PERMISSIONS / OWNERS / GROUPS  -  /ETC/SSH FOLDER
# Auto-fix all warnings in this area with: chmod 600 -R /etc/ssh; chown root:root -R /etc/ssh
#------------------------------------------------------------------------------------------------------------------------------

# 600 seems ok for the entire /etc/ssh folder.  I can connect to SSH OK, and make outgoing SSH connections OK as various users.
# This prevents non-root users from viewing or modifying SSH config details which could be used for attacks on other user
# accounts or potential privelege elevation.
check_path 600 root root /etc/ssh/moduli
check_path 600 root root /etc/ssh/sshd_config
check_path 600 root root /etc/ssh/sshd_host_dsa_key
check_path 600 root root /etc/ssh/sshd_host_rsa_key
check_path 600 root root /etc/ssh/sshd_host_ecdsa_key
check_path 600 root root /etc/ssh/sshd_host_key
check_path 600 root root /etc/ssh/blacklist.DSA-1024
check_path 600 root root /etc/ssh/blacklist.RSA-2048

# Ubuntu defaults private keys to 600 all other files to 644
# CentOS defaults public keys to 644 all other files to 600
check_path 600 root root /etc/ssh/ssh_config
check_path 600 root root /etc/ssh/ssh_host_dsa_key.pub
check_path 600 root root /etc/ssh/ssh_host_rsa_key.pub
check_path 600 root root /etc/ssh/ssh_host_ecdsa_key.pub
check_path 600 root root /etc/ssh/ssh_host_key.pub

# Ubuntu defaults folder to 755
# CentOS defaults folder to 755
check_path 600 root root /etc/ssh


#------------------------------------------------------------------------------------------------------------------------------
# PERMISSIONS / OWNERS / GROUPS  -  /ETC FOLDER SPECIAL FILES
#------------------------------------------------------------------------------------------------------------------------------

# These are just the Ubuntu defaults as per 12.04, ensure they haven't changed
check_path 440 root root /etc/sudoers
check_path 600 root root /etc/.pwd.lock
check_path 600 root root /etc/gshadow-
check_path 600 root root /etc/group-
check_path 600 root root /etc/shadow-
check_path 600 root root /etc/passwd-
check_path 640 root daemon /etc/at.deny
check_path 640 root fuse /etc/fuse.conf
check_path 640 root shadow /etc/shadow
check_path 640 root shadow /etc/gshadow
check_path 755 root root /etc/rmt
check_path 755 root root /etc/rc.local


#--------------------------------------------------------------------------------------------------------------
# CHECK FOR WORLD WRITABLE FOLDERS
#--------------------------------------------------------------------------------------------------------------

# Search for world writables in /etc or other folders
FOLDERS="/etc /bin /sbin /usr/bin"
for FOLDER in $FOLDERS
do
    # Find any files/folders in /etc which are world-writable
    # Future: also need to ensure files are owned by root.  If not, they may be able to be written to anyway.
    if [ "`find $FOLDER -type f -perm -002`" != "" ]; then
        echo "Warning: There are files under [$FOLDER] which are world writable.  It is a security risk to have world-writables in this folder, as they may be modified by other users and executed as root."
        echo "A complete list of these files follows:"
        find $FOLDER -type f -perm -002 | xargs -r ls -al
        echo ""
    fi
    if [ "`find $FOLDER -type d -perm -002`" != "" ]; then
        echo "Warning: There are folders in [$FOLDER] which are world writable.  It is a security risk to have world-writables in this folder, as they may be modified by other users and executed as root."
        echo "A complete list of these folders follows:"
        find $FOLDER -type d -perm -002
        echo ""
    fi
done


#--------------------------------------------------------------------------------------------------------------
# CHECK FOR INSECURE TMP AND SHM FOLDERS /tmp, /usr/tmp, /var/tmp, /dev/shm
#--------------------------------------------------------------------------------------------------------------

# TODO: this doesn't check /usr/tmp or /var/tmp yet

# /tmp

# First ensure that /tmp is a separate partition in mtab, otherwise the following tests are useless
if [ "$LBSA_ALLOW_NON_SEPARATE_TMP_PARTITION" != "true" ]; then
    if [ "`cat /etc/mtab | grep /tmp`" = "" ]; then
            echo "Warning: /tmp is not a separate partition, so cannot be marked nodev/nosuid/noexec.  Override this warning with LBSA_ALLOW_NON_SEPARATE_TMP_PARTITION=true";
    else

    # Ensure noexec
    # Note: Even though most admins recommend /tmp is noexec, the aptitude (apt-get) tool in do-release-upgrade mode
    # require exec permissions in /tmp and will stop with an error before installing the upgrade because /tmp has no exec permissions.
    # Workaround: Either edit /etc/apt/apt.conf and change the TempDir for apt to something else (such as /var/cache/apt/tmp), or before using the do-release-upgrade command, use this command to temporarily assign exec rights on /tmp: [mount -oremount,exec /tmp]
    if [ "`cat /etc/mtab | grep /tmp | grep noexec`" = "" ]; then
        echo "Warning: /tmp has EXECUTE permissions.  Recommend adding noexec attribute to mount options for /tmp, in /etc/fstab."
        echo "This change will help in preventing malicious users from installing and executing binary files from the folder."
        echo "To test, run these commands.  The output should say Permission denied if your system is already protected: cp /bin/ls /tmp; /tmp/ls; rm /tmp/ls;"
        echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /tmp] to avoid having to reboot."
        echo "Note: Even though most admins recommend /tmp is noexec, Ubuntu release upgrades require exec permissions in /tmp for some reason and will stop with an error before installing the upgrade because /tmp has no exec permissions."
        echo "Workaround: Either edit /etc/apt/apt.conf and change the TempDir for apt to something else (such as /var/cache/apt/tmp), or before using the do-release-upgrade command, use this command to temporarily assign exec rights on /tmp: [mount -oremount,exec /tmp]"
        echo ""
    fi

    # Ensure nosuid
    if [ "`cat /etc/mtab | grep /tmp | grep nosuid`" = "" ]; then
        echo "Warning: /tmp has SUID permissions.  Recommend adding nosuid attribute to mount options for /tmp, in /etc/fstab."
        echo "This change will help in preventing malicious users from setting SUID on files on this folder.  SUID files will run as root if they are owned by root."
        echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /tmp] to avoid having to reboot."
        echo ""
    fi

    # Ensure nodev
    if [ "`cat /etc/mtab | grep /tmp | grep nodev`" = "" ]; then
        echo "Warning: /tmp has DEVICE permissions.  Recommend adding nodev attribute to mount options for /tmp, in /etc/fstab."
        echo "This change will help in preventing malicious users from creating device files in the folder.  Device files should be creatable in temporary folders."
        echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /tmp] to avoid having to reboot."
        echo ""
        fi
    fi
fi

# /dev/shm

if [ "`cat /etc/mtab | grep /dev/shm`" != "" ]; then

    # Ensure noexec
    if [ "`cat /etc/mtab | grep /dev/shm | grep noexec`" = "" ]; then
        echo "Warning: /dev/shm has EXECUTE permissions.  Recommend adding noexec attribute to mount options for /dev/shm, in /etc/fstab."
        echo "This change will help in preventing malicious users from installing and executing malicious files from the folder."
        echo "To test, run these commands.  The output should say Permission denied if your system is already protected: cp /bin/ls /dev/shm; /dev/shm/ls; rm /dev/shm/ls;"
        if [ "`cat /etc/fstab | grep /dev/shm`" = "" ]; then
            echo "Note: you do not currently have /dev/shm listed in /etc/fstab, so it is being mounted with default options by Linux."
            echo "To fix, add this line to /etc/fstab, then remount it with [mount -oremount /dev/shm] to avoid having to reboot."
            echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
            echo ""
        else
            echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /dev/shm] to avoid having to reboot."
        fi
        echo ""
    fi

    # Ensure nosuid
    if [ "`cat /etc/mtab | grep /dev/shm | grep nosuid`" = "" ]; then
        echo "Warning: /dev/shm has SUID permissions.  Recommend adding nosuid attribute to mount options for /dev/shm, in /etc/fstab."
        echo "This change will help in preventing malicious users from setting SUID on files on this folder.  SUID files will run as root if they are owned by root."
        if [ "`cat /etc/fstab | grep /dev/shm`" = "" ]; then
            echo "Note: you do not currently have /dev/shm listed in /etc/fstab, so it is being mounted with default options by Linux."
            echo "To fix, add this line to /etc/fstab, then remount it with [mount -oremount /dev/shm] to avoid having to reboot."
            echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
            echo ""
        else
            echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /dev/shm] to avoid having to reboot."
        fi
        echo ""
    fi

    # Ensure nodev
    if [ "`cat /etc/mtab | grep /dev/shm | grep nodev`" = "" ]; then
        echo "Warning: /dev/shm has DEVICE permissions.  Recommend adding nodev attribute to mount options for /dev/shm, in /etc/fstab."
        echo "This change will help in preventing malicious users from creating device files in the folder.  Device files should be creatable in temporary folders."
        if [ "`cat /etc/fstab | grep /dev/shm`" = "" ]; then
            echo "Note: you do not currently have /dev/shm listed in /etc/fstab, so it is being mounted with default options by Linux."
            echo "To fix, add this line to /etc/fstab, then remount it with [mount -oremount /dev/shm] to avoid having to reboot."
            echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
            echo ""
        else
            echo "Tip: after adding the attribute, you can remount the partition with [mount -oremount /dev/shm] to avoid having to reboot."
        fi
        echo ""
    fi
fi


#--------------------------------------------------------------------------------------------------------------
# CHECK HEARTBEAT CONFIG (if present)
#--------------------------------------------------------------------------------------------------------------

if [ -e /etc/ha.d ]; then

    # Default is 755, but no reason for non-root users to have access to these details
        check_path 755 root root /etc/ha.d

    # Default is 600, but make sure it doesn't change
    # If details are known by user accounts, they can potentially send malicious heartbeat messages over UDP and cause havoc
    # If heartbeat is not installed, this file will not be present
        check_path 600 root root /etc/ha.d/authkeys
fi


#--------------------------------------------------------------------------------------------------------------
# CHECK DRBD CONFIG (if present)
#--------------------------------------------------------------------------------------------------------------

if [ -e /etc/drbd.conf ]; then

    # Default is 755, but if users have access to this file they can find out the shared-secret encryption key
        check_path 600 root root /etc/drbd.conf

    # Check that drbd.conf contains shared-secret keys, otherwise there is no protection against malicious external DRBD packets
    if [ "`grep shared-secret /etc/drbd.conf`" = "" ]; then
        echo "Warning: No shared-secret configured in /etc/drbd.conf.  There is no protection against malicious external DRBD packets which may cause data corruption on your DRBD disks.  Ensure that every disk is configured with a shared-secret attribute."; echo;
    fi



#--------------------------------------------------------------------------------------------------------------
# DONE
#--------------------------------------------------------------------------------------------------------------

echo "System Checks Completed"


#--------------------------------------------------------------------------------------------------------------
# Notes
#--------------------------------------------------------------------------------------------------------------

# Show account expiry/change info for all logins
#  cat /etc/passwd | cut -f 1 -d ":" | xargs -r -I USERNAME sh -c "(echo "USERNAME:"; chage -l USERNAME;)"
# Future: check sysctl network settings
# Done: implement more functions instead of repetitive code-blocks
# Future: since changing to sh, echo -e causes the text "-e" to be printed if using sh instead of bash.  Fix it.

fi

else
echo "WRONG INPUT"

fi
done
