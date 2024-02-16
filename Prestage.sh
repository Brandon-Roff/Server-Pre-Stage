#!/bin/sh
# This script is used to prestage the files for the installation of the Sever

#Remove needtoresart
sudo apt purge needrestart -y > /dev/null

#Install Nala
echo ""
echo " Installing Nala..."
echo "-------------------------"
sudo apt-get install -y nala >/dev/null


#Check if Nala is installed
echo " Checking if Nala is installed..."
echo "-------------------------------------"
if [ -x "$(command -v nala)" ]; then
  echo " Nala is installed ✅"
  echo "-------------------------------------"
else
  echo " Nala is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

# Update the system
sudo nala update  >/dev/null
sudo nala upgrade -y >/dev/null


# Install and configure the SSH server
echo " Installing SSH..."
echo "-------------------------"
sudo nala install ssh -y > /dev/null
sudo rm -f /etc/ssh/sshd_config > /dev/null
cat << EOF | sudo tee -a /etc/ssh/sshd_config > /dev/null
#       $OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Protocol 2

Include /etc/ssh/sshd_config.d/*.conf

Port 99
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

LoginGraceTime 1m
PermitRootLogin yes
#StrictModes yes
MaxAuthTries 3
#MaxSessions 10
PasswordAuthentication yes

PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile     .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
HostbasedAuthentication no
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no


UsePAM yes


X11Forwarding yes

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server
EOF

# Reload the SSH server configuration
sudo systemctl daemon-reload

# Restart the SSH server
sudo systemctl restart sshd

#Check if SSH is installed
echo " Checking if SSH is installed..."
echo "-------------------------------------"
if [ -x "$(command -v ssh)" ]; then
  echo " SSH is installed ✅"
  echo "-------------------------------------"
else
  echo " SSH is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

# Install and Configure UFW
echo " Installing UFW..."
echo "-------------------------"
sudo nala install ufw -y >/dev/null
sudo ufw --force enable >/dev/null
ports=(22 80 443 8080 9090 10000)
for port in "${ports[@]}"; do
  sudo ufw allow $port/tcp > /dev/null
  echo "Port $port has been allowed"
done
sudo ufw reload

#Check if UFW is installed
echo " Checking if UFW is installed..."
echo "-------------------------------------"
if [ -x "$(command -v ufw)" ]; then
  echo " UFW is installed ✅"
  echo "-------------------------------------"
else
  echo " UFW is not installed ❌"
  echo "-------------------------------------"
fi

echo ""

# Install and Configure Fail2Ban
echo " Installing Fail2Ban..."
echo "-------------------------"
sudo nala install fail2ban -y > /dev/null
sudo rm -f /etc/fail2ban/jail.local > /dev/null
cat << EOF | sudo tee -a /etc/fail2ban/jail.local > /dev/null
[DEFAULT]

# SSH jail
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
action = %(action_mwl)s

# UFW jail
[ufw]
enabled = true
filter = ufw
logpath = /var/log/ufw.log
maxretry = 3
bantime = 3600
action = %(action_mwl)s

# Custom filter for Apache
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 6
bantime = 3600
findtime = 600

# IP Whitelisting
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
ignoreip = 192.168.1.1/24 10.0.0.1

# Reverse DNS Lookup
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
action = %(action_mwl)s[name=sshd]

# Multiple Actions
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
action = %(action_mwl)s[name=sshd], %(action_xarf)s

# Adjusting Ban Time and Retry Counts
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

# Regular Log Review
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
action = %(action_mwl)s
EOF

# Restart the Fail2Ban service
sudo systemctl restart fail2ban

#Check if Fail2Ban is installed
echo " Checking if Fail2Ban is installed..."
echo "-------------------------------------"
if [ -x "$(command -v fail2ban-server)" ]; then
  echo " Fail2Ban is installed ✅"
  echo "-------------------------------------"
else
  echo " Fail2Ban is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

# Install and Configure docker
echo " Installing Docker..."
echo "-------------------------"
sudo nala install docker docker-compose -y >> /dev/null
sudo usermod -aG docker $USER >> /dev/null

#Check if Docker is installed
echo " Checking if Docker is installed..."
echo "-------------------------------------"
if [ -x "$(command -v docker)" ]; then
  echo " Docker is installed ✅"
  echo "-------------------------------------"
else
  echo " Docker is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

#Check if Docker-compose is installed
echo " Checking if Docker-compose is installed..."
echo "-------------------------------------"
if [ -x "$(command -v docker-compose)" ]; then
  echo " Docker-compose is installed ✅"
  echo "-------------------------------------"
else
  echo " Docker-compose is not installed ❌"
  echo "-------------------------------------"
fi
echo ""


# Install and Configure Nginx
echo " Installing Nginx..."
echo "-------------------------"
sudo nala install nginx -y >> /dev/null
sudo rm -f /etc/nginx/sites-available/default
cat << EOF | sudo tee -a /etc/nginx/sites-available/default > /dev/null
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

# Restart the Nginx service
sudo systemctl restart nginx >> /dev/null

#Check if Nginx is installed
echo " Checking if Nginx is installed..."
echo "-------------------------------------"
if [ -x "$(command -v nginx)" ]; then
  echo " Nginx is installed ✅"
  echo "-------------------------------------"
else
  echo " Nginx is not installed ❌"
  echo "-------------------------------------"
fi
echo ""


# Instal and configure samba
echo " Installing Samba..."
echo "-------------------------"
sudo nala install samba-common -y >> /dev/null
sudo rm -f /etc/samba/smb.conf
cat << EOF | sudo tee -a /etc/samba/smb.conf > /dev/null
[global]
   workgroup = WORKGROUP
   server string = Samba Server %v
   netbios name = ubuntu
   security = user
   map to guest = bad user
   dns proxy = no
EOF
sudo mkdir -p /samba/anonymous

# Restart the Samba service
sudo systemctl restart smbd >> /dev/null

#Check if Samba is installed
echo " Checking if Samba is installed..."
echo "-------------------------------------"
if [ -x "$(command -v samba)" ]; then
  echo " Samba is installed ✅"
  echo "-------------------------------------"
else
  echo " Samba is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

#Install Tacticall RMM
echo " Installing Tacticall RMM..."
echo "-------------------------" 
wget https://raw.githubusercontent.com/netvolt/LinuxRMM-Script/main/rmmagent-linux.sh >> /dev/null
sudo bash rmmagent-linux.sh install amd64 "https://mesh.roftwares.com/meshagents?id=h7xJ3qhczsYCCImrCSmPq3%24dqJ%40qyDuqzjnvmRlcB1ZgVuirykisz7FC1zsh2R8O&installflags=2&meshinstall=6" "https://rmm-api.roftwares.com" 1 5 "9ca86b01567b6288d27b20ae0686ba1339379d92bc86ea0f1ef2778a9658ba8d" server >/dev/null

#Check if Tacticall RMM is Running
echo " Checking if Tacticall RMM is Running..."
echo "-------------------------------------"
if [ -x "systemctl status tacticalagent.service" ]; then
  echo " Tacticall RMM is Running ✅"
  echo "-------------------------------------"
else
  echo " Tacticall RMM is not Running ❌"
  echo "-------------------------------------"
fi
echo ""

# configure nano 
echo " Installing nano..."
echo "-------------------------"
sudo nala install nano -y >> /dev/null

sudo rm -f /etc/nanorc
cat << EOF | sudo tee -a /etc/nanorc > /dev/null

set autoindent
set constantshow
set linenumbers
set historylog
set matchbrackets
set mouse
set morespace
set nohelp
set nowrap
set smarthome
set smooth
set suspend
set tabsize 4
set tabstospaces
set titlecolor brightwhite,blue
EOF

#Check if nano is installed
echo " Checking if nano is installed..."
echo "-------------------------------------"
if [ -x "$(command -v nano)" ]; then
  echo " nano is installed ✅"
  echo "-------------------------------------"
else
  echo " nano is not installed ❌"
  echo "-------------------------------------"
fi

echo ""

# Install network tools
echo " Installing network tools..."
echo "-------------------------"
sudo nala install net-tools -y >> /dev/null

#Check if net-tools is installed
echo " Checking if net-tools is installed..."
echo "-------------------------------------"
if [ -x "$(command -v netstat)" ]; then
  echo " net-tools is installed ✅"
  echo "-------------------------------------"
else
  echo " net-tools is not installed ❌"
  echo "-------------------------------------"
fi

echo ""

# Install and configure FTP server
echo " Installing FTP server..."
echo "-------------------------"
sudo nala install vsftpd -y >> /dev/null
sudo rm -f /etc/vsftpd.conf

cat << EOF | sudo tee -a /etc/vsftpd.conf > /dev/null
listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
user_sub_token=$USER
local_root=/home/$USER/ftp
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO
EOF

sudo systemctl restart vsftpd >> /dev/null

#Check if vsftpd is installed
echo " Checking if vsftpd is installed..."
echo "-------------------------------------"
if [ -x "$(command -v vsftpd)" ]; then
  echo " vsftpd is installed ✅"
  echo "-------------------------------------"
else
  echo " vsftpd is not installed ❌"
  echo "-------------------------------------"
fi
echo ""



# Install Wazuh-Agent
echo " Installing Wazuh-Agent..."
echo "-------------------------"
sudo nala install curl apt-transport-https lsb-release gnupg2 -y 
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb && sudo WAZUH_MANAGER='176.58.109.209' WAZUH_AGENT_GROUP='default' dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb >> /dev/null
sudo systemctl daemon-reload >> /dev/null
sudo systemctl enable wazuh-agent >> /dev/null
sudo systemctl start wazuh-agent >> /dev/null

#Check if Wazuh-Agent is Running
echo " Checking if Wazuh-Agent is Running..."
echo "-------------------------------------"
if [ -x "systemctl status wazuh-agent" ]; then
  echo " Wazuh-Agent is Running ✅"
  echo "-------------------------------------"
else
  echo " Wazuh-Agent is not Running ❌"
  echo "-------------------------------------"
fi

echo ""

# Install and Configure ClamAV
echo " Installing ClamAV..."
echo "-------------------------"
sudo nala install clamav clamav-daemon -y >> /dev/null
sudo freshclam >> /dev/null
sudo systemctl start clamav-freshclam >> /dev/null
sudo systemctl enable clamav-freshclam >> /dev/null
sudo systemctl start clamav-daemon >> /dev/null
sudo systemctl enable clamav-daemon >> /dev/null

#Check if ClamAV is installed
echo " Checking if ClamAV is installed..."
echo "-------------------------------------"
if [ -x "$(command -v clamscan)" ]; then
  echo " ClamAV is installed ✅"
  echo "-------------------------------------"
else
  echo " ClamAV is not installed ❌"
  echo "-------------------------------------"
fi

echo ""


# Install and Configure Cockpit
echo " Installing Cockpit..."
echo "-------------------------"
sudo nala install cockpit -y >> /dev/null
sudo systemctl start cockpit >> /dev/null
sudo systemctl enable cockpit >> /dev/null
sudo ufw allow 9090/tcp >> /dev/null

echo ""

# Install and Configure Webmin
echo " Installing Webmin..."
echo "-------------------------"
sudo nala install webmin -y >> /dev/null
sudo ufw allow 10000/tcp >> /dev/null

#Check if Webmin is installed
echo " Checking if Webmin is installed..."
echo "-------------------------------------"
if [ wget -qO- https://localhost:10000 ]; then
  echo " Webmin is installed ✅"
  echo "-------------------------------------"
else
  echo " Webmin is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

#install and configure AppArmor
echo " Installing AppArmor..."
echo "-------------------------"
sudo nala install apparmor -y >> /dev/null
sudo systemctl start apparmor >> /dev/null
sudo systemctl enable apparmor >> /dev/null

#Check if AppArmor is installed
echo " Checking if AppArmor is installed..."
echo "-------------------------------------"
if [ -x "$(command -v apparmor)" ]; then
  echo " AppArmor is installed ✅"
  echo "-------------------------------------"
else
  echo " AppArmor is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

#install and configure rkHunter
#echo " Installing rkhunter..."
#echo "-------------------------"
#sudo nala install rkhunter -y >> /dev/null
#sudo rkhunter --update >> /dev/null
#sudo rkhunter --propupd >> /dev/null

#Check if rkhunter is installed
#echo " Checking if rkhunter is installed..."
#echo "-------------------------------------"
#if [ -x "$(command -v rkhunter)" ]; then
#  echo " rkhunter is installed ✅"
#  echo "-------------------------------------"
#else
#  echo " rkhunter is not installed ❌"
#  echo "-------------------------------------"
#fi
#echo ""



#Install and Configure AIDE
echo " Installing AIDE..."
echo "-------------------------"
sudo nala install aide -y >> /dev/null
sudo aideinit >> /dev/null
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz >> /dev/null
sudo aide --check >> /dev/null

#Check if AIDE is installed
echo " Checking if AIDE is installed..."
echo "-------------------------------------"
if [ -x "$(command -v aide)" ]; then
  echo " AIDE is installed ✅"
  echo "-------------------------------------"
else
  echo " AIDE is not installed ❌"
  echo "-------------------------------------"
fi
echo ""

#Install and Configure OpenVAS
echo " Installing OpenVAS..."
echo "-------------------------"
sudo nala install openvas -y >> /dev/null
sudo openvas-setup >> /dev/null

#Check if OpenVAS is installed
echo " Checking if OpenVAS is installed..."
echo "-------------------------------------"
if [ -x "$(command -v openvas)" ]; then
  echo " OpenVAS is installed ✅"
  echo "-------------------------------------"
else
  echo " OpenVAS is not installed ❌"
  echo "-------------------------------------"
fi


# Check if all the services are running
services=(ssh ufw fail2ban docker nginx smd tacticalagent.service vsftpd wazuh-agent clamav-freshclam clamav-daemon cockpit webmin apparmor aide openvas)
for service in "${services[@]}"; do
  if [ -x "systemctl status $service" ]; then
    echo "$service is running ✅"
  else
    echo "$service is not running ❌"
  fi
done
```











