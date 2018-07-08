#!/bin/bash

#adm1 - CRIAR PAYLOADS
#adm2 - ATIVAR/DESATIVAR TCP SPEED
#adm3 - ATIVAR/DESATIVAR BAD UDP
#adm4 - FAILBAN SQUID PROTECTION
#adm5 - ATIVAR/DESATIVAR FIREWALL
#adm6 - VCN

comando="$1"

#------------------------------------------------------------#

function_teste () {
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
IP2=$(wget -qO- ipv4.icanhazip.com)
 if [[ "$IP" != "$IP2" ]]; then
IP="$IP2"
 fi
if [ ! -d /var ]; then
mkdir /var
fi
if [ ! -d /var/www ]; then
mkdir /var/www
fi
if [ ! -d /var/www/html ]; then
mkdir /var/www/html
fi
if [ ! -d /var/www/html/buscahost ]; then
mkdir /var/www/html/buscahost
fi
chmod -R 755 /var/www
val="$1"
mv /root/$val /var/www/html/buscahost/$val
echo ""
echo -e "ACESSE SUA LISTA DE PAYLOADS EM..."
echo -e "\033[1;36mhttp://$IP:81/buscahost/$val
ou
http://$IP:81/html/buscahost/$val
\033[0m"
}


function_payload () {
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
IP2=$(wget -qO- ipv4.icanhazip.com)
 if [[ "$IP" != "$IP2" ]]; then
IP="$IP2"
 fi
if [ ! -d /var ]; then
mkdir /var
fi
if [ ! -d /var/www ]; then
mkdir /var/www
fi
if [ ! -d /var/www/html ]; then
mkdir /var/www/html
fi
if [ ! -d /var/www/html/payload ]; then
mkdir /var/www/html/payload
fi
chmod -R 755 /var/www
val="$1"
mv /root/$val /var/www/html/payload/$val
echo ""
echo -e "ACEDA A LA LISTA DE PAYLOADS EN..."
echo -e "\033[1;36mhttp://$IP:81/payload/$val
ou
http://$IP:81/html/payload/$val
\033[0m"
read -p "enter"
}


if [ "$comando" = "adm1" ]; then
echo -e "\033[1;33m1 \033[1;31m
DIGITE UM HOST PARA CRIAR AS PAYLOADS GENERICAS! \033[1;33m
2 \033[1;31m
DIGITE SEM HTTP//
DIGITE APENAS A HOST"
sleep 3s
echo -e "\033[1;33m__________________________________________\033[1;32m"
echo -e "\033[1;36mCREADOR DE PAYLOADS"
echo -e "\033[1;33m__________________________________________\033[0m"
echo -e "\033[1;31mECRIBIR HOST\033[1;33m"
read -p ": " valor1
if [ "$valor1" = "" ]; then
echo -e "\033[1;31mNo Digito Nada!!!"
exit
fi
echo -e "\033[1;31mDIGITE SU IP\033[1;33m"
read -p ": " valor2
if [ "$valor2" = "" ]; then
valor2="127.0.0.1"
fi
echo -e "\033[1;31mESCOJA EL METODO DE ENCABEZADO...\033[1;33m
1-GET                           
2-CONNECT
3-PUT                          
4-OPTIONS
5-DELETE                     
6-HEAD
7-TRACE                      
8-PROPATCH
9-PATCH"
read -p ": " valor3
case $valor3 in
1)
req="GET"
;;
2)
req="CONNECT"
;;
3)
req="PUT"
;;
4)
req="OPTIONS"
;;
5)
req="DELETE"
;;
6)
req="HEAD"
;;
7)
req="TRACE"
;;
8)
req="PROPATCH"
;;
9)
req="PATCH"
;;
*)
req="GET"
;;
esac
echo -e "\033[1;31mPOR ULTIMO, ESCOJA METODO DE INJECCION!\033[1;33m
1-realData
2-netData
3-raw"
read -p ": " valor4
case $valor4 in
1)
in="realData"
;;
2)
in="netData"
;;
3)
in="raw"
;;
*)
in="netData"
;;
esac
sed -e "s;realData;abc;g" /bin/esqueleton > /tmp/esq1
sed -e "s;netData;abc;g" /tmp/esq1 > /tmp/esq2
sed -e "s;raw;abc;g" /tmp/esq2 > /tmp/esq3
sed -e "s;abc;$in;g" /tmp/esq3 > /tmp/esq
sed -e "s;get;$req;g" /tmp/esq > /tmp/es
sed -e "s;mhost;$valor1;g" /tmp/es > /tmp/es1
sed -e "s;mip;$valor2;g" /tmp/es1 > /root/$valor1.txt
testt=$(cat /root/$valor1.txt |egrep -o $valor1)
if [ "$testt" = "" ]; then
echo -e ""
echo -e "\033[1;33mALGO\033[1;36m ERRADO!\033[0m"
rm -rf /root/$valor1.txt
rm -rf /tmp/es
rm -rf /tmp/es1
rm -rf /tmp/esq
rm -rf /tmp/esq1
rm -rf /tmp/esq2
rm -rf /tmp/esq3
sleep 5s
exit
fi
echo -e "\033[1;33mTERMINADO, ARCHIVO DE PAYLOADS CREADO\033[1;36m /root/$valor1.txt\033[0m"
if [ -e /etc/apache2/apache2.conf ]; then
echo -e "\033[1;31mFue Identificado ServidorWEB En Su Vps, Desea Disponibilizar ese Archivo Online?\033[0m"
while true; do
read -p "[s/n]: " pay
case $pay in
(s|S)
function_payload $valor1.txt
break
;;
(N|n)
break
;;
*)
echo "Selecione 1 opcion"
;;
esac
done
fi
sleep 3s
rm -rf /tmp/es
rm -rf /tmp/es1
rm -rf /tmp/esq
rm -rf /tmp/esq1
rm -rf /tmp/esq2
rm -rf /tmp/esq3
echo -e "\033[0m"
exit
fi

#------------------------------------------------------------#

#------------------------------------------------------------#

fun1 () {
	echo ""
echo -e "\033[1;36mLa configuración de red TCP ya se ha agregado en el sistema!"
	echo ""
	read -p "Desea remover las configuraciones de TCP? [s/n]: " -e -i n res
echo -e "\033[0m"
case $res in
(S|s)
resposta0="s"
;;
*)
echo -e "\033[1;36mVolviendo\033[0m"
sleep 2s
exit
;;
esac
if [[ "$resposta0" = 's' ]]; then
		grep -v "^#ADM
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0" /etc/sysctl.conf > /tmp/syscl && mv /tmp/syscl /etc/sysctl.conf
sysctl -p /etc/sysctl.conf > /dev/null
		echo ""
echo "La configuración de red TCP se ha eliminado con éxito."
		echo ""
fi
}

fun2 () {
	echo ""
echo -e "\033[1;33mEste es un script experimental. Por su cuenta y riesgo!\033[0m"
sleep 1s
echo -e "\033[1;31mEsta secuencia de comandos cambiará algunas configuraciones de red 
do sistema para reducir la latencia y mejorar la velocidad\033[0m"
	echo ""
read -p "Continuar con la instalacion? [s/n]: " -e -i n resp
case $resp in
(s|S)
resposta="s"
;;
*)
echo -e "\033[1;33Instalação cancelada por usuário!"
echo -e "\033[1;31mRetornando!\033[0m"
sleep 1.5s
exit
;;
esac
if [[ "$resposta" = 's' ]]; then
	echo ""
echo -e "\033[1;31mModificando...\033[0m"
	echo " " >> /etc/sysctl.conf
	echo "#ADM" >> /etc/sysctl.conf
echo "net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0" >> /etc/sysctl.conf
echo ""
sysctl -p /etc/sysctl.conf
		echo ""
		echo "La configuración de red TCP se ha agregado con éxito."
fi
}


if [ "$comando" = "adm4" ]; then
echo -e "\033[01;33m________________________________________\033[01;37m"
echo -e "\033[1;33mEsse Script Foi Projetado Para Melhorar
A Latencia e Velocidade Do Servidor!"
echo -e "\033[01;33m________________________________________\033[01;37m"
sleep 1.5s
echo -e "
\033[1;36mAnalizando...\033[0m"
sleep 0.5s
if [[ `grep -c "^#ADM" /etc/sysctl.conf` -eq 0 ]]
then
fun2
exit
 else
fun1
exit
fi
fi


#------------------------------------------------------------#

udpinst () { 
echo -e "\033[1;36mO \033[1;31mBADVPN...\033[0m será instalado, que e nada mais que um programa que libera portas UDP no servidor e assim permitindo serviço VOIP como ligação no WhatsApp, Skype, etc. 
\033[1;31mAGUARDE...\033[0m"
sleep 5s
echo -e "\033[1;36mInstalando, aguarde....\033[0m"
echo -e "\033[7;31m\033[7;41m"
for prog in $(seq 10);
do
echo -n "||"
sleep 0.1s
echo -n "|"
sleep 0.1s
done
echo -e "\033[0m"
cd /root/
wget https://www.dropbox.com/s/nxf5s1lffmbikwq/badvpn-udpgw && mv /root/badvpn-udpgw /bin/badvpn-udpgw
sleep 3s
echo -e "Badvpn Istalado"
chmod 777 /bin/badvpn-udpgw
touch /etc/adm/modulo/udp
exit
}

if [ "$comando" = "adm5" ]; then
udpvar=$(netstat -nlpt | egrep -o udpgw)
 if [ -e /etc/adm/modulo/udp ]; then
  if [ "$udpvar" = "" ]; then
echo -e "\033[1;36mIniciando... BADVPN\033[0m"
sleep 1s
nohup badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 &
test=$(ps x |grep badvpn |grep -v grep |awk '{print $1}')
if [ "$test" != "" ]; then
echo -e "\033[1;36mBADVPN iniciado...\033[0m"
fi
sleep 1s
exit
 else
echo -e "\033[1;36mParando serviço BADVPN...\033[0m"
sleep 1s
kill -9 $(ps x | grep badvpn | grep -v grep | grep bin | awk '{print $1'}) > /dev/null 2>&1
killall badvpn-udpgw > /dev/null 2>&1
test=$(ps x |grep badvpn |grep -v grep |awk '{print $1}')
if [ "$test" = "" ]; then
echo -e "\033[1;36mBADVPN parado...\033[0m"
fi
exit
  fi
else
udpinst
 fi
fi

#------------------------------------------------------------#

fail_2ban () {
if [ "$5" != "" ]; then
echo -e "\033[1;31mNao Ha Mais de 4 Opcoes\033[0m"
else
if [ -e $HOME/f2b ]; then
rm -rf $HOME/f2b
fi
touch $HOME/f2b
if [ "$1" = "1" ]; then
echo "1" >> $HOME/f2b
fi
if [ "$1" = "2" ]; then
echo "2" >> $HOME/f2b
fi
if [ "$1" = "3" ]; then
echo "3" >> $HOME/f2b
fi
if [ "$1" = "4" ]; then
echo "4" >> $HOME/f2b
fi
if [ "$2" = "1" ]; then
echo "1" >> $HOME/f2b
fi
if [ "$2" = "2" ]; then
echo "2" >> $HOME/f2b
fi
if [ "$2" = "3" ]; then
echo "3" >> $HOME/f2b
fi
if [ "$2" = "4" ]; then
echo "4" >> $HOME/f2b
fi
if [ "$3" = "1" ]; then
echo "1" >> $HOME/f2b
fi
if [ "$3" = "2" ]; then
echo "2" >> $HOME/f2b
fi
if [ "$3" = "3" ]; then
echo "3" >> $HOME/f2b
fi
if [ "$3" = "4" ]; then
echo "4" >> $HOME/f2b
fi
if [ "$4" = "1" ]; then
echo "1" >> $HOME/f2b
fi
if [ "$4" = "2" ]; then
echo "2" >> $HOME/f2b
fi
if [ "$4" = "3" ]; then
echo "3" >> $HOME/f2b
fi
if [ "$4" = "4" ]; then
echo "4" >> $HOME/f2b
fi
 fi
}

if [ "$comando" = "adm6" ]; then
 if [ -e /etc/adm/modulo/fail2ban ]; then
echo -e "Fail2ban Ativo!, Deseja Ver o Log?"
read -p "[1]-Ver o Log
[2]-Desinstalar" loog
case $loog in
1)
  if [ -e /etc/squid3/squid.conf ]; then
svar="squid3"
else
svar="squid"
  fi
tput setaf 7 ; tput setab 4 ; tput bold ; printf '%48s%s%-20s\n' "LOG PRINCIPAL FAIL2BAN:" ; tput sgr0
cat /var/log/fail2ban.log
read -p "Enter"
exit
;;
2)
apt-get remove fail2ban
rm /etc/adm/modulo/fail2ban
read -p "Enter"
exit
;;
esac
 fi
tput setaf 7 ; tput setab 4 ; tput bold ; printf '%48s%s%-20s\n' "FAILBAN PROTECTION     " ; tput sgr0
tput setaf 2 ; tput bold ; echo ""
echo "Este é o FAILBAN PROTECTION, criado unicamente para proteger seu  "
echo "Sistema ,seu objetivo é analizar os LOGS DE ACESSO e bloquear toda e"
echo "qualquer ação suspeita e com isso aumentar 70% sua segurança."
read -p "Deseja Instalar o Fail2Ban?
[S/N]: " fail2ban
case $fail2ban in
(S|s)
apt-get install fail2ban -y
cd $HOME
wget -O fail2ban https://www.dropbox.com/s/qtz4aihjnwpth7y/fail2ban-0.9.4.tar.gz?dl=0
tar -xf $HOME/fail2ban
cd $HOME/fail2ban-0.9.4
./setup.py install
echo '[INCLUDES]
before = paths-debian.conf
[DEFAULT]
ignoreip = 127.0.0.1/8
# ignorecommand = /path/to/command <ip>
ignorecommand =
bantime  = 1036800
findtime  = 3600
maxretry = 5
backend = auto
usedns = warn
logencoding = auto
enabled = false
filter = %(__name__)s
destemail = root@localhost
sender = root@localhost
mta = sendmail
protocol = tcp
chain = INPUT
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
banaction = iptables-multiport
banaction_allports = iptables-allports
action_ = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mw = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
            %(mta)s-whois[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mwl = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             %(mta)s-whois-lines[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", logpath=%(logpath)s, chain="%(chain)s"]
action_xarf = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             xarf-login-attack[service=%(__name__)s, sender="%(sender)s", logpath=%(logpath)s, port="%(port)s"]
action_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"]
                %(mta)s-whois-lines[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", logpath=%(logpath)s, chain="%(chain)s"]
action_blocklist_de  = blocklist_de[email="%(sender)s", service=%(filter)s, apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]
action_badips = badips.py[category="%(__name__)s", banaction="%(banaction)s", agent="%(fail2ban_agent)s"]
action_badips_report = badips[category="%(__name__)s", agent="%(fail2ban_agent)s"]
action = %(action_)s' > /etc/fail2ban/jail.local
sleep 1s
;;
*)
exit
;;
esac
while true; do
clear
echo -e "Escolha Para Quais Serviços Ira Utilizar Fail2ban!\033[1;31m
[1]-ssh, [2]-squid, [3]-dropbear, [4]-apache.\033[1;32m
escolha 1 ou quantos for usar, colocando as opções: 1
opções: 2
opções: 1 3
opções: 1 4
opções: 1 2 3 4"
read -p "QUAIS OPÇÕES?
opções: " cacete
 if [ "$cacete" = "" ]; then
echo "NAO FOI ESCOLHIDO NADA!"
 else
fail_2ban $cacete

for options in `cat $HOME/f2b`; do
if [ "$options" = "1" ]; then
s1="ssh"
fi
if [ "$options" = "2" ]; then
s2="squid"
fi
if [ "$options" = "3" ]; then
s3="dropbear"
fi
if [ "$options" = "4" ]; then
s4="apache"
fi
done

echo -e "Voce escolheu Ativar o Fail2ban nos Seguintes Serviços:\033[1;31m "
touch $HOME/f1b
if [ "$s1" != "" ]; then
echo -ne "$s1 "
else
echo "1" >> $HOME/f1b
fi
if [ "$s2" != "" ]; then
echo -ne "$s2 "
else
echo "2" >> $HOME/f1b
fi
if [ "$s3" != "" ]; then
echo -ne "$s3 "
else
echo "3" >> $HOME/f1b
fi
if [ "$s4" != "" ]; then
echo -ne "$s4 "
else
echo "4" >> $HOME/f1b
fi
echo -e "\033[1;32m"
read -p "Confirma a escolha? 
[S/N]: " fnnnn
case $fnnnn in
(s|S)
break
;;
esac
fi
done

for options in `cat $HOME/f2b`; do
if [ "$options" = "1" ]; then
echo '[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
[sshd-ddos]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s' >> /etc/fail2ban/jail.local
fi
if [ "$options" = "2" ]; then
echo '[squid]
enabled = true
port     =  80,443,3128,8080
logpath = /var/log/squid/access.log' >> /etc/fail2ban/jail.local
fi
if [ "$options" = "3" ]; then
echo '[dropbear]
enabled = true
port     = ssh
logpath  = %(dropbear_log)s
backend  = %(dropbear_backend)s' >> /etc/fail2ban/jail.local
fi
if [ "$options" = "4" ]; then
echo '[apache-auth]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s' >> /etc/fail2ban/jail.local
fi
done
rm $HOME/f2b

for options in `cat $HOME/f1b`; do
if [ "$options" = "1" ]; then
echo '[sshd]
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
[sshd-ddos]
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s' >> /etc/fail2ban/jail.local
fi
if [ "$options" = "2" ]; then
echo '[squid]
port     =  80,443,3128,8080
logpath = /var/log/squid/access.log' >> /etc/fail2ban/jail.local
fi
if [ "$options" = "3" ]; then
echo '[dropbear]
port     = ssh
logpath  = %(dropbear_log)s
backend  = %(dropbear_backend)s' >> /etc/fail2ban/jail.local
fi
if [ "$options" = "4" ]; then
echo '[apache-auth]
port     = http,https
logpath  = %(apache_error_log)s' >> /etc/fail2ban/jail.local
fi
done
rm $HOME/f1b

echo '[selinux-ssh]
port     = ssh
logpath  = %(auditd_log)s
[apache-badbots]
port     = http,https
logpath  = %(apache_access_log)s
bantime  = 172800
maxretry = 1
[apache-noscript]
port     = http,https
logpath  = %(apache_error_log)s
[apache-overflows]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-nohome]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-botsearch]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-fakegooglebot]
port     = http,https
logpath  = %(apache_access_log)s
maxretry = 1
ignorecommand = %(ignorecommands_dir)s/apache-fakegooglebot <ip>
[apache-modsecurity]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-shellshock]
port    = http,https
logpath = %(apache_error_log)s
maxretry = 1
[openhab-auth]
filter = openhab
action = iptables-allports[name=NoAuthFailures]
logpath = /opt/openhab/logs/request.log
[nginx-http-auth]
port    = http,https
logpath = %(nginx_error_log)s
[nginx-limit-req]
port    = http,https
logpath = %(nginx_error_log)s
[nginx-botsearch]
port     = http,https
logpath  = %(nginx_error_log)s
maxretry = 2
[php-url-fopen]
port    = http,https
logpath = %(nginx_access_log)s
          %(apache_access_log)s
[suhosin]
port    = http,https
logpath = %(suhosin_log)s
[lighttpd-auth]
port    = http,https
logpath = %(lighttpd_error_log)s
[roundcube-auth]
port     = http,https
logpath  = %(roundcube_errors_log)s
[openwebmail]
port     = http,https
logpath  = /var/log/openwebmail.log
[horde]
port     = http,https
logpath  = /var/log/horde/horde.log
[groupoffice]
port     = http,https
logpath  = /home/groupoffice/log/info.log
[sogo-auth]
port     = http,https
logpath  = /var/log/sogo/sogo.log
[tine20]
logpath  = /var/log/tine20/tine20.log
port     = http,https
[drupal-auth]
port     = http,https
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s
[guacamole]
port     = http,https
logpath  = /var/log/tomcat*/catalina.out
[monit]
#Ban clients brute-forcing the monit gui login
port = 2812
logpath  = /var/log/monit
[webmin-auth]
port    = 10000
logpath = %(syslog_authpriv)s
backend = %(syslog_backend)s
[froxlor-auth]
port    = http,https
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s
[3proxy]
port    = 3128
logpath = /var/log/3proxy.log
[proftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(proftpd_log)s
backend  = %(proftpd_backend)s
[pure-ftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(pureftpd_log)s
backend  = %(pureftpd_backend)s
[gssftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s
[wuftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(wuftpd_log)s
backend  = %(wuftpd_backend)s
[vsftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(vsftpd_log)s
[assp]
port     = smtp,465,submission
logpath  = /root/path/to/assp/logs/maillog.txt
[courier-smtp]
port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s
[postfix]
port     = smtp,465,submission
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
[postfix-rbl]
port     = smtp,465,submission
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
maxretry = 1
[sendmail-auth]
port    = submission,465,smtp
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[sendmail-reject]
port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s
[qmail-rbl]
filter  = qmail
port    = smtp,465,submission
logpath = /service/qmail/log/main/current
[dovecot]
port    = pop3,pop3s,imap,imaps,submission,465,sieve
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s
[sieve]
port   = smtp,465,submission
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s
[solid-pop3d]
port    = pop3,pop3s
logpath = %(solidpop3d_log)s
[exim]
port   = smtp,465,submission
logpath = %(exim_main_log)s
[exim-spam]
port   = smtp,465,submission
logpath = %(exim_main_log)s
[kerio]
port    = imap,smtp,imaps,465
logpath = /opt/kerio/mailserver/store/logs/security.log
[courier-auth]
port     = smtp,465,submission,imap3,imaps,pop3,pop3s
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s
[postfix-sasl]
port     = smtp,465,submission,imap3,imaps,pop3,pop3s
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
[perdition]
port   = imap3,imaps,pop3,pop3s
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[squirrelmail]
port = smtp,465,submission,imap2,imap3,imaps,pop3,pop3s,http,https,socks
logpath = /var/lib/squirrelmail/prefs/squirrelmail_access_log
[cyrus-imap]
port   = imap3,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[uwimap-auth]
port   = imap3,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[named-refused]
port     = domain,953
logpath  = /var/log/named/security.log
[nsd]
port     = 53
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
logpath = /var/log/nsd.log
[asterisk]
port     = 5060,5061
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
           %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s"]
logpath  = /var/log/asterisk/messages
maxretry = 10
[freeswitch]
port     = 5060,5061
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
           %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s"]
logpath  = /var/log/freeswitch.log
maxretry = 10
[mysqld-auth]
port     = 3306
logpath  = %(mysql_log)s
backend  = %(mysql_backend)s
[recidive]
logpath  = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime  = 604800  ; 1 week
findtime = 86400   ; 1 day
[pam-generic]
banaction = %(banaction_allports)s
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s
[xinetd-fail]
banaction = iptables-multiport-log
logpath   = %(syslog_daemon)s
backend   = %(syslog_backend)s
maxretry  = 2
[stunnel]
logpath = /var/log/stunnel4/stunnel.log
[ejabberd-auth]
port    = 5222
logpath = /var/log/ejabberd/ejabberd.log
[counter-strike]
logpath = /opt/cstrike/logs/L[0-9]*.log
# Firewall: http://www.cstrike-planet.com/faq/6
tcpport = 27030,27031,27032,27033,27034,27035,27036,27037,27038,27039
udpport = 1200,27000,27001,27002,27003,27004,27005,27006,27007,27008,27009,27010,27011,27012,27013,27014,27015
action  = %(banaction)s[name=%(__name__)s-tcp, port="%(tcpport)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(udpport)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
[nagios]
logpath  = %(syslog_daemon)s     ; nrpe.cfg may define a different log_facility
backend  = %(syslog_backend)s
maxretry = 1
[directadmin]
logpath = /var/log/directadmin/login.log
port = 2222
[portsentry]
logpath  = /var/lib/portsentry/portsentry.history
maxretry = 1
[pass2allow-ftp]
# this pass2allow example allows FTP traffic after successful HTTP authentication
port         = ftp,ftp-data,ftps,ftps-data
# knocking_url variable must be overridden to some secret value in filter.d/apache-pass.local
filter       = apache-pass
# access log of the website with HTTP auth
logpath      = %(apache_access_log)s
blocktype    = RETURN
returntype   = DROP
bantime      = 3600
maxretry     = 1
findtime     = 1
[murmur]
port     = 64738
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol=tcp, chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol=udp, chain="%(chain)s", actname=%(banaction)s-udp]
logpath  = /var/log/mumble-server/mumble-server.log
[screensharingd]
logpath  = /var/log/system.log
logencoding = utf-8
[haproxy-http-auth]
logpath  = /var/log/haproxy.log' >> /etc/fail2ban/jail.local
rm -rf /root/f2b
service fail2ban restart
touch /etc/adm/modulo/fail2ban
echo -e "\033[1;36mInstalação Concluída\033[0m"
read -p "Enter" 
fi

#------------------------------------------------------------#

addfire () {
read -p "Digite su IP: " -e -i $1 ip
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

echo Configurando...
sleep 1
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -A OUTPUT -p tcp -d $ip --dport 443 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp -d $ip --dport 80 -m state --state NEW -j ACCEPT

iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 67 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 67 -m state --state NEW -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 3128 -j ACCEPT
iptables -A INPUT -p tcp --dport 8799 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 8080 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 3128 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 8799 -j ACCEPT
iptables -A FORWARD -p tcp --dport 8080 -j ACCEPT
iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp --dport 3128 -j ACCEPT
iptables -A FORWARD -p tcp --dport 8799 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

iptables -A INPUT -p tcp --dport 10000 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 10000 -j ACCEPT

echo -e "\033[1;36mFirewall moficicado
Portas 443 22 8799 8080 80 3128
Bloqueio ICMP
Bloqueio Torrent
Pequena proteçao DDoS
\033[0m"
touch /etc/adm/modulo/firewall
exit
}

resetfire () {
iptables -F
iptables -X
iptables -t nat -F
echo -e "\033[41;1;27mIPTABLES RESET NAT\033[0m"
sleep 1s
iptables -t nat -X
iptables -t mangle -F
echo -e "\033[41;1;27mIPTABLES RESET MANGLE\033[0m"
iptables -t mangle -X
echo -e "\033[41;1;27mIPTABLES FIREWALL RESETADO\033[0m"
rm -rf /etc/adm/modulo/firewall
exit
}

if [ "$comando" = "adm7" ]; then
AIP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
 if [[ "$AIP" = "" ]]; then
		AIP=$(wget -4qO- "http://whatismyip.akamai.com/")
 fi
 if [ -e /etc/adm/modulo/firewall ]; then
resetfire
else
addfire $AIP
 fi
fi


#------------------------------------------------------------#




if [ "$comando" = "adm9" ]; then
echo -e "\033[1;31mEsse Script Ira Ativar O Cache Em Teu Squid!"
sleep 1s
echo -e "\033[1;32mO script fara uma breve verificação!\033[0m"
 if [ -e /etc/squid/squid.conf ]; then
squid="1"
var="/etc/squid/squid.conf"
else
 if [ -e /etc/squid3/squid.conf ]; then
squid="2"
var="/etc/squid3/squid.conf"
else
echo -e "Nao Foi Identificado O Squid!"
exit
 fi
fi

abc="#CACHE DO SQUID"
if [[ `grep -c "^$abc" $var` -eq 1 ]]; then
echo -e "\033[1;32mSquid Ativo!\033[0m"
 if [[ -e "$var".bakk ]]; then
echo -e "\033[1;32mO sistema de squid cache já esta ativo em seu servidor!"
echo -e "\033[1;31mDeseja Desativar o SquidCache?\033[0m"
read -p "[s/n]: " squid
case $squid in
(s|S)
echo -e "\033[1;31mDesativando SquidCache!\033[0m"
sleep 1s
echo -e "\033[1;33mAguarde!\033[0m"
mv -f "$var".bakk $var
  if [ "$squid" = "1" ]; then
service squid restart
else
   if [ "$squid" = "2" ]; then
service squid3 restart
   fi
  fi
  if [ -e /etc/adm/modulo/cache ]; then
rm -rf /etc/adm/modulo/cache
  fi
echo -e "\033[1;31mFinalizado Alterações Removidas!\033[0m"
exit
;;
*)
exit
;;
esac
 fi
fi

echo -e "\033[1;31mAtivando SquidCache!\033[0m"
echo -e "Instalando Cache!"
echo "#CACHE DO SQUID
cache_mem 200 MB
maximum_object_size_in_memory 32 KB
maximum_object_size 1024 MB
minimum_object_size 0 KB
cache_swap_low 90
cache_swap_high 95" > /tmp/squid
 if [ "$squid" = "1" ]; then
echo "cache_dir ufs /var/spool/squid 100 16 256
access_log /var/log/squid/access.log squid" >> /tmp/squid
 else
  if [ "$squid" = "2" ]; then
echo "cache_dir ufs /var/spool/squid3 100 16 256
access_log /var/log/squid3/access.log squid
" >> /tmp/squid
  fi
 fi
cp $var "$var".bakup && mv -f /tmp/squid $var
cat "$var".bakup | grep -v "cache deny all" | grep -v grep | tee "$var".bakk
sqd=$(cat "$var".bakk)
echo "$sqd" >> $var
echo -e "\033[1;31mConfiguracoes adicionadas, Reiniciando Servicos!\033[0m"
 if [ "$squid" = "1" ]; then
service squid restart
 fi
 if [ "$squid" = "2" ]; then
service squid3 restart
 fi
echo -e "\033[1;32mCache Adicionado Com Sucesso!\033[0m"
 if [ ! -e /etc/adm/modulo/cache ]; then
touch /etc/adm/modulo/cache
 fi
sleep 1s
exit
fi
