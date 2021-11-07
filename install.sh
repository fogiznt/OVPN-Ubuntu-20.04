#!/bin/bash
RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
DEFAULT='\033[0m'

echo -e "${GREEN}  ____                     _   __   ___    _  __                      ";
echo -e " / __ \   ___  ___   ___  | | / /  / _ \  / |/ /                      ";
echo -e "/ /_/ /  / _ \/ -_) / _ \ | |/ /  / ___/ /    /                       ";
echo -e "\____/  / .__/\__/ /_//_/ |___/  /_/    /_/|_/                        ";
echo -e "       /_/                                                            ";
echo -e "  __  __   __               __               ___   ___      ___   ____";
echo -e " / / / /  / /  __ __  ___  / /_ __ __       |_  | / _ \    / _ \ / / /";
echo -e "/ /_/ /  / _ \/ // / / _ \/ __// // /      / __/ / // / _ / // //_  _/";
echo -e "\____/  /_.__/\_,_/ /_//_/\__/ \_,_/      /____/ \___/ (_)\___/  /_/  ";
echo -e "                                                                      ${DEFAULT}";

tls_settings(){
echo -e "Выберите версию TLS:\n1 - 1.3 - рекомендуется\n2 - 1.2"
until [[ $tls_ver =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 tls_ver;done

if [ "$tls_ver" = "1" ]; then
echo -e "Выберите реализацию:\n1 - TLS_AES_128_GCM_SHA256 - рекомендуется\n2 - TLS_AES_256_GCM_SHA384\n3 - TLS_CHACHA20_POLY1305_SHA256"
until [[ $tls_cipher =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 tls_cipher;done

elif [ "$tls_ver" = "2" ]; then
echo -e "Выберите реализацию:\n1 - TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 - рекомендуется\n2 - TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384\n3 - TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"
until [[ $tls_cipher =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 tls_cipher;done
tls_cipher=$((tls_cipher + 3))
fi

case "$tls_cipher" in
1) tls_cipher=TLS_AES_128_GCM_SHA256;;
2) tls_cipher=TLS_AES_256_GCM_SHA384;;
3) tls_cipher=TLS_CHACHA20_POLY1305_SHA256;;
4) tls_cipher=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256;;
5) tls_cipher=TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384;;
6) tls_cipher=TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256;;
esac }

data_channel_settings(){
echo -e "Выберите алгоритм шифрования:\n1 - AES-128-GCM - рекомендуется\n2 - AES-256-GCM\n3 - AES-128-CBC - для старых устройств\n4 - AES-256-CBC"
until [[ $data_cipher =~ ^[1-4]$ ]]; do read -rp "[1-4]:" -e -i 1 data_cipher;done
echo -e "Выберите алгоритм хэш-функции:\n1 - SHA256 - рекомендуется\n2 - SHA384\n3 - SHA512"
until [[ $data_digests =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 data_digests;done

case "$data_cipher" in
1) data_cipher=AES-128-GCM;;
2) data_cipher=AES-256-GCM;;
3) data_cipher=AES-128-CBC;;
4) data_cipher=AES-256-CBC;;
esac

case "$data_digests" in
1) data_digests=SHA256;;
2) data_digests=SHA384;;
3) data_digests=SHA512;;
esac }

pki_settings(){
echo -e "Выберите алгоритм сертификатов:\n1 - EC - рекомендуется\n2 - RSA"
until [[ $cert_algo =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 cert_algo;done

if [ "$cert_algo" = "1" ];then
echo -e "Выберите кривую:\n1 - prime256v1 - рекомендуется\n2 - secp384r1\n3 - secp521r1"
until [[ $cert_curve =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 cert_curve;done

case "$cert_curve" in
1) cert_curve=prime256v1;;
2) cert_curve=secp384r1;;
3) cert_curve=secp521r1;;
esac
fi

case "$cert_algo" in
1) cert_algo=ec;;
2) cert_algo=rsa;;
esac
}

clients_settings(){
ip=$(curl check-host.net/ip 2>/dev/null) >&- 2>&-
echo -e "Укажите внешний ip сервера"
read -rp "" -e -i $ip ip
echo -e "Выберите DNS сервер\n1 - CloudFlare - рекомендуется\n2 - Google DNS\n3 - Quad9\n4 - Quad9 без цензуры\n5 - Yandex Базовый\n6 - Yandex Безопасный\n7 - Yandex Семейный\n8 - AdGuard DNS - типа без рекламы\n9 - Указать свой DNS"
until [[ $dns_server =~ ^[1-9]$ ]]; do read -rp "[1-9]:" -e -i 1 dns_server;done
if [ "$dns_server" = "9" ];then read dns_server1;fi
case "$dns_server" in
1) dns_server=CloudFlare dns_server1=1.1.1.1 dns_server2=1.0.0.1;;
2) dns_server=Google\ DNS dns_server1=8.8.8.8 dns_server2=8.8.4.4;;
3) dns_server=Quad9 dns_server1=9.9.9.9 dns_server2=149.112.112.112;;
4) dns_server=Quad9\ без\ цензуры dns_server1=9.9.9.10 dns_server2=149.112.112.10;;
5) dns_server=Yandex\ Базовый dns_server1=77.88.8.8 dns_server2=77.88.8.1;;
6) dns_server=Yandex\ Безопасный dns_server1=77.88.8.88 dns_server2=77.88.8.2;;
7) dns_server=Yandex\ Семейный dns_server1=77.88.8.7 dns_server2=77.88.8.3;;
8) dns_server=AdGuard\ DNS dns_server1=94.140.14.14 dns_server2=94.140.15.15;;
esac }

network_settings(){
echo -e "Максимальное кол-во клиентов:\n1 - 253 - рекомендуется\n2 - 65533"
until [[ $subnet_mask =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 subnet_mask;done

case "$subnet_mask" in
1)subnet=10.8.8.0 subnet_mask=255.255.255.0;;
2)subnet=10.8.0.0 subnet_mask=255.255.0.0;;
esac
}

hmac_settings(){
echo -e "Дополнительная подпись HMAC к TLS-пакетам:\n1 - TLS-crypt - рекомендуется\n2 - TLS-auth\n3 - не использовать"
until [[ $tls_hmac =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 tls_hmac;done
case "$tls_hmac" in
1) tls_hmac=tls-crypt\ tls.key;;
2) tls_hmac=tls-auth\ tls.key\ 0;;
3) tls_hmac=Не\ используется;;
esac }


final_config(){
case "$cipher_base" in
1) if [ "$tls_ver" = "1" ];then cipher_base=TLS\ 1.3;else cipher_base=TLS\ 1.2;fi;;
2) cipher_base=Статичный\ ключ;;
3) cipher_base=Отсутствует;;
esac

echo -e "\nОзнакомтесь с устанавливаемой конфигурацией"
echo -e "-----------------------------------------------------------"
echo -e "Порт - ${GREEN}$(echo $proto | tr a-z A-Z):$port${DEFAULT}"
echo -e "Шифрование - ${GREEN}$cipher_base${DEFAULT}"
if [ "$cipher_base" = "TLS 1.3" ] || [ "$cipher_base" = "TLS 1.2" ];then
echo -e "Канал управления:\n	Алгоритм обмена ключами - ${GREEN}ECDH${DEFAULT}\n	Алгоритм аутентификации - ${GREEN}ECDSA${DEFAULT}"
echo -e "        Симметричное шифрование - ${GREEN}$(echo $tls_cipher | grep -o -P 'AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305|AES-128-GCM|AES-256-GCM|CHACHA20-POLY1305')${DEFAULT}"
echo -e "	Хэш-функция - ${GREEN}$(echo $tls_cipher | grep -o -P 'SHA256|SHA384')${DEFAULT}"
echo -e "Канал даннных:\n	Шифрование - ${GREEN}$(echo $data_cipher | grep -o -P 'AES-128-GCM|AES-256-GCM|AES-128-CBC|AES-256-CBC')${DEFAULT}"
echo -e "	Хэш-функция - ${GREEN}$(echo $data_digests | grep -o -P 'SHA256|SHA384|SHA512')${DEFAULT}"
fi
echo -e "Настройки PKI:\n        Алгоритм сертификатов - ${GREEN}$(echo $cert_algo | tr a-z A-Z)${DEFAULT}"
if [ "$cert_algo" = "ec" ];then echo -e "	Кривая - ${GREEN}$cert_curve${DEFAULT}";fi
echo -e "Клиентские настройки:\n        ip сервера - ${GREEN}$ip${DEFAULT}\n        DNS - ${GREEN}$dns_server${DEFAULT}"
echo -e "Дополнительные настройки:"
if [ "$cipher_base" = "TLS 1.3" ] || [ "$cipher_base" = "TLS 1.2" ];then echo -e "	HMAC подпись - ${GREEN}$tls_hmac${DEFAULT}";fi
echo -n -e "	Максимальное кол-во клиентов - "
if [ "$subnet_mask" = "255.255.255.0" ];then echo -e "${GREEN}253${DEFAULT}";else echo -e "${GREEN}65533${DEFAULT}";fi
echo "-----------------------------------------------------------"
echo -e "\nEnter - начать установку\nCtrl+C - отмена"
}

package_install(){
echo -n -e "${DEFAULT}Обновление списка пакетов ${DEFAULT}" & echo -e ${GREEN} $(apt update 2>/dev/null | grep packages | cut -d '.' -f 1 | tr -cd '[[:digit:]]') "${DEFAULT} пакетов могут быть обновлены."
echo -e "Установка пакетов: "

echo -n -e "               openvpn " & echo -n $(apt install openvpn -y >&- 2>&-)
if [ "$(dpkg --get-selections openvpn | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install openvpn ${DEFAULT}" ;fi

echo -n -e "               easy-rsa " & echo -n $(apt install easy-rsa -y >&- 2>&-)
if [ "$(dpkg --get-selections easy-rsa | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install easy-rsa ${DEFAULT}" ;fi

echo -n -e "               curl " & echo -n $(apt install curl -y >&- 2>&-)
if [ "$(dpkg --get-selections curl | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install curl ${DEFAULT}" ;fi

echo -n -e "               iptables-persistent "
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
apt install iptables-persistent -y >&- 2>&-
if [ "$(dpkg --get-selections iptables-persistent | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install iptables-persistent ${DEFAULT}" ;fi

echo -n -e "               apache2 " & echo -n $(apt install apache2 -y >&- 2>&-)
if [ "$(dpkg --get-selections apache2 | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install apache2 ${DEFAULT}" ;fi

echo -n -e "               zip " & echo -n $(apt install zip -y >&- 2>&-)
if [ "$(dpkg --get-selections zip | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install zip ${DEFAULT}" ;fi
}

cert_gen(){
echo -e "Генерация сертификатов: "

if [ "$cipher_base" = "1" ];then
cd /usr/share/easy-rsa/

echo "set_var EASYRSA_ALGO $cert_algo" >vars
if [ "$cert_algo" = "ec" ];then echo "set_var EASYRSA_CURVE prime256v1" >>vars;fi
SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars

./easyrsa init-pki >&- 2>&-

echo -n "               CA "
export EASYRSA_BATCH=1
./easyrsa build-ca nopass >&- 2>&-
cp pki/ca.crt /etc/openvpn/
if ! [ -f /etc/openvpn/ca.crt ];then echo -e "${RED}ОШИБКА, сертификат CA не сгенерирован. ${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi

echo -n -e "               Сертификат сервера "
./easyrsa build-server-full server nopass >&- 2>&-
cp pki/private/server.key /etc/openvpn
cp pki/issued/server.crt /etc/openvpn
if ! [ -f /etc/openvpn/server.key ];then echo -e "${RED}ОШИБКА, сертификат сервера не сгенерирован. ${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}"; fi
echo -n -e "               Ключ сервера "
if ! [ -f /etc/openvpn/server.crt ];then echo -e "${RED}ОШИБКА, ключ сервера не сгенерирован. ${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi

echo -n -e "               CRL "
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl >&- 2>&-
cp pki/crl.pem /etc/openvpn
if ! [ -f /etc/openvpn/crl.pem ];then echo -e "${RED}ОШИБКА, ключи crl не сгенерированы. ${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi


case "$tls_hmac" in
tls-crypt)echo -n -e "               TLS-crypt ";;
tls-auth)echo -n -e "               TLS-auth ";;
esac

if ! [ "$tls_hmac" = "Не используется" ];then
openvpn --genkey --secret /etc/openvpn/tls.key
if ! [ -f /etc/openvpn/tls.key ];then echo -e "${RED}ОШИБКА, ключи TLS не сгенерированы. ${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi
fi
fi }

server_install(){
echo -e "Окончание установки: "
echo -n -e "               OVPN-server "

case "$tls_hmac" in
tls-crypt) tls_hmac=tls-crypt\ tls.key;;
tls-auth) tls_hmac=tls-auth\ tls.key\ 0;;
Не\ используется) tls_hmac="";;
esac

cd /etc/openvpn

cat >>server.conf <<EOF
dev tun
proto $proto
server $subnet $subnet_mask
port $port
EOF

if [ "$cipher_base" = "2" ];then
cat >>server.conf <<EOF
secret static.key
EOF

elif [ "$cipher_base" = "1" ];then
cat >>server.conf <<EOF
ca ca.crt
cert server.crt
key server.key
dh none

cipher $data_cipher
ncp-ciphers $data_cipher
auth $data_digests

tls-version-max $(echo $cipher_base | grep -o -P '1.2|1.3')
tls-cipher $tls_cipher
tls-server
$tls_hmac
ecdh-curve prime256v1
EOF
fi

cat >>server.conf <<EOF
crl-verify crl.pem

topology subnet
client-to-client
client-config-dir ccd

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $dns_server1"
push "dhcp-option DNS $dns_server2"

#tun-mtu 1500
#keysize 256
#key-method 2
#sndbuf 524288
#rcvbuf 524288
#push "sndbuf 524288"
#push "rcvbuf 524288"
#comp-lzo
#push "comp-lzo yes"
keepalive 10 60
persist-key
persist-tun

log log.log
status status.log
verb 3
EOF


mkdir /etc/openvpn/ccd
mkdir /etc/openvpn/clients
touch /etc/openvpn/passwords

systemctl start openvpn@server
if ! [ "$(systemctl status openvpn@server | grep -o "running" )" = "running" ]; then
echo -e "${RED}ошибка, вы можете посмотреть причину - cat /etc/openvpn/log.log${DEFAULT}"
else
echo -e "${GREEN}запущен${DEFAULT}"
systemctl enable openvpn@server >&- 2>&-
fi
}

iptables_settings(){
iptables -t nat -A POSTROUTING -s $subnet/$subnet_mask -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf
netfilter-persistent save >&- 2>&-
echo -e "               MASQUERADE $subnet ---> ${GREEN}$ip ${DEFAULT} "
iptables -I INPUT 1 -i lo -m state --state NEW -p $proto --dport $port -j ACCEPT
iptables -I INPUT 1 -s $subnet/$subnet_mask -j ACCEPT
iptables -I FORWARD 1 -i tun+ -j ACCEPT
iptables -I FORWARD 1 -i tun+ -o lo -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 1 -i lo -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
}

apache2_settings(){
echo -e -n "               Apache2 "
cd /var/www/html/
mkdir clients
rm index.html
cat >>index.html <<EOF
<!doctype html>
<html >
<head>
  <meta charset="utf-8" />
  <title></title>
</head>
<body>
 <a href="/clients">Клиенты</a>
</body>
</html>
EOF
if ! [ "$(systemctl status apache2 | grep -o "running" )" = "running" ]; then
echo -e "${RED}ошибка, файлы для подключения будут лежать в директории /root/${DEFAULT}"
else
echo -e "${GREEN}запущен${DEFAULT}"
fi
}

account_manager(){
cd ~
touch account-manager.sh
cat >account-manager.sh <<FOE
#!/bin/bash
RED='\033[37;0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
DEFAULT='\033[0m'
f=1
while f=1
do
echo -e "\n\${DEFAULT}Настройка пользователей VPN\nВыберите действие\${DEFAULT}
\${GREEN}---------------------------------------\${DEFAULT}
\${DEFAULT}1 - Список учётных записей VPN        \033[0;32m|\${DEFAULT}
\${DEFAULT}2 - Список подключённых пользователей \033[0;32m|\${DEFAULT}
\${DEFAULT}3 - Пароли от архивов                 \033[0;32m|\${DEFAULT}
\${DEFAULT}4 - Заблокировать пользователя        \033[0;32m|\${DEFAULT}
\${DEFAULT}5 - Разблокировать пользователя       \033[0;32m|\${DEFAULT}
\${DEFAULT}6 - Добавить учётную запись           \033[0;32m|\${DEFAULT}
\${DEFAULT}7 - Удалить учётную запись            \033[0;32m|\${DEFAULT}
\${DEFAULT}8 - Выйти из программы\${DEFAULT}                \033[0;32m|\${DEFAULT}
\${GREEN}---------------------------------------\${DEFAULT}"

user-list(){
echo "---------------------------------------"
if [ "\$(ls /etc/openvpn/ccd/)" = "" ];
then echo -e "\${GREEN}Учётных записей для подключения нет.Добавте новые\${DEFAULT}";
else echo -e "\${GREEN}Открытые пользователи:\${DEFAULT}"
        if ! [ "\$(wc -l /etc/openvpn/ccd/* | grep -w "1")" = "" ];
        then grep -H -o "10.8.*" \$(wc -l /etc/openvpn/ccd/* | grep -w "1" | awk '{print \$2}') | cut -b 18- | awk '{print \$1}' | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4
        fi
echo -e "\${RED}Заблокированные пользователи:\${DEFAULT}"
grep -H -B1 "disable" /etc/openvpn/ccd/* | grep -v "disable" | sed 's/-ifconfig-push /:/' | cut -b 18- | awk '{print \$1}' | sed '/^\$/d' | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4
echo "---------------------------------------"
fi }
read value
case "\$value" in
1)
echo -e "\${GREEN}Список учётных записей для подключения:\${DEFAULT}"
user-list;;
2)
echo -e "\${GREEN}Список подключённых пользователей:\n\${DEFAULT}"
if [ "\$(cat /etc/openvpn/status.log | grep 10.8.*)" = "" ];
then echo -e "\${GREEN}Нет подключённых пользователей\${DEFAULT}"
else
echo -e "\${DEFAULT}|Локальный ip|   Аккаунт    |Время подключения|   ip пользователя   |\${DEFAULT}"
echo "|------------|--------------|-----------------|---------------------|"
for (( i=1;i<\$(cat /etc/openvpn/status.log | grep 10.8.8.* | wc -l)+1;i++ ))
do
echo -n "|\$(printf " %10s " \$(cat /etc/openvpn/status.log | grep "10.8.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$1}'))|"
echo -n "\$(printf "%11s   " \$(cat /etc/openvpn/status.log | grep "10.8.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$2}'))|"
echo -n "\$(printf "%16s " "\$(grep "\$(cat /etc/openvpn/status.log | grep "10.8.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$2}')" /etc/openvpn/status.log | sed -n '1p' | sed 's/,/ /g' | awk '{print \$6,\$7,\$8}')")|"
echo "\$(printf "%17s    " \$(cat /etc/openvpn/status.log | grep "10.8.8.*" |sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$3}'| sed 's/:/ /g' | awk '{print \$1}'))|"
done
fi;;
3)
echo -e "\${GREEN}Логин/пароль от архивов\${DEFAULT}"
cat /etc/openvpn/passwords;;
4)
echo -e "\${GREEN}Блокировка учётной записи\${DEFAULT}\nВведите имя учётной записи\n"
if ! [ "\$(ls /etc/openvpn/ccd/)" = "" ];then user-list; fi
read username
if  [ -e /etc/openvpn/ccd/\$username ];
then
        if ! [ "\$(grep -o "disable" /etc/openvpn/ccd/\$username)" = "disable" ];
        then
        echo "disable" >> /etc/openvpn/ccd/\$username
        echo -e "\${GREEN}Учётная запись заблокирована\${DEFAULT}"
        else
        echo -e "\${RED}Учётная запись уже заблокирована\${DEFAULT}"
        fi
else echo -e "\${RED}Учётной записи не существует\${DEFAULT}"
fi;;
5)
echo -e "\${GREEN}Разблокировка учётной записи\${DEFAULT}\nВведите имя учётной записи\n"
if ! [ "\$(ls /etc/openvpn/ccd/)" = "" ];then user-list;fi
read username
if [ -e /etc/openvpn/ccd/\$username ];
then
        if [ "\$(grep -o "disable" /etc/openvpn/ccd/\$username)" = "disable" ];
        then
        sed -i /disable/d /etc/openvpn/ccd/\$username
        echo -e "\${GREEN}Учётная запись разблокирована\${DEFAULT}"
        else
        echo -e "\${RED}Учётная запись уже разблокирована\${DEFAULT}"
        fi
else
echo -e "\${RED}Неправильно введено имя учётной записи\${DEFAULT}"
fi;;
6)
echo -e "\${GREEN}Добавление учётной записи\${DEFAULT}\nВведите имя учётной записи\n"
if ! [ "\$(ls /etc/openvpn/ccd/)" = "" ];then user-list;fi
read username
#echo "\${GREEN}Введите пароль\${DEFAULT}"
#read password
password=\$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c\${1:-32};echo;)
echo -e "\${GREEN}Введите локальный ip, к которому будет привязана учётная запись\${DEFAULT}"
if [ "\$(ls /etc/openvpn/ccd/)" = "" ];
then echo -e "\${GREEN}Рекомендую использовать диапозон адресов 10.8.8.100 - 10.8.8.200\${DEFAULT}"
else
echo -e "\${GREEN}Для сравнения - список назначенных учётным записям локальных ip адресов\${DEFAULT}"
        if ! [ "\$(ls /etc/openvpn/ccd/)" = "" ];
        then user-list;fi
fi

read local_ip
cd /etc/openvpn/
cat >>passwords <<EOF
\$username \$password
EOF
cd /usr/share/easy-rsa
./easyrsa build-client-full \$username nopass
cd /etc/openvpn/clients/
ca=\$(cat /usr/share/easy-rsa/pki/ca.crt)
cert=\$(cat /usr/share/easy-rsa/pki/issued/\$username.crt)
key=\$(cat /usr/share/easy-rsa/pki/private/\$username.key)
tls=\$(cat /etc/openvpn/tls.key)
cat >\$username.ovpn <<EOF
client
dev tun
proto udp
remote $ip $port

auth-nocache
verify-x509-name server name
tls-client
remote-cert-tls server

persist-key
persist-tun
nobind
resolv-retry infinite
ignore-unknown-option block-outside-dns
block-outside-dns
setenv opt block-outside-dns
EOF
FOE

if [ "$proto" = "udp" ];then
cat >>account-manager.sh <<FOE
cat >>\$username.ovpn <<EOF
explicit-exit-notify 2
EOF
FOE
fi

cat >>account-manager.sh <<FOE
cat >>\$username.ovpn <<EOF
<ca>
\$ca
</ca>
<cert>
\$cert
</cert>
<key>
\$key
</key>
EOF
FOE

if [ "$tls_hmac" = "tls-crypt" ];then
cat >>account-manager.sh <<FOE
cat >>\$username.ovpn <<EOF
<tls-crypt>
\$tls
</tls-crypt>
EOF
FOE

elif [ "$tls_hmac" = "tls-auth" ];then
cat >>account-manager.sh <<FOE
cat >>\$username.ovpn <<EOF
key-direction 1
<tls-auth>
\$tls
</tls-auth>
EOF
FOE
fi

cat >>account-manager.sh <<FOE
cd /etc/openvpn/ccd/
cat >\$username <<EOF
ifconfig-push \$local_ip $subnet_mask
EOF

cd /etc/openvpn/clients/
zip \$username.zip -P \$password  \$username.ovpn
cp \$username.ovpn ~/
cd /var/www/html/clients/
mv /etc/openvpn/clients/\$username.zip .
echo -e "\${GREEN} Пароль от архива \$username.zip - \$password \${DEFAULT}"
echo -e "\${GREEN} Учётная запись добавлена\${DEFAULT}";;

7)
echo -e "\${RED}Удаление учётной записи\${DEFAULT}\nВведите имя учётной записи\n"
if ! [ "\$(ls /etc/openvpn/ccd/)" = "" ];then user-list;fi
read username
if  [ -e /etc/openvpn/ccd/\$username ];
then
rm -f /etc/openvpn/clients/\$username.ovpn
rm /usr/share/easy-rsa/pki/issued/\$username.crt
rm /usr/share/easy-rsa/pki/private/\$username.key
rm /var/www/html/clients/\$username.zip
rm /etc/openvpn/ccd/\$username
rm /usr/share/easy-rsa/pki/reqs/\$username.req
rm /root/\$username.ovpn
sed -i /\$username/d /etc/openvpn/passwords
echo "\${GREEN} Учётная запись удалёна\${DEFAULT}"
else
echo -e "\${RED}Неправильно введено имя учётной записи\${DEFAULT}"
fi;;
8)echo -e "\${GREEN} Выход из программы\${DEFAULT}"
exit;;
esac
done
FOE
chmod +x account-manager.sh
}

echo -e "Выберите режим установки:\n1 - автоматический\n2 - настраиваемый"
until [[ $install_type =~ ^[1-2]$ ]]; do
read -rp "[1-2]:" -e -i 1 install_type
done

#----------------------------------------------------------------------
if [ "$install_type" = "1" ];then
echo -e "\nEnter - начать установку\nCtrl+C - отмена"
read install_option
if ! [ "$install_option" = "" ];then echo "Отмена установки" && exit;fi
#-----------------------------------------------------------------------

elif [ "$install_type" = "2" ];then
echo -e "Выберете протокол:\n1 - udp\n2 - tcp"
until [[ $proto =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 proto;done
case "$proto" in
1) proto=udp;;
2) proto=tcp;;
esac

echo -e "Укажите порт:"
until [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; do read -rp "" -e -i 443 port;done

echo -e "Укажите режим шифрования:\n1 - TLS\n2 - статичный ключ\n3 - без шифрования"
until [[ $cipher_base =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 cipher_base;done

if [ "$cipher_base" = "1" ];then
echo -e "${GREEN}Настройка канала управления${DEFAULT}"
tls_settings
echo -e "${GREEN}Настройка канала данных${DEFAULT}"
data_channel_settings
echo -e "${GREEN}Настройка сертификатов${DEFAULT}"
pki_settings
echo -e "${GREEN}Клиентские настройки${DEFAULT}"
clients_settings
echo -e "${GREEN}Дополнительные настройки${DEFAULT}"
hmac_settings
network_settings
final_config
read value
if [ "$value" = "" ];then
package_install
cert_gen
server_install
iptables_settings
apache2_settings
account_manager
fi
fi
fi








