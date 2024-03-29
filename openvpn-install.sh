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

#----------------------------------------------------------------------

default_settings(){
proto=udp
port=443
auth_mode="TLS"
tls_ver=TLS\ 1.3
tls_cipher=TLS_AES_128_GCM_SHA256
data_cipher=AES-128-GCM
data_digests=SHA256
cert_algo=ec
cert_curve=prime256v1
ip=$(hostname -i)
if [ "$ip" = "" ]; then ip=1.1.1.1;fi
echo -e "Укажите внешний ip сервера"
read -rp "" -e -i $ip ip
dns_server=CloudFlare
dns_server1=1.1.1.1
dns_server2=1.0.0.1
tls_hmac=tls-crypt\ tls.key
subnet=10.8.8.0
subnet_mask=255.255.255.0
}

#----------------------------------------------------------------------

tls_settings(){
echo -e "${GREEN}Настройка канала управления${DEFAULT}"
echo -e "Выберите версию TLS:\n1 - 1.3 - рекомендуется\n2 - 1.2"
until [[ $tls_ver =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 tls_ver;done

if [ "$tls_ver" = "1" ]; then
echo -e "Выберите реализацию:\n1 - TLS_AES_128_GCM_SHA256 - рекомендуется\n2 - TLS_AES_256_GCM_SHA384\n3 - TLS_CHACHA20_POLY1305_SHA256"
until [[ $tls_cipher =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 tls_cipher;done

elif [ "$tls_ver" = "2" ]; then
echo -e "Перед выбором реализации помните, что:\nАлгоритм аутентификации RSA уступает в скорости ECDSA - особенно заметно при медленном интернете.\nДля полной криптостойкости алгоритму AES достаточно ключа размером в 128 бит. Ключи размером 192 и 256 бит избыточны."
echo -e "Используйте режим работы AES-CBC при отсутствии поддержки AES-GCM.\nИспользуйте симметричный алгоритм CHACHA20-POLY1305 при отсутствии аппаратной поддержки алгоритма AES."
echo -e "Выберите реализацию:\n1 - TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256 - рекомендуется\n2 - TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384\n3 - TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"
echo -e "4 - TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256\n5 - TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384\n6 - TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256\n7 - TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA256\n8 - TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"
until [[ $tls_cipher =~ ^[1-8]$ ]]; do read -rp "[1-8]:" -e -i 1 tls_cipher;done
tls_cipher=$((tls_cipher + 3))
fi

case "$tls_cipher" in
1) tls_cipher=TLS_AES_128_GCM_SHA256;;
2) tls_cipher=TLS_AES_256_GCM_SHA384;;
3) tls_cipher=TLS_CHACHA20_POLY1305_SHA256;;
4) tls_cipher=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256;;
5) tls_cipher=TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384;;
6) tls_cipher=TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256;;
7) tls_cipher=TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256;;
8) tls_cipher=TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384;;
9) tls_cipher=TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256;;
10) tls_cipher=TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA256;;
11) tls_cipher=TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256;;

esac }

#----------------------------------------------------------------------

data_channel_settings(){
echo -e "${GREEN}Настройка канала данных${DEFAULT}"
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

#----------------------------------------------------------------------

pki_settings(){
echo -e "${GREEN}Настройка сертификатов${DEFAULT}"
echo -e "Выберите алгоритм клиентских сертификатов:\n1 - EC - рекомендуется\n2 - RSA"
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

#----------------------------------------------------------------------

clients_settings(){
echo -e "${GREEN}Клиентские настройки${DEFAULT}"
#ip=$(curl check-host.net/ip 2>/dev/null) >&- 2>&-
ip=$(hostname -i)
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
esac 

echo -e "Максимальное кол-во клиентов:\n1 - 253 - рекомендуется\n2 - 65533"
until [[ $subnet_mask =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 subnet_mask;done

case "$subnet_mask" in
1)subnet=10.8.8.0 subnet_mask=255.255.255.0;;
2)subnet=10.8.0.0 subnet_mask=255.255.0.0;;
esac

# if [ "$auth_mode" = "2" ];then
# echo -e "Импорт профиля через:\n1 - URL - требуется домен и только для программы OpenVPN Connect\n2 - Файл\n3 - URL и Файл"
# until [[ $connect_mode =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 connect_mode;done
#
# if ! [ "connect_mode" = "2" ]; then
# echo -e "Потому как программа OpenVPN Connect может подключаться только по HTTPS и только на 443 порту\nПри этом доверяя только валидным сертификатам, то для вашего домена будут выпущены бесплатные сертификаты от LetsEncrypt"
# echo -e "Убедитесь, что вы не исчерпали лимит бесплатных сертификатов ( 5 за 2 недели). \nЛибо загрузите свои сертификаты с вашего ПК\n"
# echo -e "1 - у меня нет сертификата"
# echo -e "2 - у меня есть сертификат"
# until [[ $cert_availability =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 cert_availability;done
# case "$cert_availability" in
# 1)
#  echo -e "Укажите ваш домен"
#  read domain;;
# 2)
#  echo -e "Укажите ваш домен"
#  read domain
#  mkdir /etc/letsencrypt
#  mkdir /etc/letsencrypt/live
#  mkdir /etc/letsencrypt/live/$domain
#
#  echo -e "Для загрузки сертификатов выполните на вашем компьютере -" 
#  echo -e "scp C:\\directory\fullchain.pem root@$ip:/etc/letsencrypt/live/$domain/"
#  echo -e "scp C:\\directory\privkey.pem root@$ip:/etc/letsencrypt/live/$domain/"
#  echo -e "Загружайте каждый сертификат по отдельности, а не всю директорию!"
#
#  echo -e "\nПо окнончании загрузки сертификатов нажмите Enter"
#  read wait
#  echo -e "Проверка наличия сертификатов"
#  if [ -f /etc/letsencrypt/live/$domain/fullchain.pem ] && [ -f /etc/letsencrypt/live/$domain/privkey.pem ];then 
#   echo "${GREEN}Сертификаты найдены${DEFAULT}"
#  else 
#   echo "${RED}Сертификаты не найдены,\n1 - сгенерировать сертификаты заново\n2 - отказаться от URL - импорт профиля${DEFAULT}"
#   read value
#   case "$value" in
#    1)cert_availability=1;;
#    2)connect_mode=2;;
#   esac
#  fi;;
#  esac
# fi
# fi

}

#----------------------------------------------------------------------

network_settings(){
echo -e "Выберете протокол:\n1 - udp\n2 - tcp"
until [[ $proto =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 proto;done
case "$proto" in
1) proto=udp;;
2) proto=tcp;;
esac

echo -e "Укажите порт:"
until [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; do read -rp "" -e -i 443 port;done
}

#----------------------------------------------------------------------

hmac_settings(){
echo -e "${GREEN}Дополнительные настройки${DEFAULT}"
echo -e "Дополнительная подпись HMAC к TLS-пакетам:\n1 - TLS-crypt - рекомендуется\n2 - TLS-auth\n3 - не использовать"
until [[ $tls_hmac =~ ^[1-3]$ ]]; do read -rp "[1-3]:" -e -i 1 tls_hmac;done
case "$tls_hmac" in
1) tls_hmac=tls-crypt\ tls.key;;
2) tls_hmac=tls-auth\ tls.key\ 0;;
3) tls_hmac=Не\ используется;;
esac }

#----------------------------------------------------------------------

final_config(){
case "$auth_mode" in
1) auth_mode=TLS;;
2) auth_mode=Логин/Пароль;;
3) auth_mode=Статичный\ ключ;;
esac

case "$tls_ver" in
1) tls_ver=TLS\ 1.3;;
2) tls_ver=TLS\ 1.2;;
esac

echo -e "\nОзнакомтесь с устанавливаемой конфигурацией"
echo -e "-----------------------------------------------------------"
echo -e "Порт - ${GREEN}$(echo $proto | tr a-z A-Z):$port${DEFAULT}"
echo -e "Режим аутентификации - ${GREEN}$auth_mode${DEFAULT}"
echo -e "Версия TLS - ${GREEN}$(echo $tls_ver | grep -o -P '1.3|1.2')${DEFAULT}"
if [ "$tls_ver" = "TLS 1.3" ] || [ "$tls_ver" = "TLS 1.2" ];then
echo -e "Канал управления:\n	Алгоритм обмена ключами - ${GREEN}ECDH${DEFAULT}\n	Алгоритм аутентификации - ${GREEN}ECDSA${DEFAULT}"
echo -e "        Симметричное шифрование - ${GREEN}$(echo $tls_cipher | grep -o -P 'AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305|AES-128-GCM|AES-256-GCM|CHACHA20-POLY1305')${DEFAULT}"
echo -e "	Хэш-функция - ${GREEN}$(echo $tls_cipher | grep -o -P 'SHA256|SHA384')${DEFAULT}"
echo -e "Канал даннных:\n	Шифрование - ${GREEN}$(echo $data_cipher | grep -o -P 'AES-128-GCM|AES-256-GCM|AES-128-CBC|AES-256-CBC')${DEFAULT}"
echo -e "	Хэш-функция - ${GREEN}$(echo $data_digests | grep -o -P 'SHA256|SHA384|SHA512')${DEFAULT}"
fi
echo -e "Настройки PKI:\n        Алгоритм клиентских сертификатов - ${GREEN}$(echo $cert_algo | tr a-z A-Z)${DEFAULT}"
if [ "$cert_algo" = "ec" ];then echo -e "	Кривая - ${GREEN}$cert_curve${DEFAULT}";fi
echo -e "Клиентские настройки:\n        ip сервера - ${GREEN}$ip${DEFAULT}\n        DNS - ${GREEN}$dns_server${DEFAULT}"

#if [ "$auth_mode" = "Логин/Пароль" ];then 
#echo -n -e "        Импорт профиля через - ${GREEN}"
#case "$connect_mode" in
#1) echo -e "URL${DEFAULT}";;
#2) echo -e "Файл${DEFAULT}";;
#3) echo -e "URL и Файл${DEFAULT}";;
#esac
#
#if ! [ "$connect_mode" = "2" ];then
#echo -e "        Домен - ${GREEN}$domain${DEFAULT}"
#echo -n -e "        Сертификат - ${GREEN}"
#case "$cert_availability" in
#1) echo -e  "будет сгенерирован самостоятельно${DEFAULT}";;
#2) echo -e "был успешно загружен${DEFAULT}";;
#esac
#fi
#fi

echo -e "Дополнительные настройки:"
if [ "$tls_ver" = "TLS 1.3" ] || [ "$tls_ver" = "TLS 1.2" ];then echo -e "	HMAC подпись - ${GREEN}$(echo $tls_hmac | grep -o -P 'tls-crypt|tls-auth|Не используется')${DEFAULT}";fi
echo -n -e "	Максимальное кол-во клиентов - "
if [ "$subnet_mask" = "255.255.255.0" ];then echo -e "${GREEN}253${DEFAULT}";else echo -e "${GREEN}65533${DEFAULT}";fi

 
echo "-----------------------------------------------------------"
echo -e "\nEnter - начать установку\nCtrl+C - отмена"
}

#----------------------------------------------------------------------

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

if [ "$auth_mode" = "Логин/Пароль" ] &! [ "$connect_mode" = "2" ] && [ "$cert_availability" = "1" ];then
echo -n -e "               certbot " & echo -n $(apt install certbot -y >&- 2>&-)
if [ "$(dpkg --get-selections certbot | awk '{print $2}')" = "install" ]; then echo -e "${GREEN}OK${DEFAULT}"; else echo -e "${RED}ОШИБКА, попробуйте установить данный пакет самостоятельно -${GREEN} apt install certbot ${DEFAULT}";fi
fi
}

#----------------------------------------------------------------------

cert_gen(){
echo -e "Генерация сертификатов: "

if ! [ "$auth_mode" = "Статичный ключ" ];then
cd /usr/share/easy-rsa/

case "$tls_ver" in
TLS\ 1.3) server_cert_algo=ec;;
TLS\ 1.2) server_cert_algo=$(echo $tls_cipher | grep -o -P 'RSA|ECDSA' | tr '[:upper:]' '[:lower:]' | sed 's/ecdsa/ec/g');;
esac

echo "set_var EASYRSA_ALGO $server_cert_algo" >vars
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

sed -i 's/set_var EASYRSA_ALGO '$server_cert_algo'/set_var EASYRSA_ALGO '$cert_algo'/g' /usr/share/easy-rsa/vars
if [ "$cert_algo" = "ec" ] && [ "$(cat /usr/share/easy-rsa/vars | grep -o "prime256v1")" = "" ];then echo "set_var EASYRSA_CURVE prime256v1" >>vars;fi
case "$tls_hmac" in
tls-crypt\ tls.key)echo -n -e "               TLS-crypt ";;
tls-auth\ tls.key\ 0)echo -n -e "               TLS-auth ";;
esac

if ! [ "$tls_hmac" = "Не используется" ];then
openvpn --genkey --secret /etc/openvpn/tls.key
if ! [ -f /etc/openvpn/tls.key ];then echo -e "${RED}ОШИБКА, ключи TLS не сгенерированы. ${DEFAULT}" exit;else echo -e "${GREEN}OK${DEFAULT}";fi
fi


if [ "$auth_mode" = "Логин/Пароль" ];then
ca=$(cat /usr/share/easy-rsa/pki/ca.crt)
tls=$(cat /etc/openvpn/tls.key)
echo -n -e "               client.ovpn "
cd ~
cat >client.ovpn <<EOF
client
dev tun
proto $proto
remote $ip $port

auth-user-pass

auth-nocache
verify-x509-name server name
tls-client
remote-cert-tls server

auth $data_digests
cipher $data_cipher

persist-key
persist-tun
nobind
resolv-retry infinite
ignore-unknown-option block-outside-dns
block-outside-dns
setenv opt block-outside-dns
EOF

if [ "$proto" = "udp" ];then
cat >>client.ovpn <<EOF
explicit-exit-notify 2
EOF
fi

cat >>client.ovpn <<EOF
<ca>
$ca
</ca>
EOF

if [ "$tls_hmac" = "tls-crypt tls.key" ];then
cat >>client.ovpn <<EOF
<tls-crypt>
$tls
</tls-crypt>
EOF


elif [ "$tls_hmac" = "tls-auth tls.key 0" ];then
cat >>client.ovpn <<EOF
key-direction 1
<tls-auth>
$tls
</tls-auth>
EOF
fi
echo -e "${GREEN}OK${DEFAULT}"

cat >>/etc/openvpn/user.pass <<EOF
admin:admin
EOF
fi



#if [ "$auth_mode" = "Логин/Пароль" ] &! [ "$connect_mode" = "2" ] && [ "$cert_availability" = "1" ];then
#echo -n -e "               Сертификат LetsEncrypt"
#systemctl stop apache2 >&- 2>&-
#certbot certonly --standalone -n -d $domain --agree-tos --email 123@$domain &> /dev/null
#systemctl start apache2 >&- 2>&-
#if [ -f /etc/letsencrypt/live/$domain/fullchain.pem ] && [ -f /etc/letsencrypt/live/$domain/privkey.pem ];then echo -e "${GREEN}OK${DEFAULT}"
#else echo -e "${RED}ошибка, импорт файла по url работать не будет${DEFAULT}"
#fi
#fi

fi }

#----------------------------------------------------------------------

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

if [ "$auth_mode" = "Статичный ключ" ];then
cat >>server.conf <<EOF
secret static.key
EOF

elif ! [ "$auth_mode" = "Статичный ключ" ];then
cat >>server.conf <<EOF
ca ca.crt
cert server.crt
key server.key
dh none

cipher $data_cipher
ncp-ciphers $data_cipher
auth $data_digests

tls-version-max $(echo $tls_ver | grep -o -P '1.2|1.3')
EOF

if [ "$tls_ver" = "TLS 1.3" ];then
cat >>server.conf <<EOF
tls-ciphersuites $tls_cipher
EOF

elif [ "$tls_ver" = "TLS 1.2" ];then
cat >>server.conf <<EOF
tls-cipher $tls_cipher
EOF
fi

cat >>server.conf <<EOF
tls-server
$tls_hmac
ecdh-curve prime256v1
EOF
fi

if [ "$auth_mode" = "Логин/Пароль" ];then
cat >>server.conf <<EOF
auth-user-pass-verify /etc/openvpn/verify.sh via-file
client-cert-not-required
username-as-common-name
tmp-dir /etc/openvpn/tmp
script-security 2
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

if [ "$auth_mode" = "Логин/Пароль" ];then
mkdir /etc/openvpn/tmp
touch /etc/openvpn/user.pass
cat >verify.sh <<EOF
#!/bin/sh
USERS=\`cat /etc/openvpn/user.pass\`
vpn_verify() {
if [ ! \$1 ] || [ ! \$2 ]; then
exit 1
fi
for i in \$USERS; do
if [ "\$i" = "\$1:\$2" ]; then
exit 0
fi
done
}
if [ ! \$1 ] || [ ! -e \$1 ]; then
exit 1
fi
vpn_verify \`cat \$1\`
exit 1

EOF
chmod +x /etc/openvpn/verify.sh
fi

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

#----------------------------------------------------------------------

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

#----------------------------------------------------------------------

apache2_settings(){
echo -e -n "               Apache2 "
cd /var/www/html/
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
mkdir /var/www/html/clients
if [ "$auth_mode" = "Логин/Пароль" ];then cp ~/client.ovpn /var/www/html/clients/;fi


#if [ "$auth_mode" = "Логин/Пароль" ] &! [ "$connect_mode" = "2" ];then
#mkdir /etc/apache2/ssl
#cp /etc/letsencrypt/live/$domain/fullchain.pem /etc/apache2/ssl/
#cp /etc/letsencrypt/live/$domain/privkey.pem /etc/apache2/ssl/
#
#a2enmod ssl >&- 2>&-
#systemctl restart apache2
#
#cd /etc/apache2/sites-enabled/
#cat >000-default.conf <<EOF
#<VirtualHost *:443>
#        ServerAdmin webmaster@localhost
#        DocumentRoot /var/www/html
#        ErrorLog ${APACHE_LOG_DIR}/error.log
#        CustomLog ${APACHE_LOG_DIR}/access.log combined
#        SSLEngine on
#        SSLCertificateFile ssl/fullchain.pem
#        SSLCertificateKeyFile ssl/privkey.pem
#        ServerName $domain
#</VirtualHost>
#EOF
#apachectl graceful
#fi

if ! [ "$(systemctl status apache2 | grep -o "running" )" = "running" ]; then
echo -e "${RED}ошибка, файлы для подключения будут лежать в директории /root/${DEFAULT}"
else
echo -e "${GREEN}запущен${DEFAULT}"
fi
}

#----------------------------------------------------------------------

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
echo -e "\${DEFAULT}|Локальный ip|    Аккаунт   |Время подключения|   ip пользователя   |\${DEFAULT}"
echo "|------------|--------------|-----------------|---------------------|"
for (( i=1;i<\$(cat /etc/openvpn/status.log | grep 10.8.* | wc -l)+1;i++ ))
do
echo -n "|\$(printf " %10s " \$(cat /etc/openvpn/status.log | grep "10.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$1}'))|"
echo -n "\$(printf "%11s   " \$(cat /etc/openvpn/status.log | grep "10.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$2}'))|"
echo -n "\$(printf "%16s " "\$(grep "\$(cat /etc/openvpn/status.log | grep "10.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$2}')" /etc/openvpn/status.log | sed -n '1p' | sed 's/,/ /g' | awk '{print \$6,\$7,\$8}')")|"
echo "\$(printf "%17s    " \$(cat /etc/openvpn/status.log | grep "10.8.*" |sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$3}'| sed 's/:/ /g' | awk '{print \$1}'))|"
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
proto $proto
remote $ip $port

auth-nocache
verify-x509-name server name
tls-client
remote-cert-tls server

auth $data_digests
cipher $data_cipher

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

if [ "$tls_hmac" = "tls-crypt tls.key" ];then
cat >>account-manager.sh <<FOE
cat >>\$username.ovpn <<EOF
<tls-crypt>
\$tls
</tls-crypt>
EOF
FOE

elif [ "$tls_hmac" = "tls-auth tls.key 0" ];then
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

pap_account_manager(){
cd ~
touch account-manager.sh
cat >account-manager.sh <<FOE
#!/bin/bash
#RED='\033[1;31m'
#GREEN='\033[1;32m'
#DEFAULT='\033[0m'
f=1
while f=1
do
echo -e "\nНастройка пользователей VPN\nВыберите действие
---------------------------------------
1 - Список учётных записей VPN        |
2 - Список подключённых пользователей |
3 - Сменить пароль учётной записи     |
4 - Добавить учётную запись           |
5 - Удалить учётную запись            |
6 - Выйти из программы                |
---------------------------------------"
read value
case "\$value" in
1)
echo -e "Список учётных записей для подключения:"
cat /etc/openvpn/user.pass
;;
2)
echo -e "\${GREEN}Список подключённых пользователей:\n\${DEFAULT}"
if [ "\$(cat /etc/openvpn/status.log | grep 10.8.*)" = "" ];
then echo -e "\${GREEN}Нет подключённых пользователей\${DEFAULT}"
else
echo -e "\${DEFAULT}|Локальный ip|    Аккаунт   |Время подключения|   ip пользователя   |\${DEFAULT}"
echo "|------------|--------------|-----------------|---------------------|"
for (( i=1;i<\$(cat /etc/openvpn/status.log | grep 10.8.* | wc -l)+1;i++ ))
do
echo -n "|\$(printf " %10s " \$(cat /etc/openvpn/status.log | grep "10.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$1}'))|"
echo -n "\$(printf "%11s   " \$(cat /etc/openvpn/status.log | grep "10.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$2}'))|"
echo -n "\$(printf "%16s " "\$(grep "\$(cat /etc/openvpn/status.log | grep "10.8.*" | sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$2}')" /etc/openvpn/status.log | sed -n '1p' | sed 's/,/ /g' | awk '{print \$6,\$7,\$8}')")|"
echo "\$(printf "%17s    " \$(cat /etc/openvpn/status.log | grep "10.8.*" |sed -n ''\$i'p'| sed 's/,/ /g' | awk '{print \$3}'| sed 's/:/ /g' | awk '{print \$1}'))|"
done
fi;;
3)
echo -e "Смена пароля\nВведите имя пользователя"
cat /etc/openvpn/user.pass
echo "---------------------------------------"
read username
if ! [ "\$(grep -w \$username /etc/openvpn/user.pass)" = ""  ];
then
echo -e "Введите новый пароль"
read password
sed -i 's/'\$username':'\$(grep \$username /etc/openvpn/user.pass | sed 's/'\$username'://g')'/'\$username':'\$password'/g' /etc/openvpn/user.pass
else echo "Пользователя не существует"
fi
;;
4)
echo -e "Добавление нового пользователя\nВведите имя пользователя"
cat /etc/openvpn/user.pass
echo "---------------------------------------"
read username
if [ "\$(grep -w \$username /etc/openvpn/user.pass)" = ""  ];
then
echo -e "Enter - случайный пароль\nИли введите свой"
read password
if [ "\$(echo \$password)" = "" ]; then
password=\$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c\${1:-16};echo;)
fi
echo \$username:\$password >> /etc/openvpn/user.pass
else echo -e "Пользователь уже существует"
fi
;;
5)
echo -e "Удаление пользователя\nВведите имя пользователя"
cat /etc/openvpn/user.pass
echo "---------------------------------------"
read username
if ! [ "\$(grep -w \$username /etc/openvpn/user.pass)" = ""  ];
then
sed -i /\$username/d /etc/openvpn/user.pass
else echo -e "Пользователя не существует"
fi
;;
6)
echo -e "Выход из программы"
exit;;

esac
done
FOE
chmod +x account-manager.sh
}

#----------------------------------------------------------------------

echo -e "Укажите режим аутентификации:\n1 - TLS - сертификаты\n2 - Логин/Пароль"
until [[ $auth_mode =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 auth_mode;done

echo -e "Выберите режим установки:\n1 - автоматический\n2 - настраиваемый"
until [[ $install_type =~ ^[1-2]$ ]]; do read -rp "[1-2]:" -e -i 1 install_type;done

#----------------------------------------------------------------------
if [ "$auth_mode" = "1" ] && [ "$install_type" = "1" ];then
default_settings
final_config
read install_option
if ! [ "$install_option" = "" ];then echo "Отмена установки" && exit;fi
package_install
cert_gen
server_install
iptables_settings
apache2_settings
account_manager
echo -e "${GREEN}Установка завершена${DEFAULT}"
echo "После добавления пользователя вы можете загрузить файл для подключения - http://$ip/clients/"
echo "Добавить пользователя - cd ~ && ./account-manager.sh"
#-----------------------------------------------------------------------

elif [ "$auth_mode" = "1" ] && [ "$install_type" = "2" ];then
network_settings
tls_settings
data_channel_settings
pki_settings
clients_settings
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
echo -e "${GREEN}Установка завершена${DEFAULT}"
echo "Добавить пользователя - cd ~ && ./account-manager.sh"
echo "После добавления пользователя вы можете загрузить файл для подключения - http://$ip/clients/"
fi

elif [ "$auth_mode" = "2" ] && [ "$install_type" = "1" ];then
default_settings
auth_mode="Логин/Пароль"
#connect_mode=2
#cert_availability=1
final_config
read value
if [ "$value" = "" ];then
package_install
cert_gen
server_install
iptables_settings
apache2_settings
pap_account_manager
echo -e "${GREEN}Установка завершена${DEFAULT}"
echo "Вы можете загрузить файл для подключения - http://$ip/clients/"
echo "Стандарнтный логин - пароль - admin - admin"
echo "Сменить пароль\Добавить пользователя - cd ~ && ./account-manager.sh"
fi

elif [ "$auth_mode" = "2" ] && [ "$install_type" = "2" ];then
network_settings
tls_settings
data_channel_settings
pki_settings
clients_settings
hmac_settings
final_config
read value
if [ "$value" = "" ];then
package_install
cert_gen
server_install
iptables_settings
apache2_settings
pap_account_manager
echo -e "${GREEN}Установка завершена${DEFAULT}"
echo "Вы можете загрузить файл для подключения - http://$ip/clients/"
echo "Стандарнтный логин - пароль - admin - admin"
echo "Сменить пароль\Добавить пользователя - cd ~ && ./account-manager.sh"
fi
fi








