Данный скрипт устанавливает серверную конфигурацию OpenVPN.  

Предоставляется следующий выбор конфигурации OpenVPN сервера.  
Режим атунтификации:   
1. TLS сертификаты  
2. Логин пароль  

Алгоритм цифровой подписи:  
1. ECDSA  
2. RSA   

Версия TLS - 1.3 или 1.2  

Для шифрованя канала данных и управления выбор из следующих алгоритмов:  
1. AES-128-GCM/CBC  
2. AES-256-GCM/CBC  
3. CHACHA20-POLY1305 ( используйте при отсутствии аппаратной поддержки AES )  

Присутствует выбор использования HMAC подписи к пакетам - TLS-crypt или TLS-auth  

Установка OpenVPN - на Ubuntu 20.04  
``` 
cd ~
wget https://raw.githubusercontent.com/fogiznt/OVPN-Ubuntu-20.04/main/openvpn-install.sh -O openvpn-install.sh --secure-protocol=TLSv1
chmod +x openvpn-install.sh
./openvpn-install.sh
```

Добавление пользователей  
```
cd ~ 
./account-manager.sh
```
