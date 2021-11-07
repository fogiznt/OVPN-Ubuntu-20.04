Данный скрипт устанавливает серверную конфигурацию OpenVPN.  
 

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
./account_manager.sh
```
