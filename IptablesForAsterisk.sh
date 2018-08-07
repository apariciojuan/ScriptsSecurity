#!/bin/bash

#Se acepta todo el trafico en entrada direccionado a la interfaz lookpack
iptables -A INPUT -i lo -j ACCEPT

#Se rechaza (REJECT) todo el trafico entrante direccionado a las IP 127.0.0.0/127.255.255.255 menos que para la interfaz -lo
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

#Se aceptan todos los paquetes en entrada de conexiones ya establecidas, o relacionados con conexiones establecidas.
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#Se deja pasar todos los paquetes salientes.
iptables -A OUTPUT -j ACCEPT

#Se deja pasar todo el trafico en entrada para el protocolo tcp (SSH) 22
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT

#Se deja pasar todo el trafico en entrada destinado al puerto udp 4569 (protocolo IAX2)
#iptables -A INPUT -p udp --dport 4569 -j ACCEPT

#Se deja pasar todo el trafico en entrada para el protocolo SMTP (puerto 25 tcp) solamente si se ha configurado el acceso desde remoto al programa SendMail: 
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 25 -j ACCEPT  
#Se deja pasar todo el trafico en entrada para el protocolo HTTP (puerto 80 tcp): 
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT 
#Se deja pasar todo el trafico en entrada para el protocolo HTTPs (puerto 443 tcp): 
#iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT 

#Se bloquea el trafico sobre el puerto 5060 para los más conocidos programas de escaneo de servidores SIP utilizados para ataques y fraudes de llamadas: 
iptables -A INPUT -p udp -m udp --dport 5060 -m string --string "friendly-scanner" --algo bm -j DROP 
iptables -A INPUT -p udp -m udp --dport 5060 -m string --string "sipcli" --algo bm -j DROP 
iptables -A INPUT -p udp -m udp --dport 5060 -m string --string "VaxSIPUserAgent/3.0" --algo bm -j DROP 
iptables -A INPUT -p udp -m udp --dport 5060 -m string --string "sipvicious" --algo bm -j DROP 

#Se deja pasar todo el trafico en entrada destinado al puerto udp 5060 (protocolo SIP) que no fue filtrado antes
iptables -A INPUT -p udp --dport 5060 -j ACCEPT

#Se deja pasar todo el trafico en entrada destinado al puerto tcp 5060 (protocolo SIP sobre TCP)
iptables -A INPUT -p tcp -m state –state NEW -m tcp –dport 5060 -j ACCEPT

#Se deja pasar todo el trafico en entrada destinado a los puertos udp que van de 10000 a 20000 (protocolo RTP)
iptables -A INPUT -p udp --dport 10000:20000 -j ACCEPT

#Se dejan pasar las solicitudes de ping
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

#A este punto, ya que hemos definido los puertos que necesitamos abiertos, podemos bloquear todo el trafico restante.
iptables -A INPUT -j REJECT
iptables -A FORWARD -j REJECT
