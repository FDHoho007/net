# FDHoho007 Netzwerk

Das FDHoho007 Netzwerk bezeichnet den Verbund mehrerer einzelner, geografisch unabhängiger Netzwerke, die permanent
durch WireGuard Tunnel miteinander verbunden sind. Durch ein einheitliches Adressierungsschema ist die Kommunikation mit
Rechnern aus anderen Teilnetzen problemlos möglich. Zudem gibt es die Möglichkeit sich mit mobilen Geräte flexibel von
unterwegs zum Netzwerk zu verbinden. Dadurch ist auch unterwegs ein Zugriff auf eigene oder fremde, durch Firewalls
geschützte Ressourcen möglich.

## Authentifizierung

Über https://net.fdhoho007.de/ können Änderungen an der Netzwerkkonfiguration vorgenommen werden. Diese werden
automatisch auf alle betroffenen Netzwerkteilnehmer angewandt (mit Ausnahme mobiler Geräte). Der Zugriff auf diese Seite
erfolgt durch ein MyFDWeb IDM Konto (https://idm.myfdweb.de/) mit erteilter Berechtigung.

## Administration

Ein Netzwerkadministrator verwaltet sowohl die fixen Endpunkte des Netzwerks, als auch Teilnehmer IP Bereiche, also
Teilnehmer die fest und mit mehreren Geräten am Netzwerk teilnehmen und dadurch einen eigenen Adressraum zur Verfügung
bekommen. Die nachfolgenden zwei Absätze richten sich speziell an Netzwerkadministratoren.

### Endpunkte

### Teilnehmer

## Netzwerkteilnehmer

Netzwerkteilnehmer haben, sofern durch einen Netzwerkadministrator richtig registriert, ebenfalls Zugriff
auf https://net.fdhoho007.de/

### Zugelassene Geräte

Jeder Netzwerkteilnehmer kann selbst entscheiden, von welchen Netzwerkteilnehmern er Verbindungen entgegennehmen möchte.
Damit eine Kommunikation zwischen Geräten zweier Netzwerkteilnehmer möglich ist, müssen beide die Kommunikation mit dem
jeweils anderen Teilnehmer zulassen.

Diese Sicherheitsvorrichtung ist nur eine Richtlinie und muss von jedem Endpunkt entsprechend umgesetzt werden. Je nach
technischen Voraussetzungen funktioniert dieser Schutz also nur eingeschränkt oder gar nicht.

### Geräte

Hier kann jeder Netzwerkteilnehmer seine eigenen Geräte über deren MAC-Adresse im Netzwerk registrieren. Es sollte daher
darauf geachtet werden, dass sich die MAC-Adresse nicht ändert und in allen Endpunkten gleich ist. Neben einem
Gerätenamen kann auch eine IP Endung angegeben werden. Näheres dazu in Adressierung.

## Adressierung

Die Adressierung im Netzwerk erfolgt durch ein einheitliches IPv4 Adressen Schema. Genutzt wird hierfür der private IP
Bereich 10.0.0.0/8. Dadurch bleiben 24 Bit bzw. 3 Stellen zu vergeben (10.a.b.c). Die erste zu vergebene Stelle (a) gibt
den Endpunkt an, über den man mit dem Netzwerk verbunden ist. Jeder Endpunkt hat hierfür einen eigenen Adressraum. Die
Adressierung erfolgt hier in der Regel in 10er Schritten (also z.B. 10.10.x.x, 10.20.x.x, ...). Die zweite zu vergebene
Stelle (b) gibt den Teilnehmer an zu dem das adressierte Gerät gehört. Hierfür erhält jeder Teilnehmer einen Adressraum,
dessen Adressierung auch in der Regel in 10er Schritten erfolgt. Die letzte Stelle identifiziert das Gerät und wird
durch den jeweiligen Teilnehmer festgelegt.

### Beispiel

Ein Netzwerkendpunkt hat den Adressraum 30. Ein Netzwerkteilnehmer den Raum 50. Er verbindet sich mit seinem Computer,
dem er zuvor die IP 15 zugewiesen hat. Die interne IPv4 Adresse seines Computers lautet dann 10.30.50.15. Nimmt er nun
seinen Computer und verbindet sich über den Endpunkt 40 zum Netzwerk, ändert sich seine IPv4 Adresse zu 10.40.50.15.

### Ausnahmen

Befindet sich an der ersten zu vergebenen Stelle eine

* 30, deutet dies auf ein mobiles Gerät hin, welches nicht über einen fixen Endpunkt verbunden ist.

Befindet sich an der zweiten zu vergebenen Stelle eine

* 0, handelt es sich um ein internes Gerät (wie z.B. Router, Switches, ...), welche dem Netzwerk und nicht einem Nutzer
  zugeordnet werden.
* 5, handelt es sich um ein Gast Gerät, also ein Gerät, dass mit dem Endpunkt lokal verbunden ist, aber keinem
  Teilnehmer zugeordnet werden kann. Gast Geräte sollten nicht auf das FDHoho007 Netzwerk zugreifen können (siehe
  zugelassene Geräte).
* 30, handelt es sich um ein Gerät eines Netzwerkteilnehmers, der keinen eigenen IP Bereich erhalten hat. Dies ist meist
  nur temporär oder für einzelne Geräte.

## Einrichtung

### Endpunkt

Nachdem ein Endpunkt über das Web Interface erstellt wurde, müssen zunächst die Schlüssel neu generiert werden und der
private Schlüssel sicher gespeichert werden. Dann wird ein Gateway benötigt. Dieser kann z.B. der Netzwerkrouter oder
auch ein RaspberryPi sein. Hierauf muss wireguard und iptables (oder eine andere firewall wie z.B. ufw) installiert
sein.
* Schritt 1: Lege die Datei `/etc/wireguard/wg0.conf` an und sorge dafür, dass der ausführende Nutzer Schreibrechte darauf hat.
* Schritt 2: (auf Raspi nicht erforderlich) Sorge dafür, dass der ausführende Nutzer über die entsprechenden administrativen Rechte verfügt. (visudo: pi      ALL=(ALL) NOPASSWD: /bin/systemctl reload wg-quick@wg0, /usr/sbin/iptables*)
* Schritt 3: Führe folgende 5 Befehle zur Einrichtung von iptables aus:
  * `sudo iptables -N fdhoho007-network-routing`
  * `sudo iptables -t nat -I POSTROUTING -s "10.0.0.0/8" -o "eth0" -j MASQUERADE -m comment --comment "fdhoho007-network"`
  * `sudo iptables -I FORWARD 1 -d "10.0.0.0/8" -i "eth0" -o "wg0" -j ACCEPT -m comment --comment "fdhoho007-network"`
  * `sudo iptables -I FORWARD 2 -s "10.0.0.0/8" -i "wg0" -o "eth0" -j ACCEPT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "fdhoho007-network"`
  * `sudo iptables -I FORWARD 3 -s "10.0.0.0/8" -i "wg0" -o "eth0" -j fdhoho007-network-routing -m comment --comment "fdhoho007-network"`
  * `sudo iptables-save > /etc/iptables/routes.v4`
* Schritt 4: Touch the files devices.sha256, config.sha256 and routing.sha256 in the script directory. Ethically of course ;) 
* Schritt 5: Lade das Update Script von https://net.fdhoho007.de/netclient.py herunter und führe es einmal aus.
* Schritt 6: Starte das Wireguard Interface mit `wg-quick up wg0`
* Schritt 7: Sorge dafür, dass das Script regelmäßig ausgeführt wird (z.B. crontab -e -> */10 * * * * (cd /home/pi && /usr/bin/python3 netclient.py)).
