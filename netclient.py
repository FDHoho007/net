import requests, base64, hmac, hashlib, os, sys, time, re, urllib.request, urllib.parse, xml.etree.ElementTree as ET

# Config
privateKey = ""
dhcpType = 0 # 0 = Disabled, 1 = FriendlyWrt (must be installed on same host), 2 = FRITZ!Box
# Only change this if you choose dhcpType 2
fritzboxUser = ""
fritzboxPassword = ""



# ----- Code - Do not change from here on -----

# Utility Functions

def shell_exec(cmd):
    return os.popen(cmd).read()

def val(line, index):
    return line.split(" = ")[index]

def request(path):
    hmac_key = hashlib.sha256(base64.b64decode(privateKey)).digest()
    hmac_msg = hashlib.sha256(b"password").hexdigest()
    return requests.get(url="https://net-api.fdhoho007.de/" + path, timeout=5, headers={"Authorization": "Basic " + base64.b64encode((publicKey + ":" + hmac.new(hmac_key, hmac_msg.encode("utf-8"), hashlib.sha256).hexdigest()).encode("utf-8")).decode("utf-8")})

# Wireguard Utiliy Functions

def parse_wg_config(raw):
    config = {"interface": {}, "peers": []}
    peer = -1
    for line in raw.split("\n"):
        if re.fullmatch("\[Interface\]", line):
            peer = -1
        elif re.fullmatch("\[Peer\]( #[a-zA-Z0-9äöüÄÖÜ -]+)?", line):
            peer += 1
            if re.fullmatch("\[Peer\]( #[a-zA-Z0-9äöüÄÖÜ -]+)", line):
                config["peers"].append({"Description": re.sub("\[Peer\] #([a-zA-Z0-9äöüÄÖÜ -]+)", r"\1", line)})
            else:
                config["peers"].append({})
        elif line != "":
            split = line.split(" = ")
            if peer < 0:
                config["interface"][split[0]] = split[1]
            else:
                config["peers"][peer][split[0]] = split[1]
    return config

# Not implemented

def compliance_check_wg_parameter(dataset_old, dataset_new, parameter):
    if parameter in dataset_new:
        if parameter == "Endpoint":
            if not parameter in dataset_old or not dataset_old[parameter] == shell_exec("dig +short " + dataset_new[parameter]) + ":51820":
                if not dataset_old[parameter] == shell_exec("dig +short " + dataset_new[parameter]) + ":51820":
                    print("endpoint mismatch " + dataset_old[parameter] + " " + shell_exec("dig +short " + dataset_new[parameter]) + ":51820")
                else:
                    print("endpoint mismatch")
                return False
        elif not parameter in dataset_old or not dataset_old[parameter] == dataset_new[parameter]:
            print("parameter mismatch " + parameter + " " + dataset_old[parameter] + " " + dataset_new[parameter])
            return False
    elif parameter in dataset_old and not parameter == "Endpoint":
        print("missing parameter " + parameter)
        return False
    return True

def compliance_check_wg(dataset_old, dataset_new):
    interface_map = {"ListenPort", "PrivateKey"}
    peer_map = {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}
    for parameter in interface_map:
        if not compliance_check_wg_parameter(dataset_old["interface"], dataset_new["interface"], parameter):
            return False
    if not len(dataset_old["peers"]) == len(dataset_new["peers"]):
        return False
    for i in range(0, len(dataset_old["peers"])):
        for parameter in peer_map:
            if not compliance_check_wg_parameter(dataset_old["peers"][i], dataset_new["peers"][i], parameter):
                return False
    return True

# Based on AVM example: https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_Technical_Note_-_Session_ID_deutsch_2021-05-03.pdf

def fritzboxSID(username: str, password: str) -> str:
    challenge_parts = ET.fromstring(urllib.request.urlopen("http://fritz.box/login_sid.lua?version=2").read()).find("Challenge").text.split("$")
    iter1 = int(challenge_parts[1])
    salt1 = bytes.fromhex(challenge_parts[2])
    iter2 = int(challenge_parts[3])
    salt2 = bytes.fromhex(challenge_parts[4])
    hash1 = hashlib.pbkdf2_hmac("sha256", password.encode(), salt1, iter1)
    hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, iter2)
    post_data = urllib.parse.urlencode({"username": username, "response": f"{challenge_parts[4]}${hash2.hex()}"}).encode()
    http_response = urllib.request.urlopen(urllib.request.Request("http://fritz.box/login_sid.lua?version=2", post_data, {"Content-Type": "application/x-www-form-urlencoded"}))
    return ET.fromstring(http_response.read()).find("SID").text

def fritzboxNew(sid: str, name: str, mac: str, ip: str):
    mac = mac.split(":")
    ip = ip.split(".")
    post_data = urllib.parse.urlencode({"sid": sid, "devname": name, "macaddr0": mac[0], "macaddr1": mac[1], "macaddr2": mac[2], "macaddr3": mac[3], "macaddr4": mac[4], "macaddr5": mac[5], "ipaddr0": ip[0], "ipaddr1": ip[1], "ipaddr2": ip[2], "ipaddr3": ip[3], "page": "newdevice", "apply": True}).encode()
    urllib.request.urlopen(urllib.request.Request("http://fritz.box/data.lua", post_data, {"Content-Type": "application/x-www-form-urlencoded"}))

def fritzboxEdit(sid: str, name: str, devid: str, ip: str):
    ip2 = ip.split(".")
    post_data = urllib.parse.urlencode({"sid": sid, "dev": devid, "dev_name": name, "dev_ip": ip, "dev_ip2": ip2[2], "dev_ip3": ip2[3], "static_dhcp": "on", "page": "edit_device", "apply": True, "confirmed": True}).encode()
    urllib.request.urlopen(urllib.request.Request("http://fritz.box/data.lua", post_data, {"Content-Type": "application/x-www-form-urlencoded"}))

def fritzboxDelete(sid: str, devid: str):
    post_data = urllib.parse.urlencode({"sid": sid, "delete": devid, "page": "netDev", "confirmed": True}).encode()
    urllib.request.urlopen(urllib.request.Request("http://fritz.box/data.lua", post_data, {"Content-Type": "application/x-www-form-urlencoded"}))

publicKey = shell_exec("echo " + privateKey + " | wg pubkey").strip()
ipPrefix = ""
force = False

def update_dhcp():
    print("[dhcp] Requesting devices ...")
    req = request("devices")
    sha256 = hashlib.sha224(req.text.encode("utf-8")).hexdigest()
    f = open("devices.sha256", "r")
    cached = f.read()
    if sha256 == cached and not force:
        print("[dhcp] No changes found.")
    else:
        print("[dhcp] Found some changes.")
        f = open("devices.sha256", "w")
        f.write(sha256)
        devices = {}
        for device in req.json():
            devices[device["mac"]] = device
        if dhcpType == 1:
            i = 0
            while True:
                lines = shell_exec("uci show dhcp.@host[" + str(i) + "]").split("\n")
                if len(lines) > 1:
                    device = {}
                    for j in range(1,5):
                        l = lines[j].split("=")
                        device[re.sub(r"^dhcp.cfg[a-zA-Z0-9]+.([a-zA-Z0-9]+)$", r"\1", l[0])] = l[1][1:len(l[1])-1]
                    mac = device["mac"]
                    if mac in devices:
                        if device["name"] != devices[mac]["name"]:
                            shell_exec("uci set dhcp.@host[" + str(i) + "].name='" + devices[mac]["name"] + "'")
                        ip = ipPrefix + "." + str(devices[mac]["ip1"]) + "." + str(devices[mac]["ip2"])
                        if device["ip"] != ip:
                            shell_exec("uci set dhcp.@host[" + str(i) + "].ip='" + ip + "'")
                        del devices[mac]
                    elif re.fullmatch("[0-9]{1,3}\.[0-9]{1,3}\.0\.[0-9]{1,3}", device["ip"]) == None:
                        shell_exec("uci del dhcp.@host[" + str(i) + "]")
                    i += 1
                else:
                    break
            for mac in devices:
                device = devices[mac]
                shell_exec("uci add dhcp host")
                shell_exec("uci set dhcp.@host[-1].dns='1'")
                shell_exec("uci set dhcp.@host[-1].name='" + device["name"] + "'")
                shell_exec("uci set dhcp.@host[-1].ip='" + ipPrefix + "." + str(device["ip1"]) + "." + str(device["ip2"]) + "'")
                shell_exec("uci set dhcp.@host[-1].mac='" + device["mac"] + "'")
            shell_exec("uci commit dhcp")
            shell_exec("/etc/init.d/dnsmasq restart")
        elif dhcpType == 2:
            print("[dhcp] Fetching Session Id.")
            sid = fritzboxSID(fritzboxUser, fritzboxPassword)
            print("[dhcp] Fetching current devices.")
            fbDevices = requests.post("http://fritz.box/data.lua", data="sid=" + sid + "&page=netDev&xhrId=cleanup", headers={"Content-Type": "application/x-www-form-urlencoded"}).json()
            fbDevices = fbDevices["data"]["active"] + fbDevices["data"]["passive"]
            for dev in fbDevices:
                mac = dev["mac"]
                ip = ""
                if mac in devices:
                    ip = ipPrefix + "." + devices[mac]["ip1"] + "." + devices[mac]["ip2"]
                if not mac in devices and not dev["ipv4"]["ip"] == "" and re.fullmatch("[0-9]{1,3}\.[0-9]{1,3}\.([05]|11)\.[0-9]{1,3}", dev["ipv4"]["ip"]) == None:
                    print("[dhcp] Removing " + mac + ".")
                    fritzboxDelete(sid, dev["UID"])
                elif mac in devices:
                    if not dev["name"] == devices[mac]["name"] or not dev["ipv4"]["ip"] == ip:
                        print("[dhcp] Update " + mac + ".")
                        fritzboxEdit(sid, devices[mac]["name"], dev["UID"], ip)
                    del devices[mac]
            for mac in devices:
                dev = devices[mac]
                print("[dhcp] Add " + mac + ".")
                fritzboxNew(sid, devices[mac]["name"], mac, ipPrefix + "." + devices[mac]["ip1"] + "." + devices[mac]["ip2"])

def update_wg():
    print("[wg] Requesting config ...")
    configRaw = request("config").text.replace("\r", "")
    config = parse_wg_config(configRaw)
    global ipPrefix
    print("[wg] Resolving prefix.")
    ipPrefix = re.sub(r"^(10\.[0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$", r"\1", config["interface"]["Address"])
    sha256 = hashlib.sha224(configRaw.encode("utf-8")).hexdigest()
    f = open("config.sha256", "r")
    cached = f.read()
    if sha256 == cached and not force:
        print("[wg] No changes in configuration found.")
    else:
        #if force or not compliance_check_wg(parse_wg_config(shell_exec("sudo wg showconf wg0")), config):
        print("[wg] Changes in configuration found.")
        f = open("config.sha256", "w")
        f.write(sha256)
        if dhcpType == 1:
            print("[wg] Configuring wireguard via uci.")
            print("[wg] Configuring interface.")
            shell_exec("uci set network.wg0.private_key='" + config["interface"]["PrivateKey"] + "'")
            shell_exec("uci set network.wg0.addresses='" + config["interface"]["Address"] + "'")
            shell_exec("uci set network.wg0.listen_port='" + config["interface"]["ListenPort"] + "'")
            for i in shell_exec("uci show network | grep wg0peer | sed 's/network\.wg0peer\(.\).*/\1/' | uniq").split("\n"):
                shell_exec("uci del network.wg0peer" + i)
            i = 0
            for peer in config["peers"]:
                id = str(i)
                print("[wg] Configuring peer " + peer["Description"] + ".")
                shell_exec("uci set network.wg0peer" + id + "='wireguard_wg0'")
                shell_exec("uci set network.wg0peer" + id + ".description='" + peer["Description"] + "'")
                shell_exec("uci set network.wg0peer" + id + ".public_key='" + peer["PublicKey"] + "'")
                shell_exec("uci set network.wg0peer" + id + ".preshared_key='" + peer["PresharedKey"] + "'")
                shell_exec("uci set network.wg0peer" + id + ".allowed_ips='" + peer["AllowedIPs"] + "'")
                shell_exec("uci set network.wg0peer" + id + ".route_allowed_ips='1'")
                if "Endpoint" in peer:
                    shell_exec("uci set network.wg0peer" + id + ".endpoint_host='" + peer["Endpoint"].split(":")[0] + "'")
                if "PersistentKeepalive" in peer:
                    shell_exec("uci set network.wg0peer" + id + ".persistent_keepalive='" + peer["PersistentKeepalive"] + "'")
                i += 1
            print("[wg] Restarting wireguard.")
            shell_exec("uci commit network")
            shell_exec("ifdown wg0")
            shell_exec("ifup wg0")
            time.sleep(5)
        elif dhcpType == 2:
            print("[wg] Writing config to /etc/wireguard/wg0.conf")
            f = open("/etc/wireguard/wg0.conf", "w")
            f.write(config)
            f.close()
            print("[wg] Reloading wg-quick.")
            shell_exec("sudo systemctl restart wg-quick@wg0")
            sid = fritzboxSID(fritzboxUser, fritzboxPassword)
            fbRoutes = requests.post("http://fritz.box/data.lua", data="sid=" + sid + "&page=static_route_table", headers={"Content-Type": "application/x-www-form-urlencoded"}).json()["data"]["staticRoutes"]["route"]
            routes = []
            for peer in config["peers"]:
                routes.append(peer["AllowedIPs"])
            for route in fbRoutes:
                if not route["ipaddr"] + "/16" in routes:
                    print("[wg] Remove static route " + route["ipaddr"] + "/16")
                    urllib.request.urlopen(urllib.request.Request("http://fritz.box/data.lua", urllib.parse.urlencode({"sid": sid, "id": route["_node"], "delete": True, "page": "static_route_table"}).encode(), {"Content-Type": "application/x-www-form-urlencoded"}))
                else:
                    routes.remove(route["ipaddr"] + "/16")
            for route in routes:
                print("[wg] Add static route " + route)
                post_data = urllib.parse.urlencode({"sid": sid, "ipaddr0": 10, "ipaddr1": route.split("/")[0].split(".")[1], "ipaddr2": 0, "ipaddr3": 0, "netmask0": 255, "netmask1": 255, "netmask2": 0, "netmask3": 0, "gateway0": 10, "gateway1": ipPrefix.split(".")[1], "gateway2": 0, "gateway3": 2, "isActive":1, "route": "", "apply": True, "page": "new_static_route"}).encode()
                urllib.request.urlopen(urllib.request.Request("http://fritz.box/data.lua", post_data, {"Content-Type": "application/x-www-form-urlencoded"})).read()
        #if dhcpType == 1 or dhcpType == 2:
        #    print("[wg] Setting local routes.")
        #    shell_exec("sudo ip route del " + ipPrefix + ".0.0/16 dev wg0")
        #    for peer in config["peers"]:
        #        shell_exec("sudo ip route add " + peer["AllowedIPs"] + " dev wg0")
    f.close()

def update_firewall():
    print("[iptables] Configuring firewall.")
    routing = request("routing")
    sha256 = hashlib.sha224(routing.text.encode("utf-8")).hexdigest()
    f = open("routing.sha256", "r")
    cached = f.read()
    if sha256 == cached and not force:
        print("[iptables] No changes found.")
    else:
        print("[iptables] Found some changes.")
        routing = routing.json()
        f = open("routing.sha256", "w")
        f.write(sha256)
        if dhcpType == 1 or dhcpType == 2:
            shell_exec("sudo iptables -F fdhoho007-network-routing")
            for chain in routing:
                if not chain == "fdhoho007-network-routing":
                    shell_exec("sudo iptables -F " + chain)
                    shell_exec("sudo iptables -X " + chain)
                    shell_exec("sudo iptables -N " + chain)
                    for rule in routing[chain]:
                        shell_exec('sudo iptables -A ' + chain + ' -d "' + ipPrefix + '.' + rule + '" -j ACCEPT')
                    shell_exec('sudo iptables -A ' + chain + ' -j REJECT')
            for rule in routing["fdhoho007-network-routing"]:
                shell_exec('sudo iptables -A fdhoho007-network-routing -s "' + rule + '" -j "' + routing["fdhoho007-network-routing"][rule] + '"')
            shell_exec('sudo iptables -A fdhoho007-network-routing -j REJECT')           
    f.close()

for arg in sys.argv:
    if arg == "-f":
        force = True

update_wg()
update_firewall()
update_dhcp()
print("Everything should be up to date.")
