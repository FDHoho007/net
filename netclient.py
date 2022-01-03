import requests, base64, hmac, hashlib, os, time, re, urllib.request, urllib.parse, xml.etree.ElementTree as ET

# Config
privateKey = ""
dhcpType = 0 # 0 = Disabled, 1 = FriendlyWrt (must be installed on same host), 2 = FRITZ!Box
# Only change this if you choose dhcpType 2
fritzboxUser = ""
fritzboxPassword = ""



# ----- Code - Do not change from here on -----

def shell_exec(cmd):
    return os.popen(cmd).read()

def val(line, index):
    return line.split(" = ")[index]

def request(path):
    hmac_key = hashlib.sha256(base64.b64decode(privateKey)).digest()
    hmac_msg = hashlib.sha256(b"password").hexdigest()
    return requests.get(url="https://net-api.fdhoho007.de/" + path, headers={"Authorization": "Basic " + base64.b64encode((publicKey + ":" + hmac.new(hmac_key, hmac_msg.encode("utf-8"), hashlib.sha256).hexdigest()).encode("utf-8")).decode("utf-8")})

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

def update_dhcp():
    print("[dhcp] Requesting devices ...")
    req = request("devices")
    sha256 = hashlib.sha224(req.text.encode("utf-8")).hexdigest()
    f = open("devices.sha256", "r")
    cached = f.read()
    if sha256 == cached:
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
    config = request("config").text.replace("\r", "")
    global ipPrefix
    print("[wg] Resolving prefix.")
    ipPrefix = re.sub(r"^Address = (10\.[0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$", r"\1", config.split("\n")[2])
    sha256 = hashlib.sha224(config.encode("utf-8")).hexdigest()
    f = open("config.sha256", "r")
    cached = f.read()
    if sha256 == cached:
        print("[wg] No changes found.")
    else:
        print("[wg] Found some changes.")
        f = open("config.sha256", "w")
        f.write(sha256)
        lines = config.split("\n")
        if dhcpType == 1:
            routes = []
            data = None
            interface = False
            i = 0
            id = 0
            while i < len(lines):
                if not re.fullmatch("\[Interface\]", lines[i]) == None:
                    data = {}
                    interface = True
                elif not re.fullmatch("\[Peer\] #[a-zA-Z0-9äöüÄÖÜ -]+", lines[i]) == None:
                    if not data == None:
                        aip = process_data(data, interface, id)
                        if not aip == None and not aip.split(".")[1] == "30":
                            routes.append(aip)
                        id += 1
                    data = {"Description": re.sub("^\[Peer\] #([a-zA-Z0-9äöüÄÖÜ -]+)$", r"\1", lines[i])}
                    interface = False
                elif " = " in lines[i]:
                    data[lines[i].split(" = ")[0]] = lines[i].split(" = ")[1]
                i += 1
            if not data == None:
                aip = process_data(data, interface, id)
                if not aip == None and not aip.split(".")[1] == "30":
                    routes.append(aip)
            print("[wg] Restarting wireguard.")
            shell_exec("uci commit network")
            shell_exec("ifdown wg0")
            shell_exec("ifup wg0")
            time.sleep(2)
            for route in routes:
                shell_exec("ip route add " + route + " dev wg0")
            shell_exec("ip route del " + ipPrefix + ".0.0/16 dev wg0")
        elif dhcpType == 2:
            print("[wg] Writing config to /etc/wireguard/wg0.conf")
            f = open("/etc/wireguard/wg0.conf", "w")
            f.write(config)
            f.close()
            print("[wg] Reloading wg-quick.")
            shell_exec("sudo systemctl reload wg-quick@wg0")
            print("[wg] Configuring routes.")
            shell_exec("sudo ip route del " + ipPrefix + ".0.0/16 dev wg0")
            routes = []
            i = 0
            peer = False
            while i < len(lines):
                if not re.fullmatch("\[Peer\] #[a-zA-Z0-9äöüÄÖÜ -]+", lines[i]) == None and not peer:
                    peer = True
                if not re.fullmatch("AllowedIps = .+", lines[i]) == None and peer and not lines[i].split(" = ")[1].split(".")[1] == "30":
                    routes.append(lines[i].split(" = ")[1])
                i += 1
            sid = fritzboxSID(fritzboxUser, fritzboxPassword)
            fbRoutes = requests.post("http://fritz.box/data.lua", data="sid=" + sid + "&page=static_route_table", headers={"Content-Type": "application/x-www-form-urlencoded"}).json()["data"]["staticRoutes"]["route"]
            for route in fbRoutes:
                if not route["ipaddr"] + "/16" in routes:
                    print("[wg] Remove static route " + route["ipaddr"] + "/16")
                    post_data = urllib.parse.urlencode({"sid": sid, "id": route["_node"], "delete": True, "page": "static_route_table"}).encode()
                    urllib.request.urlopen(urllib.request.Request("http://fritz.box/data.lua", post_data, {"Content-Type": "application/x-www-form-urlencoded"}))
                else:
                    routes.remove(route["ipaddr"] + "/16")
            for route in routes:
                print("[wg] Add static route " + route)
                post_data = urllib.parse.urlencode({"sid": sid, "ipaddr0": 10, "ipaddr1": route.split("/")[0].split(".")[1], "ipaddr2": 0, "ipaddr3": 0, "netmask0": 255, "netmask1": 255, "netmask2": 0, "netmask3": 0, "gateway0": 10, "gateway1": ipPrefix.split(".")[1], "gateway2": 0, "gateway3": 2, "isActive":1, "route": "", "apply": True, "page": "new_static_route"}).encode()
                print(post_data)
                print(urllib.request.urlopen(urllib.request.Request("http://fritz.box/data.lua", post_data, {"Content-Type": "application/x-www-form-urlencoded"})).read())
    print("[wg] Configuring firewall.")
    routing = request("routing")
    sha256 = hashlib.sha224(routing.text.encode("utf-8")).hexdigest()
    f = open("routing.sha256", "r")
    cached = f.read()
    if sha256 == cached:
        print("[wg] No changes found.")
    else:
        print("[wg] Found some changes.")
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

def process_data(data, interface, id):
    id = str(id)
    if interface:
        print("[wg] Configuring interface.")
        shell_exec("uci set network.wg0.private_key='" + data["PrivateKey"] + "'")
        shell_exec("uci add_list network.wg0.addresses='" + data["Address"] + "'")
        shell_exec("uci set network.wg0.listen_port='" + data["ListenPort"] + "'")
        for i in range(0,10):
            shell_exec("uci del network.wg0peer" + str(i))
        return None
    else:
        print("[wg] Configuring peer " + data["Description"] + ".")
        shell_exec("uci set network.wg0peer" + id + "='wireguard_wg0'")
        shell_exec("uci set network.wg0peer" + id + ".description='" + data["Description"] + "'")
        shell_exec("uci set network.wg0peer" + id + ".public_key='" + data["PublicKey"] + "'")
        shell_exec("uci set network.wg0peer" + id + ".preshared_key='" + data["PresharedKey"] + "'")
        shell_exec("uci add_list network.wg0peer" + id + ".allowed_ips='" + data["AllowedIps"] + "'")
        if "Endpoint" in data:
            shell_exec("uci set network.wg0peer" + id + ".endpoint_host='" + data["Endpoint"].split(":")[0] + "'")
        if "PersistentKeepalive" in data:
            shell_exec("uci set network.wg0peer" + id + ".persistent_keepalive='" + data["PersistentKeepalive"] + "'")
        return data["AllowedIps"]

update_wg()
update_dhcp()
print("Everything should be up to date.")
    
