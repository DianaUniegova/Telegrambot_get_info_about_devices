from library import g4f, requests, re, pd, ipaddress
from library import SHODAN_URL, SHODAN_API_KEY, IPAPI_URL, ABUSEIPDB_URL, ABUSEIPDB_API_KEY, MAC_VENDOR_LOOKUP_URL, PORTS_FILE_NAME, MACLOOKUP_API_KEY, MACLOOKUP_URL

data=[]
all_ips=[]
all_macs=[]
all_ports=[]

#function to load ports from excel
def load_ports_from_excel(file_path: str):
    df = pd.read_excel(file_path, engine="openpyxl")

    port_dict = {}

    for _, row in df.iterrows():
        try:
            port = int(row["Port Number"])
            service = row["Service Name"] if pd.notna(row["Service Name"]) else "Unknown"
            protocol = row["Transport Protocol"] if pd.notna(row["Transport Protocol"]) else "Unknown"
            description = row["Description"] if pd.notna(row["Description"]) else "No description"

            # зберігаємо як порт → info
            port_dict[port] = {
                "service": service,
                "protocol": protocol,
                "description": description
            }
        except:
            continue

    return port_dict

PORT_INFO = load_ports_from_excel(PORTS_FILE_NAME)

#function to parse user input
def parse_user_input(text: str):
    global all_ips, all_macs, all_ports
    
    #ip address
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    all_ips.extend(ips)

    #mac address
    mac_pattern = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'
    macs = re.findall(mac_pattern, text)
    all_macs.extend(macs)

    text_clean = text
    for ip in set(ips):
        text_clean = text_clean.replace(ip, ' ')
    for mac in set(macs):
        text_clean = text_clean.replace(mac, ' ')
    
    ports_set = set()

    pattern_context = r'(?:port|ports|порт|порти)[:\s]*[\[\(]*([\d,\s;/\\\]\)\-]+)'
    ctx_matches = re.findall(pattern_context, text_clean, flags=re.IGNORECASE)
    for m in ctx_matches:
        for token in re.split(r'[,\s;/\\\]\)\(\-]+', m):
            if token.isdigit():
                p = int(token)
                if 1 <= p <= 65535:
                    ports_set.add(p)

    pattern_colon = r':\s*(\d{1,5})'
    for m in re.findall(pattern_colon, text_clean):
        p = int(m)
        if 1 <= p <= 65535:
            ports_set.add(p)

    pattern_proto = r'\b(\d{1,5})\s*(?:/|\s+)?\s*(tcp|udp)?\b'
    for m, proto in re.findall(pattern_proto, text_clean, flags=re.IGNORECASE):
        if m.isdigit():
            p = int(m)
            if 1 <= p <= 65535:
                ports_set.add(p)

    if not ports_set:
        for m in re.findall(r'\b\d{1,5}\b', text_clean):
            p = int(m)
            if 1 <= p <= 65535:
                ports_set.add(p)

    ports = sorted(ports_set)
    
    return {
        "ips": ips,
        "macs": macs,
        "ports": ports
    }

#function to get IP info from ip-api
def get_ip_info(ip: str):
    if not IPAPI_URL:
        return None
    try:
        response = requests.get(f"{IPAPI_URL}{ip}")
        if response.status_code == 200:
            global data
            data.append(response.json())
            return response.json()
        return None
    except Exception as e:
        return {"error": str(e)}

#function to get IP info from abuseIPDB
def check_abuse_ipdb(ip: str):
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        if response.status_code == 200:
            global data
            data.append(response.json())
            return response.json()
    except Exception as e:
        return {"error": str(e)}

#function to validate IP
def is_private_ip(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

#function to get IP info from shodan
def get_shodan_info(ip: str):
    if not SHODAN_URL:
        return None
    if is_private_ip(ip):
        return {"error": "Private IP — Shodan does not support LAN ranges"}
    try:
        url = f"{SHODAN_URL}{ip}?key={SHODAN_API_KEY}"
        response = requests.get(f"{SHODAN_URL}{ip}?key={SHODAN_API_KEY}")
        try:
            json_data = response.json()
        except:
            json_data = {"raw": response.text}

        result = {
            "status_code": response.status_code,
            "url": url,
            "response": json_data
        }
        global data
        data.append(result)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

#function to get MAC info from macvendors
def get_mac_vendor(mac: str):
    if not MAC_VENDOR_LOOKUP_URL:
        return None
    try:
        response = requests.get(f"{MAC_VENDOR_LOOKUP_URL}{mac}")
        if response.status_code == 200:
            global data
            data.append(response.text)
            return response.text
        return None
    except Exception as e:
        return {"error": str(e)}

#function to get MAC info from maclookup
def get_maclookup_info(mac: str):
    if not MACLOOKUP_API_KEY:
        return None
    try:
        response = requests.get(f"{MACLOOKUP_URL}{mac}?apiKey={MACLOOKUP_API_KEY}")
        if response.status_code == 200:
            global data
            data.append(response.json())
            return response.json()
        return None
    except Exception as e:
        return {"error": str(e)}

#function to check port info
def check_port_info(port: int):
    if not port or port < 1 or port > 65535:
        return None
    try:
        if port in PORT_INFO:
            entry = PORT_INFO[port]
            service = entry.get("service", "Unknown")
            protocol = entry.get("protocol", "Unknown")
            description = entry.get("description", "No description")

            info = {
                "port": port,
                "service": service,
                "protocol": protocol,
                "description": description
            }
        else:
            info = {
                "port": port,
                "service": "Unknown",
                "protocol": "Unknown",
                "description": "No information found in ports.xlsx"
            }
        return info
    except Exception as e:
        return {"error": str(e)}

def analyze_ports(port_list: list):
    results = []
    for port in port_list:
        info = check_port_info(port)
        results.append(info)
    global data
    data.append(results)
    return results

#function to get chatGPT analysis
def get_chatgpt_analysis():
    data_str = "\n".join(str(item) for item in data)
    prompt = f"""
    You are a specialized analytical assistant in cybersecurity and network infrastructure.
    Your task is to analyze MAC addresses, IP addresses and port lists and make probable conclusions about:
    Device type and manufacturer (by MAC address)
    Use knowledge of OUI (Organizationally Unique Identifier).
    Indicate the most likely brand and type of device (for example: TP-Link router, Fortinet firewall, Dell server, Lenovo laptop).
    System assignment based on open port list
    Based on ports, determine possible server type: {PORT_INFO}
    If information is not enough, make the most likely assumption.
    Geolocation or network owner (by IP address)
    Based on knowledge of IP address structure and known ranges (Amazon AWS, Google Cloud, Azure, countries, providers, home ranges 192.168.x.x, CGNAT 100.64.x.x).
    Indicate a possible location, type of provider or data center.
    
    Answer briefly, clearly and structured, for example:
        MAC: (explanation of the manufacturer and type of device)
        Ports: (what kind of service or purpose of the server)
        IP: (geolocation, provider, data center, or local network)
    
    If the user provides mixed data - analyze each part separately.
    
    If the data is unclear or incomplete - suggest the most likely scenario.
    \n\n{all_ips}
    \n\n{all_macs}
    \n\n{all_ports}
    \n\n{data_str}
    """
    try:
        response = g4f.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        data.clear()
        return response
    except Exception as e:
        return {"error": str(e)}
