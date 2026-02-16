"""Utility functions."""


import os
import re           # For doing regex
import time
import uuid
import socket       # For network connections
import hashlib      # For hashing mac addresses
import platform     # For getting the operating system name
import ipaddress
import subprocess   # For executing a shell command



def run_command(cmd, timeout_seconds=60):
    try:
        if not isinstance(cmd,str):
            print("Error in run_command: provided cmd was not a string")
            return None
            
        if 'nmap' in cmd:
            timeout_seconds = 300
            
        my_env = os.environ.copy()
        if not 'DBUS_SESSION_BUS_ADDRESS' in my_env:
            #print("WARNING, had to add DBUS_SESSION_BUS_ADDRESS to environment variables")
            my_env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=/run/user/1000/bus' #str(run_command('echo $DBUS_SESSION_BUS_ADDRESS')).strip()
        if not 'XDG_RUNTIME_DIR' in my_env:
            #print("WARNING, had to add XDG_RUNTIME_DIR to environment variables")
            my_env['XDG_RUNTIME_DIR'] = '/run/user/1000'
        
        
        p = subprocess.run(cmd, env=my_env, timeout=timeout_seconds, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True, text=True)

        if p.returncode == 0:
            result_string = p.stdout;
            if type(result_string) == 'bytes':
                #print("result string was bytes: ", result_string)
                result_string = result_string.split(b'\x00')
                result_string = result_string.decode('UTF-8')
                
                #result_string = result_string.replace(b'\x00','')
            #result_string = result_string.replace('\x00','')
            #print("result_string: ", type(result_string))
            
            #if type(result_string) != 'str':
            #    result_string = result_string.decode('UTF-8')
            #print("command ran succesfully")
            return result_string #p.stdout.decode('UTF-8') #.decode('utf-8')
            #yield("Command success")
        else:
            if p.stderr:
                return str(p.stderr) # + '\n' + "Command failed"   #.decode('utf-8'))

    except Exception as e:
        print("Error running command: "  + str(e) + ", cmd was: " + str(cmd))
        

def extract_ip(line):
    ip_addresses = re.findall(r'[0-9]+(?:\.[0-9]+){3}', str(line))
    #print("extract_ip: ip_addresses: ", ip_addresses, ", extracted from: ", line)
    #p = re.compile(r'(?:[0-9a-fA-F]:?){12}')
    #p = re.compile(r'((([a-zA-z0-9]{2}[-:]){5}([a-zA-z0-9]{2}))|(([a-zA-z0-9]{2}:){5}([a-zA-z0-9]{2})))')
    # from https://stackoverflow.com/questions/4260467/what-is-a-regular-expression-for-a-mac-address
    if len(ip_addresses):
        #print("extract_ip:  ip_addresses: ", ip_addresses)
        if valid_ip(str(ip_addresses[0])):
            return str(ip_addresses[0])
        elif len(ip_addresses[0]) and valid_ip(str(ip_addresses[0][0])):
            #print("extract_ip: two layers deep")
            return str(ip_addresses[0][0])
    return None
    
def valid_ip(ip=None):
    valid = False
    if isinstance(ip,str):
        try:
            if ip.count('.') == 3 and \
                all(0 <= int(num) < 256 for num in ip.rstrip().split('.')) and \
                len(ip) < 16 and \
                all(num.isdigit() for num in ip.rstrip().split('.')):
                valid = True
        except Exception as ex:
            #print("error in valid_ip: " + str(ex))
            pass
            
    return valid



def valid_ip6(value):
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False
    return False

def extract_mac(line):
    if isinstance(line,str):
        #p = re.compile(r'(?:[0-9a-fA-F]:?){12}')
        p = re.compile(r'((([a-zA-z0-9]{2}[-:]){5}([a-zA-z0-9]{2}))|(([a-zA-z0-9]{2}:){5}([a-zA-z0-9]{2})))')
        # from https://stackoverflow.com/questions/4260467/what-is-a-regular-expression-for-a-mac-address
        macs = re.findall(p, str(line))
        if macs and len(macs):
            if valid_mac(str(macs[0])):
                return str(macs[0]).upper()
            elif len(macs[0]) and valid_mac(str(macs[0][0])):
                return str(macs[0][0]).upper()
    return None

def valid_mac(mac):
    if isinstance(mac,str):
        return mac.count(':') == 5 and \
            all(0 <= int(num, 16) < 256 for num in mac.rstrip().split(':')) and \
            not all(int(num, 16) == 255 for num in mac.rstrip().split(':'))
    else:
        return False

def mac_to_id(mac=''):
    #hash_string = str(hash(mac))
    #if hash_string[:1] == '-':
    #    hash_string = hash_string[1:]
    #return hash_string
    if not isinstance(mac,str) or mac == '':
        print("\n\nWARNING, mac_to_id: mac was empty or not a string. Using uuid instead\n\n")
        mac = str(uuid.uuid4())
    
    mac = mac.upper()
    hash_object = hashlib.md5(mac.encode())
    hash_string = hash_object.hexdigest()
    hash_string = hash_string[:12]
    #print("hashed mac: " + str(hash_string))
    
    return 'presence-{}'.format(hash_string)


def text_hash(text):
    if not isinstance(text,str) or text == '':
        return None
    hash_object = hashlib.md5(text.encode())
    return str(hash_object.hexdigest())


def extract_hostname_from_avahi_line(line):
    if isinstance(line,str) and ';' in line and line.startswith('='):
        line_parts = line.split(';')
        if len(line_parts) > 6 and len(str(line_parts[6])) > 4:
            if not '<' in str(line_parts[6]) and '.' in str(line_parts[6]):
                return str(line_parts[6]).lower()
    return None

def clamp(n, minn, maxn):
    return max(min(maxn, n), minn)


def get_own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '192.168.1.1'
    finally:
        s.close()
    return IP















# I couldn't get the import to work, so I just copied some of the code here:
# It was made by Victor Oliveira (victor.oliveira@gmx.com)


OUI_FILE = 'oui.txt'
SEPARATORS = ('-', ':')
BUFFER_SIZE = 1024 * 8

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

def get_vendor_old(mac, oui_file=OUI_FILE):
    
    
    # TODO: this could be replaced with a shell call:
    # #!/bin/bash
    # OUI=$(ip addr list|grep -w 'link'|awk '{print $2}'|grep -P '^(?!00:00:00)'| grep -P '^(?!fe80)' | tr -d ':' | head -c 6)
    #curl -sS "http://standards-oui.ieee.org/oui.txt" | grep -i "$OUI" | cut -d')' -f2 | tr -d '\t'
    
    mac_clean = mac
    for separator in SEPARATORS:
        mac_clean = ''.join(mac_clean.split(separator))

    try:
        int(mac_clean, 16)
    except ValueError:
        raise ValueError('Invalid MAC address.')

    mac_size = len(mac_clean)
    if mac_size > 12 or mac_size < 6:
        raise ValueError('Invalid MAC address.')

    mac_half = mac_clean[0:6]
    mac_half_upper = mac_half.upper()

    
    #vendor_command = "grep -i " + str(mac_half_upper) + " " + str(os.path.join(__location__, oui_file)) + " | cut -d')' -f2 | tr -d '\t'"
    #result = subprocess.run(vendor_command, shell=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) #.decode())
    #vendor_alt = result.stdout.split('\n')[0]
    #print("VENDOR_ALT FROM GREP: " + str(vendor_alt))

    with open(os.path.join(__location__, oui_file)) as file:
        #mac_half = mac_clean[0:6]
        #mac_half_upper = mac_half.upper()
        while True:
            line = file.readline()
            if line:
                if line.startswith(mac_half_upper):
                    vendor = line.strip().split('\t')[-1]
                    return vendor
            else:
                break



def nmblookup(ip_address):
    # This can sometimes find the hostname.
    #print("in NMB lookup helper function")
    if valid_ip(ip_address):
        command = "nmblookup -A " + str(ip_address)
        #print("NMB command = " + str(command))
        try:
            result = subprocess.run(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) #.decode())
            name = ""
            for line in result.stdout.split('\n'):
                
                #print("NMB LINE = " + str(line))
                if line.endswith(ip_address) or line.endswith('not found'): # Skip the first line, or if nmblookup is not installed.
                    continue
                name = str(line.split('<')[0])
                name = name.strip()
                #print("lookup name = " + str(name))
                
                return name
                
            #return str(result.stdout)

        except Exception as ex:
            pass
            #print("Nmblookup error: " + str(ex))
        return ""
        #return str(subprocess.check_output(command, shell=True).decode())
    
    
#def hostname_lookup(addr):
#     try:
#         return socket.gethostbyaddr(addr)
#     except socket.herror:
#         return None, None, None    