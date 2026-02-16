"""Network scanner for Candle Controller"""


# get details about scanning speed:
# nmap -T4 -d -p21-25 192.168.0.1



import os
import re
import sys
import csv
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
import json
import time
import uuid
import socket
import chardet
from datetime import datetime, timedelta
#import xmltodict
import threading
import subprocess
from gateway_addon import Adapter, Database, Action

try:
    #from gateway_addon import APIHandler, APIResponse
    from .networkscanner_api_handler import *
    #print("VocoAPIHandler imported")
except Exception as ex:
    print("\n\n\n\nERROR IN APIHANDLER\n\n\n\nUnable to load APIHandler (which is used for UI extention): " + str(ex))

from .presence_device import PresenceDevice
from .util import *


#from mac_vendor_lookup import MacLookup, BaseMacLookup



_TIMEOUT = 3

_CONFIG_PATHS = [
    os.path.join(os.path.expanduser('~'), '.webthings', 'config'),
]

if 'WEBTHINGS_HOME' in os.environ:
    _CONFIG_PATHS.insert(0, os.path.join(os.environ['WEBTHINGS_HOME'], 'config'))


class NetworkScannerAdapter(Adapter):
    """Adapter for network scannern"""

    def __init__(self, verbose=False):
        """
        Initialize the object.

        verbose -- whether or not to enable verbose logging
        """
        #print("Initialising adapter from class")
        self.ready = False
        self.addon_name = 'networkscanner'
        self.name = self.__class__.__name__
        Adapter.__init__(self,
                         self.addon_name,
                         self.addon_name,
                         verbose=verbose)
        #print("Adapter ID = " + self.get_id())
        
        self.mayor_version = 2
        self.meso_version = 0
        
        self.DEBUG = False
        self.ready = False
        #print("self.user_profile['baseDir'] = " + self.user_profile['baseDir'])
     
        
        self.should_quick_scan = False
        self.quick_scan_phase = 0
        self.scan_time_delta = 0 # how long the periodic scan took. Should be less than a minute..
        
        #self.memory_in_weeks = 10 # How many weeks a device will be remembered as a possible device.
        self.time_window = 10 # How many minutes should a device be away before we consider it away?

        self.own_ip = [] # We scan only scan if the device itself has an IP address.
        
        self.thing_pairing_done = False
        
        self.prefered_interface = "eth0"
        self.selected_interface = "eth0"
        
        self.busy_doing_light_scan = False
        self.devices_excluding_arping = ""
        
        self.use_brute_force_scan = False # was used for continuous brute force scanning. This has been deprecated.
        self.should_brute_force_scan = False
        self.busy_doing_brute_force_scan = False
        self.last_brute_force_scan_time = 0             # Allows the add-on to start a brute force scan right away.
        self.seconds_between_brute_force_scans = 1800  #1800  # 30 minutes     

        self.busy_doing_security_scan = False
        self.script_outputs = {}
        self.last_scan_timestamp = int(time.time())

        self.avahi_lines = []
        self.available_interfaces = {}
        self.available_ips = {}

        self.messages = []
        self.tcpdump = None
        
        self.own_hostname = str(run_command('hostname')).lower() + '.local'

        #NMAP
        self.nmap_installed = False
        if str(run_command('which nmap')).startswith('/'):
            self.nmap_installed = True
        self.nmap_quick_scan_results = {}

        # AVAHI
        self.last_avahi_scan_time = 0
        self.raw_avahi_scan_result = ""
        self.avahi_lookup_table = {}
        self.candle_controllers_ip_list = set()
        self.ignore_candle_controllers = True
        
        self.nbtscan_results = ""
        self.thing_ids_with_possibly_intermittent_hostnames = []
        
        self.waiting_two_minutes = True
        self.running = True
        self.created_as_things = [] # created as a thing. The user may or may not have accepted it as a thing
        self.accepted_as_things = [] # accepted as a thing by the user
        self.not_seen_since = {} # used to determine if a device hasn't responded for a long time

        self.addon_path = os.path.join(self.user_profile['addonsDir'], self.addon_name)
        
        self.data_dir_path = os.path.join(self.user_profile['dataDir'], self.addon_name)
        self.persistence_file_path = os.path.join(self.data_dir_path,'persistence.json')
        
        self.nmap_scripts = []
        self.nmap_scripts_dir = os.path.join(os.path.expanduser('~'), '.webthings','etc','nmap','scripts')

        self.last_security_update_time = 0
        self.update_available_nmap_scripts_list()
        
        
        self.nmap_vulners_file_exists = False
        self.nmap_vulnerabilities_script_path = os.path.join(self.nmap_scripts_dir,'vulners.nse')
        if os.path.isfile(self.nmap_vulnerabilities_script_path):
            self.nmap_vulners_file_exists = True

        self.backup_oui_file_path = os.path.join(self.addon_path,'oui.csv')
        
        self.oui_file_path = os.path.join(self.data_dir_path,'oui.csv')
        if not os.path.exists(self.oui_file_path) and os.path.exists(self.backup_oui_file_path):
            os.system('cp ' + str(self.backup_oui_file_path) + ' ' + self.oui_file_path)
        
        
        self.mac_vendor_csv = None
        if os.path.exists(self.oui_file_path):
            self.mac_csv = open(self.oui_file_path, 'r')
            if self.mac_csv:
                self.mac_vendor_csv = csv.reader(self.mac_csv)
        
        self.should_save = False
        
        self.saved_devices_from_controller = {} # holds devices that the controller says it has already accepted
        self.persistent_data = {} # will hold data loaded from persistence file
        self.previously_found = {} # will hold the previously accepted devices recovered from persistence data
        
        try:
            if os.path.isfile(self.persistence_file_path):
                with open(self.persistence_file_path) as file_object:
                
                    self.persistent_data = json.load(file_object)
                    if 'previously_found' in self.persistent_data:
                        #pass
                        self.previously_found = self.persistent_data['previously_found']
                    elif 'devices' in self.persistent_data:
                        #pass
                        print("loading persistent data's devices into self.previously_found")
                        self.previously_found = self.persistent_data['devices']
                        
                    if 'last_security_update_time' in self.persistent_data:
                        self.last_security_update_time = self.persistent_data['last_security_update_time']
                
                #print("Previously found items: = " + str(self.previously_found))

        #except (IOError, ValueError):
        except Exception as ex:   
            self.previously_found = {}
            print("Failed to load persistent data JSON file. Error was: " + str(ex))
            
        self.previous_found_devices_length = len(self.previously_found)
        
        # Reset all the last_seen data from the persistence file, since it could be out of date.
        for _id in list(self.previously_found.keys()):
            try:
                if not 'thing' in self.previously_found[_id]:
                    del self.previously_found[_id]
                    continue
                elif isinstance(self.previously_found[_id]['thing'],bool) and self.previously_found[_id]['thing'] == False:
                    del self.previously_found[_id]
                    continue
                
                if 'mac_address' in self.previously_found[_id] and isinstance(self.previously_found[_id]['mac_address'],str):
                    self.previously_found[_id]['mac'] = self.previously_found[_id]['mac_address']
                    del self.previously_found[_id]['mac_address']
                if 'mac' in self.previously_found[_id] and isinstance(self.previously_found[_id]['mac'],str):
                    self.previously_found[_id]['mac'] = self.previously_found[_id]['mac'].upper()
                if not 'mac' in self.previously_found[_id]:
                    print("ERROR, deleting previously_found device that did not have mac address: ", json.dumps(self.previously_found[_id],indent=4))
                    del self.previously_found[_id]
                
                if 'data-collection' in self.previously_found[_id]:
                    self.previously_found[_id]['data_collection'] = bool(self.previously_found[_id]['data-collection'])
                    del self.previously_found[_id]['data-collection']
                if not 'data_collection' in self.previously_found[_id]:
                    self.previously_found[_id]['data_collection'] = True
                
                if 'last_seen' in self.previously_found[_id]:
                    self.previously_found[_id]['last_seen'] = None
                self.not_seen_since[_id] = None
            except Exception as ex:
                print("Error pruning/adjusting previously_found devices from persistence: " + str(ex))
        
        if self.DEBUG:
            print("\n\ninitial self.previously_found: \n\n", json.dumps(self.previously_found, indent=4), "\n\n")
        
        
        time.sleep(.3) # avoid swamping the sqlite database
        
        self.add_from_config() # Here we get data from the settings in the Gateway interface.

        try:
            if self.DEBUG:
                print("starting api handler")
            self.api_handler = NetworkScannerAPIHandler(self, verbose=True)
            #self.manager_proxy.add_api_handler(self.extension)
            if self.DEBUG:
                print("Extension API handler initiated")
        except Exception as e:
            if self.DEBUG:
                print("Failed to start API handler (this only works on gateway version 0.10 or higher). Error: " + str(e))
        

        if self.DEBUG:
            print("self.previously_found: " + str(self.previously_found ))

        if not self.DEBUG:
            time.sleep(5) # give it a few more seconds to make sure the network is up
           
        self.selected_interface = "wlan0"
        self.select_interface() # checks if the preference is possible.
        
        if self.DEBUG:
            print("selected interface = " + str(self.selected_interface))
        
        #self.DEBUG = False
           
        try:
            if len(self.own_ip) == 0:
                fresh_ip = get_own_ip()
                if valid_ip(fresh_ip):
                    self.own_ip = [fresh_ip]
        except:
            if self.DEBUG:
                print("Error, could not get actual own IP address")

        # First scan
        time.sleep(2) # wait a bit before doing the quick scan. The gateway will pre-populate based on the 'handle-device-saved' method.

        self.controller_start_time = None
        try:
            controller_uptime = run_command('cat /proc/uptime')
            if isinstance(controller_uptime,str):
                if ' ' in controller_uptime:
                    controller_uptime = controller_uptime.split()[0]
                    controller_uptime = float(controller_uptime)
                    self.controller_start_time = time.time() - controller_uptime
                    if controller_uptime >= 0 and controller_uptime < 120:
                        time.sleep(120 - controller_uptime)
        except Exception as ex:
            print("caught error getting controller uptime: " + str(ex))
            time.sleep(120)
        
        self.waiting_two_minutes = False
        
        #print("starting tcpdump_listener")
        self.tcpdump_listener()
        
        self.quick_scan() # get initial list of devices

        #self.handle_unfound_accepted_things() # some things might not be found by the scan, but be accepted in the UI. They should be set to disconnected.
        
        if self.DEBUG:
            print("Starting the clock thread")
        try:
            t = threading.Thread(target=self.clock)
            t.daemon = True
            t.start()
        except:
            if self.DEBUG:
                print("Error starting the continous light scan thread")
        
        self.ready = True
        
        
        

    def add_from_config(self):
        """Attempt to load addon settings."""

        try:
            database = Database(self.addon_name)

            if not database.open():
                return

            config = database.load_config()
            database.close()


        except Exception as ex:
            print("Error getting config data from database. Check the add-on's settings page for any issues. Error: " + str(ex))
            self.close_proxy()

        
        try:
            if not config:
                print("Error: required variables not found in config database. Check the addon's settings.")
                return

            if 'Debugging' in config:
                self.DEBUG = bool(config['Debugging'])
            
            if 'Show Candle controllers' in config:
                self.ignore_candle_controllers = not bool(config['Show Candle controllers'])
                if self.DEBUG:
                    print("self.ignore_candle_controllers: " + str(self.ignore_candle_controllers))
            
            # Target IP
            # Can be used to override normal behaviour (which is to scan the controller's neighbours), and target a very different group of IP addresses.
            if 'Target IP' in config:
                try:
                    potential_ip = str(config['Target IP'])
                    if potential_ip != "":
                        if valid_ip(potential_ip):
                            if not potential_ip in self.own_ip:
                                self.own_ip.append(potential_ip)
                            print("Using target IP from addon settings")
                        else:
                            if self.DEBUG:
                                print("This addon does not understand '" + str(potential_ip) + "' as a valid IP address. Go to the add-on settings page to fix this. For now, the addon will try to detect and use the system's IP address as a base instead.")
                        
                except exception as ex:
                    print("Error handling Target IP setting: " + str(ex))
            else:
                if self.DEBUG:
                    print("No target IP address was available in the settings data")

            # Network interface preference
            if 'Network interface' in config:
                if str(config['Network interface']) != "":
                    if str(config['Network interface']) == "prefer wired":
                        self.prefered_interface = "eth0"
                    if str(config['Network interface']) == "prefer wireless":
                        self.prefered_interface = "wlan0"

            # how many minutes should "not recently spotted" be?
            if 'Time window' in config:
                try:
                    if config['Time window'] != None and config['Time window'] != '':
                        self.time_window = clamp(int(config['Time window']), 1, 10800) # In minutes. 'Grace period' could also be a good name.
                        if self.DEBUG:
                            print("Using time window value from settings: " + str(self.time_window))
                except:
                    print("No time window preference was found in the settings. Will use default.")

            # Should brute force scans be attempted?
            if 'Use brute force scanning' in config:
                self.use_brute_force = bool(config['Use brute force scanning'])

            if 'Addresses to not arping' in config:
                try:
                    self.devices_excluding_arping = str(config['Devices excluding arping'])  
                    if self.DEBUG:
                        print("Devices excluding ARPing from settings: " + str(self.devices_excluding_arping))
                except:
                    if self.DEBUG:
                        print("No addresses to exclude from arping were found in the settings.")

        except Exception as ex:
            print("Error getting config data from database. Check the add-on's settings page for any issues. Error: " + str(ex))
            self.close_proxy()
            
            






    def clock(self):
        """ Runs continuously and scans IP addresses that the user has accepted as things """
        if self.DEBUG:
            print("clock thread init")
        time.sleep(5)
        last_run = 0
        succesfully_found = 0 # If all devices the user cares about are actually present, then no deep scan is necessary.
        slow_counter = 0
        while self.running:
            last_run = time.time()
            
            if self.DEBUG:
                print("Clock TICK")
                
            slow_counter += 1
            
                
            
            if self.busy_doing_light_scan == False and self.busy_doing_brute_force_scan == False:
                if self.should_quick_scan:
                    self.should_quick_scan = False
                    self.quick_scan()
                
            mdns_emitters = []
            mdns_hostname_lookup = {}
            if self.DEBUG:
                print("\nclock: total tcpdump messages length: ", len(self.messages))
            if slow_counter > 15:
                if self.DEBUG:
                    print("skipping using tcpdump messages (once every 15 minutes)")
            else:
                for message in reversed(self.messages): # start from the end, with the newest messages
                    if not '.5353 > 224.0.0.251.5353:' in message:
                        if self.DEBUG:
                            print("clock: strange tcpdump message: ", message)
                    else:
                        split_message = message.split('.5353 > 224.0.0.251.5353:')
                        source_ip = split_message[0].split()[-1]
                        

                        #if self.DEBUG:
                        #    print("clock:  source_ip from tcpdump message: ", source_ip, message)
                            
                        if valid_ip(source_ip):
                            
                            if not source_ip in mdns_emitters:
                                if self.DEBUG:
                                    print("clock: spotted another mDNS emitter IP: ", source_ip)
                                mdns_emitters.append(source_ip)
                            
                            if not source_ip in mdns_hostname_lookup and '(Cache flush) SRV ' in split_message[1] and '.:' in split_message[1]:
                                hostname = split_message[1].split('(Cache flush) SRV ')[1].split('.:')[0].lower()
                                if hostname.count(".") == 1 and not ' ' in hostname and not '<' in hostname and len(hostname) < 64:
                                    if self.DEBUG:
                                        print("clock: got a hostname from live mDNS messages: ", hostname)
                                    mdns_hostname_lookup[hostname] = source_ip
                                    mdns_hostname_lookup[source_ip] = hostname
                            
                            
                if self.DEBUG:
                    print("last minute's mdns_emitters: ", mdns_emitters)
            
                        
            self.messages = []
            
            succesfully_found = 0
            try:
                # check if own hostname changed, and if so, take a shortcut to immediately start updating hostnames
                current_own_hostname = str(run_command('hostname')).lower() + '.local'
                if current_own_hostname != 'none.local' and current_own_hostname != self.own_hostname:
                    if self.DEBUG:
                        print("Detected that OWN hostname changed from ", self.own_hostname, " to ", current_own_hostname)
                    self.own_hostname = current_own_hostname
                    ip_addresses = str(run_command('hostname -I')).split()
                    for ip_address in ip_addresses:
                        if valid_ip(ip_address) or valid_ip6(ip_address):
                            mdns_hostname_lookup[ip_address] = current_own_hostname
                            mdns_hostname_lookup[current_own_hostname] = ip_address
                    
                    slow_counter == 16
                    self.should_save = True
                
                previously_found_keys = list(self.previously_found.keys())
                
                
                fresh_arpa_output = str(run_command('arp -a | grep -v incomplete'))
                ip_mac_lookup = {}
                for line in fresh_arpa_output.splitlines():
                    ip_address = extract_ip(line)
                    mac_address = extract_mac(line)
                    if valid_ip(ip_address) and valid_mac(mac_address):
                        ip_mac_lookup[ip_address] = mac_address
                        ip_mac_lookup[mac_address] = ip_address
                if self.DEBUG:
                    print("_____")
                    print("mdns_hostname_lookup: \n", json.dumps(mdns_hostname_lookup,indent=4))
                    print("ARPA ip_mac_lookup: \n", json.dumps(ip_mac_lookup,indent=4))
                    
                # TODO: Not optimal to have to update both these sources of truth this way
                # TODO: also validate against MAC from arp -a?
                for _id in previously_found_keys:
                    if 'ip' in self.previously_found[_id]:
                        if str(self.previously_found[_id]['ip']) in mdns_hostname_lookup:
                            print("previously_found ip was in mdns_hostname_lookup: ", str(self.previously_found[_id]['ip']), " -> ", mdns_hostname_lookup[str(self.previously_found[_id]['ip'])])
                            for ifname in list(self.available_ips.keys()):
                                for known_ip_address in list(self.available_ips[ifname].keys()):
                                    if 'thing_id' in self.available_ips[ifname][known_ip_address] and self.available_ips[ifname][known_ip_address]['thing_id'] == _id:
                                        if self.DEBUG:
                                            print("- found the device with the ip for that hostname")
                                        if 'hostname' in self.available_ips[ifname][known_ip_address] and str(self.available_ips[ifname][known_ip_address]['hostname']) != mdns_hostname_lookup[str(self.previously_found[_id]['ip'])]:
                                            if self.DEBUG:
                                                print("hostname of device changed from: ", str(self.available_ips[ifname][known_ip_address]['hostname']), " to ", str(mdns_hostname_lookup[str(self.previously_found[_id]['ip'])]))
                                            #if str(mdns_hostname_lookup[str(self.previously_found[_id]['ip'])]) == str(known_ip_address):
                                            
                                            self.available_ips[ifname][known_ip_address]['message'] = 'Hostname changed from ' + str(self.available_ips[ifname][known_ip_address]['hostname']) + ' to ' + str(mdns_hostname_lookup[str(self.previously_found[_id]['ip'])])
                                            self.should_save = True
                                        if self.DEBUG:
                                            print("updating/setting hostname in self.available_ips to: ", mdns_hostname_lookup[str(self.previously_found[_id]['ip'])])
                                        self.available_ips[ifname][known_ip_address]['hostname'] = str(mdns_hostname_lookup[str(self.previously_found[_id]['ip'])])

                            # some curiosity
                            if 'ip' in self.previously_found[_id] and 'mac' in self.previously_found[_id] and str(self.previously_found[_id]['ip']) in ip_mac_lookup:
                                if ip_mac_lookup[str(self.previously_found[_id]['ip'])] == str(self.previously_found[_id]['mac']):
                                    if self.DEBUG:
                                        print("OK, according to arp -a the mac address is still matched for ", str(self.previously_found[_id]['ip']))
                                else:
                                    if self.DEBUG:
                                        print("ERROR, according to arp -a the mac address is no longer a match for ", str(self.previously_found[_id]['ip']))
                                        print("- self.previously_found[_id]: ", self.previously_found[_id])
                                        print("- fresh_arpa_output: ", fresh_arpa_output)
                            
                            if self.DEBUG:
                                print("updating/setting hostname in self.previously_found to: ", mdns_hostname_lookup[str(self.previously_found[_id]['ip'])])
                            self.previously_found[_id]['hostname'] = mdns_hostname_lookup[str(self.previously_found[_id]['ip'])].lower()
                            self.should_save = True
                                
                                        
                
                #for _id in self.accepted_as_things:
                for _id in previously_found_keys:
                    
                    if not _id in self.devices:
                        if self.DEBUG:
                            print("\n\nclock ERROR: _id was not in self.devices\n\n")
                        continue
                    
                    if _id in self.previously_found and 'ip' in self.previously_found[_id] and valid_ip(self.previously_found[_id]['ip']):
                        
                        #
                        #  LOOKING FOR REASONS TO SKIP PINGING
                        #
                    
                        should_ping = True
                        
                        # Data collection disabled?
                        if 'data_collection' in self.previously_found[_id]:
                            if self.previously_found[_id]['data_collection'] == False:
                                if self.DEBUG:
                                    print("clock: skipping pinging of " + str(self.previously_found[_id]['ip']) + " because data collection is disabled")
                                should_ping = False
                        else:
                            if self.DEBUG:
                                print("clock: data_collection value did not exist yet in this thing, adding it now.")
                            self.previously_found[_id]['data_collection'] = True
                            self.should_save = True
                    
                            
                        # Data-mute enabled?
                        if 'data_mute_end_time' in self.previously_found[_id]:
                            if self.DEBUG:
                                print("data_mute_end_time: " + str(self.previously_found[_id]['data_mute_end_time']) + ". delta: " + str(self.previously_found[_id]['data_mute_end_time'] - time.time()))
                            if self.previously_found[_id]['data_mute_end_time'] > time.time():
                                should_ping = False
                                if self.DEBUG:
                                    print("clock: skipping pinging of muted device " + str(self.previously_found[_id]['ip']))
                                try:
                                    self.previously_found[_id]['last_seen'] = None
                                    
                                    if 'recently1' in self.devices[_id].properties.keys():
                                        if 'value' in self.devices[_id].properties["recently1"] and self.devices[_id].properties["recently1"].value == None:
                                            pass
                                        else:
                                            self.devices[_id].properties["recently1"].update(None)
                                except Exception as ex:
                                    print("caught error checking data_mute_end_time: " + str(ex))
                                
                                
                        else:
                            if self.DEBUG:
                                print("clock: mute_end_time value did not exist yet in this thing, adding it now.")
                            self.previously_found[_id]['data_mute_end_time'] = 0
                            self.should_save = True
                        
                            
                        # To ping or not to ping
                        if should_ping == True:
                            
                            # No need to ping because it was broadcasting during the past minute
                            if str(self.previously_found[_id]['ip']) in mdns_emitters:
                                self.previously_found[_id]['last_seen'] = time.time()
                                if self.DEBUG:
                                    print("clock: skipping pinging of " + str(self.previously_found[_id]['ip']) + " because it's emitting mDNS messages")
                                self.should_save = True
                            
                            elif self.nmap_installed:
                                time.sleep(1)
                                nmap_ping_output = str(run_command('sudo nmap -sn -PP ' + str(self.previously_found[_id]['ip'])))
                                #nmap_ping_output = str(run_command('sudo nmap -sn -PR ' + str(self.previously_found[_id]['ip'])))
                                if self.DEBUG:
                                    print("clock -> ip, nmap_ping_output: ", self.previously_found[_id]['ip'], nmap_ping_output)
                                if 'Host is up' in nmap_ping_output:
                                    self.previously_found[_id]['last_seen'] = time.time()
                                    for line in nmap_ping_output.splitlines():
                                        if 'MAC Address:' in str(line):
                                            nmap_ping_mac = extract_mac(line)
                                            if valid_mac(nmap_ping_mac) and 'mac' in self.previously_found[_id] and str(self.previously_found[_id]['mac']) != str(nmap_ping_mac).upper():
                                                if not 'previous_mac_addresses' in self.previously_found[_id]:
                                                    self.previously_found[_id]['previous_mac_addresses'] = []
                                                self.previously_found[_id]['previous_mac_addresses'].append({'mac':str(self.previously_found[_id]['mac']),'change_detection_timestamp':int(time.time())})
                                                if len(self.previously_found[_id]['previous_mac_addresses']) > 10:
                                                    self.previously_found[_id]['previous_mac_addresses'] = self.previously_found[_id]['previous_mac_addresses'][-10:]
                                                self.previously_found[_id]['mac'] = nmap_ping_mac
                                    
                                                # also update the mac in the scan data, so the UI will get updated
                                                for ifname in list(self.available_ips.keys()):
                                                    for known_ip_address in list(self.available_ips[ifname].keys()):
                                                        if 'thing_id' in self.available_ips[ifname][known_ip_address] and str(self.available_ips[ifname][known_ip_address]['thing_id']) == _id:
                                                            self.available_ips[ifname][known_ip_address]['message'] = 'MAC address changed from ' + str(self.available_ips[ifname][known_ip_address]['mac']) + ' to ' + str(nmap_ping_mac)
                                                            self.available_ips[ifname][known_ip_address]['mac'] = nmap_ping_mac
                                                            self.available_ips[ifname][known_ip_address]['mac_source'] = 'nmap'
                                                            self.should_save = True
                                                            break
                        
                            else:
                                if self.DEBUG:
                                    print("- Should ping is True. Will ping/arping now.")
                                if 'ip' in self.previously_found[_id]:
                                    if self.ping(self.previously_found[_id]['ip'],1):
                                        if self.DEBUG:
                                            print("Clock: >> Ping could not find " + str(self.previously_found[_id]['ip']) + " at " + str(self.previously_found[_id]['ip']) + ". Maybe Arping can.")
                                        try:
                                            if 'mac' in self.previously_found[_id]:
                                                if not self.previously_found[_id]['ip'] in self.devices_excluding_arping and not self.previously_found[_id]['mac'] in self.devices_excluding_arping and self.arping(self.previously_found[_id]['ip'], 1) == 0:
                                                    self.previously_found[_id]['last_seen'] = int(time.time())
                                                    if self.DEBUG:
                                                        print("Clock: >> Arping found it. last_seen updated.")
                                                    succesfully_found += 1
                                                    self.not_seen_since[_id] = None
                                                else:
                                                    if self.DEBUG:
                                                        print("Clock: >> Arping also could not find the device.")
                                                    if _id not in self.not_seen_since:
                                                        if self.DEBUG:
                                                            print("--adding first not_seen_since time")
                                                        self.not_seen_since[_id] = int(time.time())
                                            
                                                    if self.not_seen_since[_id] == None:
                                                        if self.DEBUG:
                                                            print("--not_seen_since time was None. Setting current time instead.")
                                                        self.not_seen_since[_id] = int(time.time())
                                                        if self.DEBUG:
                                                            print("- Clock: Remembering fresh not-seen-since time")
                                                    elif self.not_seen_since[_id] + (60 * (self.time_window + 1)) < time.time():
                                                        if self.DEBUG:
                                                            print("NOT SPOTTED AT ALL DURATION IS NOW LONGER THAN THE TIME WINDOW!")
                                                        recently = False
                                                        if _id in self.devices:
                                                            if 'recently1' not in self.devices[_id].properties:
                                                                if self.DEBUG:
                                                                    print("+ Clock: Adding recently spotted property to presence device")
                                                                self.devices[_id].add_boolean_child("recently1", "Recently spotted", recently, True, "BooleanProperty") # name, title, value, readOnly, @type
                                                            else:
                                                                if self.DEBUG:
                                                                    print("+ Clock: updating recently spotted property")
                                                                self.devices[_id].properties["recently1"].update(recently)
                                                        else:
                                                            if self.DEBUG:
                                                                print("warning, that is was not yet in self.devices?")
                                            else:
                                                if self.DEBUG:
                                                    print("Should arping, but missing mac address: " + str(self.previously_found[_id]))
                                                
                                                
                                        except Exception as ex:
                                            if self.DEBUG:
                                                print("Error trying last_seen arping: " + str(ex))
                                    else:
                                        if self.DEBUG:
                                            print(">> Ping found device")
                                        self.previously_found[_id]['last_seen'] = int(time.time())
                                        succesfully_found += 1
                                        self.not_seen_since[_id] = None
                                else:
                                    if self.DEBUG:
                                        print("- Should ping, but no IP: " + str(self.previously_found[_id]))
                    
                        else:
                            if self.DEBUG:
                                print("-data-collection is not allowed for " + str(self.previously_found[_id]['ip']) + ", skipping ping.")
                        
                    
                    
                    
                    
                        #
                        #  MINUTES AGO
                        #

                        try:
                            if self.previously_found[_id]['last_seen'] != 0 and self.previously_found[_id]['last_seen'] != None:
                                if self.DEBUG:
                                    print("-adding a minute to minutes_ago variable")
                                minutes_ago = int( (time.time() - self.previously_found[_id]['last_seen']) / 60 )
                            
                            else:
                                minutes_ago = None
                                if self.DEBUG:
                                    print("                             --> MINUTES AGO IS NONE <--")
                                
                            
                                
                        
                            if minutes_ago == None:
                                if self.DEBUG:
                                    print("ERROR minutes ago fell through because it's None")
                            
                            elif isinstance(minutes_ago, (int, float, complex)) and minutes_ago <= 86400:
                                
                                if self.devices[_id] and 'minutes_ago' not in self.devices[_id].properties:
                                    if self.DEBUG:
                                        print("+ Adding minutes ago property to presence device, with value: " + str(minutes_ago))
                                    self.devices[_id].add_integer_child("minutes_ago", "Minutes ago last seen", minutes_ago)

                                if self.DEBUG:
                                    print("Probably updating minutes_ago of " + str(self.previously_found[_id]['ip']) + " to: " + str(minutes_ago))
                            
                                # The longer the device is away, the less precise/frequent the tracking becomes
                                if minutes_ago >= 43200:
                                    if minutes_ago % 60 == 0:
                                        self.devices[_id].properties["minutes_ago"].update(minutes_ago)
                                elif minutes_ago >= 21600:
                                    if minutes_ago % 30 == 0:
                                        self.devices[_id].properties["minutes_ago"].update(minutes_ago)
                                elif minutes_ago >= 10800:
                                    if minutes_ago % 10 == 0:
                                        self.devices[_id].properties["minutes_ago"].update(minutes_ago)
                                elif minutes_ago >= 7200:
                                    if minutes_ago % 5 == 0:
                                        self.devices[_id].properties["minutes_ago"].update(minutes_ago)
                                elif minutes_ago >= 3600:
                                    if minutes_ago % 3 == 0:
                                        self.devices[_id].properties["minutes_ago"].update(minutes_ago)
                                else:
                                    self.devices[_id].properties["minutes_ago"].update(minutes_ago)
                            else:
                                if self.DEBUG:
                                    print("ERROR minutes ago fell through while updating. Its value is: " + str(minutes_ago))
                                    
                        except Exception as ex:
                            if self.DEBUG:
                                print("Clock: caught ERROR: could not add/update minutes_ago property" + str(ex))
                    
                    
                        #
                        #  RECENTLY SPOTTED
                        #
                    
                        try:
                            recently = None
                            if minutes_ago != None:
                                if self.DEBUG:
                                    print("minutes_ago was not None, it was: " + str(minutes_ago))
                                if minutes_ago > self.time_window:
                                    recently = False
                                else:
                                    recently = True
                                
                            else:
                                if self.DEBUG:
                                    print("minutes_ago was None, so not determining recently state (will be None too)")
                        
                            if 'recently1' not in self.devices[_id].properties:
                                if self.DEBUG:
                                    print("+ Adding recently spotted property to presence device")
                                self.devices[_id].add_boolean_child("recently1", "Recently spotted", recently, True, "BooleanProperty") # name, title, value, readOnly, @type
                            else:
                                self.devices[_id].properties["recently1"].update(recently)
                        
                        except Exception as ex:
                            if self.DEBUG:
                                print("Clock: caught error adding recently spotted property: " + str(ex))



                        #
                        #  DATA COLLECTION
                        #
                    
                        try:
                            if 'data_collection' not in self.devices[_id].properties:
                                if self.DEBUG:
                                    print("+ Adding data-collection property to presence device")
                            
                                data_collection_state = True
                                if 'data_collection' in self.previously_found[_id]:
                                    if self.DEBUG:
                                        print("+ Found a data-collection preference in the previously_found data")
                                    data_collection_state = self.previously_found[_id]['data_collection']
                        
                                self.devices[_id].add_boolean_child("data_collection", "Data collection", data_collection_state, False, "") # name, title, value, readOnly, @type
                        
                        except Exception as ex:
                            if self.DEBUG:
                                print("Clock: caught error adding data_collection property: " + str(ex))
                            
                    
            except Exception as ex:
                if self.DEBUG:
                    print("\nClock thread error: " + str(ex))
            
            if slow_counter > 15:
                slow_counter = 0
            
            if self.should_save: # This is the only time the json file is stored.    
                self.save_to_json() # also sets should_save to false again
                if self.DEBUG:
                    print("clock: called save_to_json")
            
            accepted_as_things_count = len(self.accepted_as_things)
            self.scan_time_delta = time.time() - last_run
            if self.DEBUG:
                print("clock: pinging all " + str(accepted_as_things_count) + " accepted devices took " + str(self.scan_time_delta) + " seconds.")
                
            delay = 5
            if self.scan_time_delta < 59:
                if self.DEBUG:
                    print("clock: scan took less than a minute. Will wait " + str(self.scan_time_delta + 1 ) + " seconds before starting the next round")
                delay = 59 - self.scan_time_delta
            
            for second in range(int(delay)):
                if self.should_quick_scan and self.busy_doing_light_scan == False and self.busy_doing_brute_force_scan == False:
                   break
                time.sleep(1)
                
            time.sleep(1)
            
           
        
        
    def check_available_interfaces(self):
        if self.DEBUG:
            print("\n\n\nnetworkscanner debug: in check_available_interfaces")
        available_interfaces = {}
        try:
            # nmap -sn 192.168.12.0/24
            
            nmcli_check = str(run_command("nmcli -g device,state c s | grep activated | grep -v 'lo:'")).lower() #str(subprocess.check_output(['nmcli', '-g', 'DEVICE,STATE', 'c', 's', '|', 'grep', 'activated']).decode('utf-8'))
            if self.DEBUG:
                print("networkscanner debug: check_available_interfaces: nmcli_check: ", nmcli_check)
            if 'command not found' in nmcli_check:
                nmcli_check = ''
            
            ip_link_show_raw_json = str(subprocess.check_output(['ip', '-p', '-j', 'link', 'show']).decode('utf-8'))
            
            if ip_link_show_raw_json.startswith('['):
                ip_link_show_list = json.loads(ip_link_show_raw_json)
                
                for interface_item in ip_link_show_list:
                    if 'ifname' in interface_item and 'link_type' in interface_item and interface_item["link_type"] == "ether":
                        
                        interface_address_check = str(run_command('ip -p -j addr show ' + str(interface_item['ifname'])))
                        if 'addr_info' in interface_address_check:
                            interface_address_dict = json.loads(interface_address_check)
                            if len(interface_address_dict):
                                interface_item['addr_data'] = interface_address_dict[0]
                        
                        if nmcli_check:
                            if str(interface_item['ifname']).lower() + ':' in nmcli_check:
                                available_interfaces[str(interface_item['ifname'])] = interface_item
                            else:
                                if self.DEBUG:
                                    print("networkscanner debug: check_available_interfaces: skipping interface that according to nmcli is not connected: " + str(interface_item['ifname']))
                                continue
                        else:
                            available_interfaces[str(interface_item['ifname'])] = interface_item
                
                self.available_interfaces = available_interfaces
                self.quick_scan_phase += 1
            if self.DEBUG:
                print("\n\n\nnetworkscanner debug: check_available_interfaces: DONE\n\nself.available_interfaces: \n", json.dumps(self.available_interfaces,indent=4), "\n\n")
                
        except Exception as ex:
            if self.DEBUG:
                print("networkscanner debug: caught error checking for available network interfaces: " + str(ex))




    def check_available_ips(self):
        self.nmap_quick_scan_results = {}
        available_ips = {}
        if self.DEBUG:
            print("in check_available_ips")
        
        nmap_port_hashes = []
            
        arpa_output = ""
        for i in range(10):
            fresh_arpa_output = str(run_command('arp -a | grep -v incomplete'))
            if self.DEBUG:
                print("networkscanner debug: fresh_arpa_output count: ", fresh_arpa_output.count("["))
            if fresh_arpa_output.count("[") == 0:
                pass
            elif fresh_arpa_output.count("[") > arpa_output.count("["):
                pass
            elif fresh_arpa_output.count("[") < arpa_output.count("["):
                break
            elif fresh_arpa_output.count("[") == arpa_output.count("[") and i > 2:
                break
            
            arpa_output = fresh_arpa_output
            
            #if not 'incomplete' in arpa_output.lower():
            #    break
            #else:
            #    print(i, "check_available_ips: there was 'incomplete' in arp -a output: ", arpa_output.lower().count("incomplete"), arpa_output.lower().count("["))
            time.sleep(3)
            #if i % 2 == 0:
            #    self.quick_scan_phase += 1
        if self.DEBUG:
            print("networkscanner debug: optimal arpa_output: \n", arpa_output)
        
        
        ip_neighbor_output = ""
        for i in range(30):
            ip_neighbor_output = str(subprocess.check_output(['ip', 'neighbor']).decode('utf-8'))
            if not 'incomplete' in ip_neighbor_output.lower():
                break
            else:
                if self.DEBUG:
                    print("networkscanner debug: check_available_ips: there was 'incomplete' in ip_neighbor_output: ", ip_neighbor_output.lower().count("incomplete"))
            time.sleep(1)
            if i % 3 == 0:
                self.quick_scan_phase += 1
        
        
        ip6_neighbor_output = ""
        for i in range(30):
            ip6_neighbor_output = str(subprocess.check_output(['ip','-6','neigh']).decode('utf-8'))
            if not 'incomplete' in ip6_neighbor_output.lower():
                break
            else:
                if self.DEBUG:
                    print("networkscanner debug: check_available_ips: there was 'incomplete' in ip6_neighbor_output: ", ip6_neighbor_output.lower().count("incomplete"))
            time.sleep(1)
            if i % 3 == 0:
                self.quick_scan_phase += 1
        
        
        
        self.interface_lookup = {}
        for interface_name in self.available_interfaces.keys():
            if self.DEBUG:
                print("networkscanner debug: check_available_ips:  checking interface: " + str(interface_name))
            
            if not 'addr_data' in self.available_interfaces[interface_name]:
                if self.DEBUG:
                    print("warning, " + str(interface_item) + " has no addr_data. Skipping.")
                continue
                
            if not 'addr_info' in self.available_interfaces[interface_name]['addr_data']:
                if self.DEBUG:
                    print("warning, " + str(interface_item) + " has addr_data, but no addr_info. Skipping.")
                continue
            
            if len(self.available_interfaces[interface_name]['addr_data']['addr_info']) == 0:
                if self.DEBUG:
                    print("warning, " + str(interface_item) + " has addr_data and addr_info, but the IP list is empty. Skipping.")
                continue
            
            if not str(interface_name) in available_ips:
                available_ips[interface_name] = {}
        
            self.quick_scan_phase += 2
            
            interface_mac = None
            interface_second_mac = None
            interface_ip4 = None
            
            if 'address' in self.available_interfaces[interface_name]['addr_data'] and valid_mac(self.available_interfaces[interface_name]['addr_data']['address']):
                interface_mac = str(self.available_interfaces[interface_name]['addr_data']['address']).upper()
            if 'permaddr' in self.available_interfaces[interface_name]['addr_data'] and valid_mac(self.available_interfaces[interface_name]['addr_data']['permaddr']):
                if interface_mac != None and str(self.available_interfaces[interface_name]['addr_data']['permaddr']).upper() != str(self.available_interfaces[interface_name]['addr_data']['address']).upper():
                    interface_second_mac = str(self.available_interfaces[interface_name]['addr_data']['permaddr']).upper()
            
            
            
            
            for ip_data in self.available_interfaces[interface_name]['addr_data']['addr_info']:
                if self.DEBUG:
                    print("check_available_ips:  interface_name,ip_data: \n INTERFACE: ", interface_name, "\n", json.dumps(ip_data,indent=4))
                if 'local' in ip_data:
                    
                    if not str(ip_data['local']) in self.own_ip:
                        self.own_ip.append(str(ip_data['local']))
                    
                    nmap_quick_scan_results = ""
                    if valid_ip(str(ip_data['local'])):
                        interface_ip4 = str(ip_data['local'])
                        available_ips[interface_name][interface_ip4] = {'ip':interface_ip4,'ip_source':'nmcli','candle':True,'self':True}
                        if valid_mac(interface_mac):
                            available_ips[interface_name][interface_ip4]['mac'] = interface_mac
                            available_ips[interface_name][interface_ip4]['mac_source'] = 'nmcli'
                        if valid_mac(interface_second_mac):
                            available_ips[interface_name][interface_ip4]['mac2'] = interface_second_mac
                            available_ips[interface_name][interface_ip4]['mac2_source'] = 'nmcli'
                        if not str(interface_name) in self.interface_lookup and valid_ip(ip_data['local']):
                            self.interface_lookup[str(interface_name)] = str(ip_data['local'])
                        if self.DEBUG:
                            print("calling nmap with interface IP: ", interface_name, ip_data['local'])
                        #nmap_quick_scan_results = str(run_command("sudo nmap --scan-delay=25ms -sS -F " + str(ip_data['local']) + "/24")) #   | grep 'Nmap scan report for'
                        nmap_quick_scan_results = str(run_command("sudo nmap --scan-delay=25ms -sS -F " + str(ip_data['local']) + "/24")) #   | grep 'Nmap scan report for'
                        if nmap_quick_scan_results:
                            self.nmap_quick_scan_results[interface_name] = str(nmap_quick_scan_results)
                        if self.DEBUG:
                            print("\nnmap quick scan results: \n", nmap_quick_scan_results)
                            print("\n")
                            
                        if self.DEBUG:
                            print("nmap_quick_scan_results for: ", interface_name, nmap_quick_scan_results)
                    
                        current_nmap_ip = None
                        spotted_mac = None
                        for nmap_line in nmap_quick_scan_results.splitlines():
                            if 'Nmap scan report for ' in nmap_line:
                            
                                if spotted_mac == False and current_nmap_ip != None:
                                    print("\nWARNING, IT SEEMS LIKE NMAP DID NOT RETURN A MAC ADDRESS FOR: ", current_nmap_ip)
                            
                                spotted_mac = False
                                nmap_line = str(nmap_line).replace('Nmap scan report for ','').rstrip()
                                print("nmap_line is ip? -->" + str(nmap_line) + "<--")
                                if valid_ip(nmap_line):
                                    print("OK, valid ip: ", nmap_line)
                                    current_nmap_ip = str(nmap_line)
                                    if not current_nmap_ip in available_ips[interface_name]:
                                        available_ips[interface_name][current_nmap_ip] = {}
                                    if not 'ip' in available_ips[interface_name][current_nmap_ip]:
                                        available_ips[interface_name][current_nmap_ip]['ip'] = current_nmap_ip
                                        available_ips[interface_name][current_nmap_ip]['ip_source'] = 'nmap'
                                    if not 'ip4_services' in available_ips[interface_name][current_nmap_ip]:
                                        available_ips[interface_name][current_nmap_ip]['ip4_services'] = {}
                                    if not 'ip6_services' in available_ips[interface_name][current_nmap_ip]:
                                        available_ips[interface_name][current_nmap_ip]['ip6_services'] = {}
                                    #available_ips[interface_name][nmap_line] = {'ip':nmap_line,'ip_source':'nmap','ip4_services':{},'ip6_services':{}}
                                    if current_nmap_ip == str(ip_data['local']):
                                        available_ips[interface_name][current_nmap_ip]['candle'] = True
                                elif '::' in nmap_line:
                                    if self.DEBUG:
                                        print("\nUNEXPECTEDLY, quick nmap scan seems to have found an IPv6 address: ", nmap_line)
                                    available_ips[interface_name][nmap_line] = {}
                                    current_nmap_ip = str(nmap_line)
                                else:
                                    if self.DEBUG:
                                        print("Warning, no valid IP from nmap quick scan?  nmap_line: ", nmap_line)
                            elif valid_ip(current_nmap_ip):
                                if '/tcp ' in nmap_line or '/udp ' in nmap_line:
                                    if self.DEBUG:
                                        print("extracting port for IP: ", current_nmap_ip, nmap_line)
                                    port_parts = nmap_line.split()
                                    #print("len(port_parts): ", len(port_parts))
                                    if len(port_parts) == 3:
                                        port_number = str(port_parts[0])
                                        port_number = port_number.replace('/tcp','')
                                        port_number = port_number.replace('/udp','')
                                        if port_number.isdigit():
                                            available_ips[interface_name][current_nmap_ip]['ip4_services'][port_number] = {'nr':port_number}
                                            if '/tcp' in nmap_line:
                                                available_ips[interface_name][current_nmap_ip]['ip4_services'][port_number]['protocol'] = 'tcp'
                                            else:
                                                available_ips[interface_name][current_nmap_ip]['ip4_services'][port_number]['protocol'] = 'udp'
                                                
                                            available_ips[interface_name][current_nmap_ip]['ip4_services'][port_number]['service'] = port_parts[2];
                                            available_ips[interface_name][current_nmap_ip]['ip4_services'][port_number]['state'] = port_parts[1];
                                        else:
                                            if self.DEBUG:
                                                print("\nERROR, port number was not a number?: ", port_number)
                            
                                elif nmap_line.startswith('MAC Address: '):
                                    spotted_mac = True
                                    if self.DEBUG:
                                        print("networkscanner debug: extracting mac for IP: ", current_nmap_ip, nmap_line)
                                    nmap_mac = extract_mac(nmap_line)
                                    if nmap_mac and valid_mac(nmap_mac) and current_nmap_ip in available_ips[interface_name] and not 'mac' in available_ips[interface_name][current_nmap_ip]:
                                        available_ips[interface_name][current_nmap_ip]['mac'] = nmap_mac
                                        available_ips[interface_name][current_nmap_ip]['mac_source'] = 'nmap'
                                
                                    if not '(Unknown)' in nmap_line and '(' in nmap_line and ')' in nmap_line and not 'mac_vendor' in available_ips[interface_name][current_nmap_ip]:
                                        mac_vendor = nmap_line.split('(',1)[1].split(')')[0]
                                        if self.DEBUG:
                                            print("networkscanner debug: + extracted mac_vendor too: ", mac_vendor)
                                        if len(str(mac_vendor)) > 4:
                                            available_ips[interface_name][current_nmap_ip]['mac_vendor'] = str(mac_vendor)
                                    
                                    current_nmap_ip = None
                            
                            
                            
                    elif '::' in str(ip_data['local']) and valid_ip6(ip_data['local']):
                        if self.DEBUG:
                            print("interface has an ipv6 address:" + str(ip_data['local']))
                        if valid_ip(interface_ip4):
                            if not 'ip6' in available_ips[interface_name][interface_ip4]:
                                available_ips[interface_name][interface_ip4]['ip6'] = {}
                            available_ips[interface_name][interface_ip4]['ip6'][str(ip_data['local'])] = {'ip6':str(ip_data['local']),'ip6_source':'nmcli'}
                            
                        #nmap_quick_scan_results = str(run_command("nmap --scan-delay=25ms -6 -sn " + str(ip_data['local']) + "/64 | grep 'Nmap scan report for'"))
                    else:
                        if self.DEBUG:
                            print("\nERROR, interface IP address fell through, doesn't seem a valid ip4 or ip6 IP:" + str(ip_data['local']))
                    
                    
                                
                    
                    self.quick_scan_phase += 3
                else:
                    if self.DEBUG:
                        print("check_available_ips: warning, 'local' was missing from ip_data: ", ip_data)
                self.available_ips = available_ips
        
        interface_name = None
        
        
        for ifname in list(available_ips.keys()):
            for known_ip_address in list(available_ips[ifname].keys()):
                if not 'mac' in available_ips[ifname][known_ip_address]:
                    if self.DEBUG:
                        print("\nEARLY WARNING, missing mac: ", known_ip_address, available_ips[ifname][known_ip_address])
        
        ifname = None
        
        #ip_neighbor_output2 = str(subprocess.check_output(['ip', 'neighbor']).decode('utf-8'))
        #if self.DEBUG:
        #    print("check_available_ips: ip_neighbor_output: " + str(ip_neighbor_output))
        #    print("")
        #    print("check_available_ips: ip_neighbor_output2: " + str(ip_neighbor_output2))
            
            
        for line in ip_neighbor_output.splitlines():
            if line.strip().endswith("REACHABLE") or line.endswith("STALE") or line.endswith("DELAY"):
                if self.DEBUG:
                    print("OK, stale, delay or reachable in line:  "+ str(line))
                    #print("OK, REACHABLE in line:  "+ str(line))
                try:
                    mac_address = extract_mac(line)
                    if self.DEBUG:
                        print("ip_neighbor mac_address: " + str(mac_address))
                    ip_address = line.split(" ", 1)[0]
                    if self.DEBUG:
                        print("ip_neighbor ip_address: " + str(ip_address))
                    #possible_name = "unknown"
        
                    if valid_ip(ip_address) and ip_address in self.own_ip:
                        if self.DEBUG:
                            print("ip neighbor was own IP address, skipping")
                        continue
        
                    if self.DEBUG:
                        print("neighbor mac: " + str(mac_address) + ", and ip: " + str(ip_address))
                    if valid_ip(ip_address):
                        for ifname in available_ips.keys():
                            if ' dev ' + str(ifname) + ' ' in line:
                                if not ip_address in available_ips[ifname]:
                                    if self.DEBUG:
                                        print("ip neighbour had an ip address that nmap didn't: ", ip_address)
                                    available_ips[ifname][ip_address] = {'ip':str(ip_address), 'ip_source':'neighbor'}
                                if valid_mac(mac_address) and not 'mac' in available_ips[ifname][ip_address]: # currently there is no change of a mac already existing
                                    if self.DEBUG:
                                        print("adding neighbour mac")
                                    available_ips[ifname][ip_address]['mac'] = str(mac_address).upper()
                                    available_ips[ifname][ip_address]['mac_source'] = 'neighbor'
                except Exception as ex:
                    if self.DEBUG:
                        print("check_available_ips: caught error looping over ip neighbour line: " + str(ex))
            else:
                if self.DEBUG:
                    print("check_available_ips: ignoring ip neigbour line: ", line)
            
        self.quick_scan_phase += 1
        self.available_ips = available_ips
        
        line = None
        
        
        #
        #  + AVAHI
        #
        
        #avahi_output = str(run_command('avahi-browse --all --resolve --terminate --parsable'))
        #self.avahi_lines = 
        outdated_avahi_data = []
        self.avahi_lines = self.get_avahi_lines()
        if self.DEBUG:
            print("check_available_ips: self.avahi_lines: " + str(self.avahi_lines))
            print("")
        #for line in avahi_output.splitlines():
        for line in self.avahi_lines:
            if not isinstance(line,str):
                if self.DEBUG:
                    print("\nERROR: a line from self.avahi_lines was not a string: ", line)
                continue
            avahi_ip_address = extract_ip(str(line))
            #print("avahi_ip_address: ", avahi_ip_address)
            if valid_ip(avahi_ip_address):
                #print("extracted IP from avahi line: ", avahi_ip_address)
                for ifname in available_ips.keys():
                    if line.startswith('=;' + str(ifname) + ';') and not 'shairport' in line.lower():
       
                        already_used_that_mac = False
                        mac_address = str(extract_mac(line))
                        if self.DEBUG and mac_address != 'None':
                            print("avahi line mac_address: " + str(mac_address))
                        if valid_mac(mac_address):
                            # quickly check if the mac avahi found hasn't already been used
                            
                            for check_ifname in list(available_ips.keys()):
                                for check_known_ip_address in available_ips[check_ifname]:
                                    if 'mac' in available_ips[check_ifname][check_known_ip_address] and str(available_ips[check_ifname][check_known_ip_address]['mac']) == mac_address:
                                        already_used_that_mac = True
                                        if check_known_ip_address == avahi_ip_address:
                                            if self.DEBUG:
                                                print("OK, The mac that avahi spotted has already been used in a device, but the avahi info is correct")
                                        else:
                                            if self.DEBUG:
                                                print("\nWARNING: the mac that avahi spotted has already been used in a device. This avahi-data should be considered outdated.")
                                            outdated_avahi_data.append(avahi_ip_address)
                                            outdated_avahi_data.append(mac_address)
                                            
                            if already_used_that_mac == False:
                                
                                if not avahi_ip_address in list(available_ips[ifname].keys()):
                                    if self.DEBUG:
                                        print("\nWARNING, avahi had an IP address (and unused mac) that nmap didn't: ", avahi_ip_address, mac_address, " from line: ", line)
                                    available_ips[ifname][avahi_ip_address] = {'ip': str(avahi_ip_address),'ip_source':'avahi','mac':mac_address,'mac_source':'avahi'}
                                    
                                
                                if self.DEBUG:
                                    print("adding avahi mac?: ", mac_address, " based on line: ", line, " and avahi's IP: ", avahi_ip_address)
                                if not 'mac' in list(available_ips[ifname][avahi_ip_address].keys()):
                                    available_ips[ifname][avahi_ip_address]['mac'] = str(mac_address).upper()
                                    available_ips[ifname][avahi_ip_address]['mac_source'] = 'avahi'
                                elif valid_mac(mac_address) and mac_address != available_ips[ifname][avahi_ip_address]['mac'] and not 'mac2' in available_ips[ifname][avahi_ip_address]:
                                    available_ips[ifname][avahi_ip_address]['mac2'] = str(mac_address).upper()
                                    available_ips[ifname][avahi_ip_address]['mac2_source'] = 'avahi'
                            
                                if "IPv4;CandleMQTT-" in line:
                                    available_ips[ifname][avahi_ip_address]['candle'] = True
                            
                            

        line = None
        
        self.quick_scan_phase += 3
        self.available_ips = available_ips
        
        found_hostname_ips = []
        unmatched_hostnames = []
        
        
        
        # use avahi to get hostnames
        
        for line in self.avahi_lines:
            
            found_a_hostname = False
            avahi_ip_address = extract_ip(line)
            #print("avahi_ip_address for hostname: ", avahi_ip_address)
            if valid_ip(avahi_ip_address):
                if avahi_ip_address in found_hostname_ips:
                    
                    curiosity_avahi_hostname = extract_hostname_from_avahi_line(line)
                    if self.DEBUG:
                        print("already have a hostname for that IP, no need to get the one in the avahi line: ", avahi_ip_address, curiosity_avahi_hostname)
                    
                    # out of curiosity, quickly check if the avahi hostname matches to the one already found
                    if curiosity_avahi_hostname:
                        for curiosity_ifname in list(self.available_ips.keys()):
                            if avahi_ip_address in self.available_ips[curiosity_ifname]:
                                if not 'hostname' in self.available_ips[curiosity_ifname][avahi_ip_address]:
                                    if self.DEBUG:
                                        print("\nERROR, according to found_hostname_ips that ip should have a hostname, but it doesn't: ", avahi_ip_address, found_hostname_ips)
                                    break
                                elif str(self.available_ips[curiosity_ifname][avahi_ip_address]['hostname']) != str(curiosity_avahi_hostname):
                                    if self.DEBUG:
                                        print("\nWARNING, avahi hostname is different from the one found earlier. Avahi seems outdated? hostnames and line: ", str(self.available_ips[curiosity_ifname][avahi_ip_address]['hostname']), str(curiosity_avahi_hostname), line)
                                    outdated_avahi_data.append(curiosity_avahi_hostname)
                                    outdated_avahi_data.append(avahi_ip_address)
                            
                    
                    continue
                
                for ifname in available_ips.keys():
                    if line.startswith('=;' + str(ifname) + ';'):
                        if avahi_ip_address in available_ips[ifname] and not 'hostname' in available_ips[ifname][avahi_ip_address]:
                            if self.DEBUG:
                                print("opportunity to add a hostname from avahi for: ", avahi_ip_address)
                            
                            line = line.lower()
                            line_parts = line.split(';')
                            #for line_part in line_parts:
                            for index, line_part in enumerate(line_parts):
                                # TODO: hostname always a fixed place in the line parts?
                                if self.DEBUG:
                                    print(index, ". ", line_part)
                                if len(line_part) > 7 and line_part.lower().endswith('.local'):
                                    available_ips[ifname][avahi_ip_address]['hostname'] = str(line_part).lower()
                                    if self.DEBUG:
                                        print("added hostname from avahi: ", available_ips[ifname][avahi_ip_address]['hostname'])
                                    available_ips[ifname][avahi_ip_address]['hostname_source'] = 'avahi'
                                    found_hostname_ips.append(avahi_ip_address)
                                    break
                    
        line = None
        
         
        
        if 'incomplete' in arpa_output:
            more_arpa_output = str(run_command('arp -a'))
            if not 'incomplete' in more_arpa_output:
                arpa_output = more_arpa_output
            if self.DEBUG:
                print("there was still 'incomplete' in the arp output. Perhaps there is good output now: ", arpa_output)
        
        self.quick_scan_phase += 1
        #if 'incomplete' in arpa_output:
        #    time.sleep(10)
        #    arpa_output = str(run_command('arp -a'))
        #    if self.DEBUG:
        #        print("there was still 'incomplete' in the arp output. Final more attempt to get good output: ", arpa_output)
            
        self.quick_scan_phase += 1
        if 'incomplete' in ip_neighbor_output.lower():
            more_ip_neighbor_output = str(subprocess.check_output(['ip', 'neighbor']).decode('utf-8'))
            if not 'incomplete' in more_ip_neighbor_output.lower():
                ip_neighbor_output = more_ip_neighbor_output.lower()
            else:
                if self.DEBUG:
                    print("there was still 'incomplete' in the neighbor output. one more attempt to get good output: ", ip_neighbor_output)
                time.sleep(10)
                more_ip_neighbor_output = str(subprocess.check_output(['ip', 'neighbor']).decode('utf-8'))
                if not 'incomplete' in more_ip_neighbor_output.lower():
                    ip_neighbor_output = more_ip_neighbor_output.lower()
                if self.DEBUG:
                    print("there was still 'incomplete' in the neighbor output. final ip_neighbor_output: ", ip_neighbor_output)    
        
        self.quick_scan_phase += 2
                
        for ifname in list(available_ips.keys()):
            for known_ip_address in list(available_ips[ifname].keys()):
                if not 'mac' in available_ips[ifname][known_ip_address]:
                    if self.DEBUG:
                        print("no known mac address yet for: ", known_ip_address)
                    if known_ip_address in arpa_output:
                        for line in arpa_output.splitlines():
                            if known_ip_address in line:
                                if self.DEBUG:
                                    print("ARP -A knows that IP.  line: ", line)
                                mac_address = extract_mac(line)
                                if self.DEBUG:
                                    print("mac_address from arp -a: ", mac_address)
                                if valid_mac(str(mac_address)):
                                    if self.DEBUG:
                                        print("adding missing mac address from arp: " + str(mac_address))
                                    available_ips[ifname][known_ip_address]['mac'] = str(mac_address).upper()
                                    available_ips[ifname][known_ip_address]['mac_source'] = 'arp'
                                break
                                
                if not 'mac' in available_ips[ifname][known_ip_address]:
                    if known_ip_address in ip_neighbor_output:
                        for line in ip_neighbor_output.splitlines():
                            if known_ip_address in line:
                                if self.DEBUG:
                                    print("ip neighbor knows that IP.  line: ", line)
                                mac_address = extract_mac(line)
                                if self.DEBUG:
                                    print("mac_address from ip neighbor: ", mac_address)
                                if valid_mac(str(mac_address)):
                                    if self.DEBUG:
                                        print("adding missing mac address from arp: " + str(mac_address))
                                    available_ips[ifname][known_ip_address]['mac'] = str(mac_address).upper()
                                    available_ips[ifname][known_ip_address]['mac_source'] = 'neighbor'
                                break
            
                if 'mac' in available_ips[ifname][known_ip_address] and valid_mac(available_ips[ifname][known_ip_address]['mac']):
                    
                    available_ips[ifname][known_ip_address]['mac_id'] = mac_to_id(available_ips[ifname][known_ip_address]['mac'])
                    
                    mac_vendor = self.get_vendor(available_ips[ifname][known_ip_address]['mac'])
                    if isinstance(mac_vendor, str):
                        if self.DEBUG:
                            print("mac_vendor: " + str(mac_vendor))
                        available_ips[ifname][known_ip_address]['mac_vendor'] = str(mac_vendor)
                    else:
                        if self.DEBUG:
                            print("getting mac_vendor did not return a string: " + str(mac_vendor))
            
                if not 'mac_vendor' in available_ips[ifname][known_ip_address] and not 'hostname' in available_ips[ifname][known_ip_address]:
                    nmap_quick_scan_output = str(run_command("sudo nmap --host-timeout 15 --scan-delay=25ms -sn " + str(known_ip_address) + " | grep 'MAC Address:'")) # | grep -v 'Unknown'
                    if 'MAC Address:' in str(nmap_quick_scan_output):
                        mac_double_check = extract_mac(str(nmap_quick_scan_output))
                        if valid_mac(mac_double_check):
                            if 'mac' in available_ips[ifname][known_ip_address] and valid_mac(available_ips[ifname][known_ip_address]['mac']):
                                if self.DEBUG:
                                    print("mac_double_check: -->" + str(mac_double_check) + '<-- new =?= known -->' + str(available_ips[ifname][known_ip_address]['mac']) + "<--")
                                if str(mac_double_check) != str(available_ips[ifname][known_ip_address]['mac']):
                                    if self.DEBUG:
                                        print(" - - - -  WARNING, MAC ADDRESSS MISMATCH! - - - - - ")
                                    available_ips[ifname][known_ip_address]['mac'] = str(mac_double_check).upper()
                                    available_ips[ifname][known_ip_address]['mac_id'] = mac_to_id(mac_double_check)
                        if not '(Unknown)' in nmap_quick_scan_output and '(' in nmap_quick_scan_output and ')' in nmap_quick_scan_output:
                            available_ips[ifname][known_ip_address]['mac_vendor'] = nmap_quick_scan_output.split('(',1)[1].split(')')[0]
                            if self.DEBUG:
                                print("got mac_vendor from nmap: " + str(available_ips[ifname][known_ip_address]['mac_vendor']))
                available_ips[ifname][known_ip_address]['tags'] = []
                
                ssh_quick_scan_output = run_command("nmap --scan-delay=25ms -p 22 " + str(known_ip_address))
                if '22/tcp open' in str(ssh_quick_scan_output):
                    available_ips[ifname][known_ip_address]['tags'].append('SSH server')
                
                dns_quick_scan_output = run_command("nmap --scan-delay=25ms -p 53 " + str(known_ip_address))
                if '53/tcp open' in str(dns_quick_scan_output):
                    available_ips[ifname][known_ip_address]['tags'].append('DNS server')
                    
                webserver_quick_scan_output = run_command("nmap --scan-delay=25ms -p 80,443 " + str(known_ip_address))
                if '80/tcp open' in str(webserver_quick_scan_output):
                    available_ips[ifname][known_ip_address]['tags'].append('Web server')
                elif '443/tcp open' in str(webserver_quick_scan_output):
                    available_ips[ifname][known_ip_address]['tags'].append('Web server')
                    
                if not 'uuid' in available_ips[ifname][known_ip_address]:
                    available_ips[ifname][known_ip_address]['uuid'] = str(uuid.uuid4())
                    if self.DEBUG:
                        print("added uuid: ", available_ips[ifname][known_ip_address]['uuid'])
        
            self.quick_scan_phase += 2
        
        ifname = None
        
        
        #
        #  TRY TO MATCH IPv6 ADDRESSES WITH IPv4 devices
        #
        
        if self.DEBUG:
            print("\nnetworkscanner debug:\n----------------\nip6_neighbor_output:")
            print(ip6_neighbor_output)
            print("----------------\n\n")
        for line in ip6_neighbor_output.splitlines():
            try:
                line_parts = line.split()
                if len(line_parts) > 5 and valid_ip6(line_parts[0]):
                    ip6 = str(line_parts[0])
                    ip6_mac = str(line_parts[4]).upper()
                    if self.DEBUG:
                        print("ip6_neighbor_output line parts: ", json.dumps(line_parts,indent=6))
                    
                    if not valid_ip6(ip6) or not valid_mac(ip6_mac):
                        if self.DEBUG:
                            print("ERROR, ip6 or ip6_mac from ip6_neighbor_output was not a valid: ", ip6, ip6_mac)
                        continue
                        
                    #ip6_interface = str(line_parts[2])
                    ip6_ifname = str(line_parts[2])
                    if not ip6_ifname in list(self.available_interfaces.keys()):
                        if self.DEBUG:
                            print("Error, unexpected interface in ip6_neighbor output: ", ip6_ifname)
                    else:
                        
                        if self.DEBUG:
                            print("doing quick nmap check of ip6 address: -->" + str(ip6) + "<--")
                        quick_ip6_nmap_output = str(run_command('sudo nmap -6 --host-timeout 15 --scan-delay=25ms -sS -F ' + str(ip6)))
                        if self.DEBUG:
                            print("quick_ip6_nmap_output: ", quick_ip6_nmap_output)
                        
                        
                        
                        matched_ip4 = None
                        for known_ip_address in list(available_ips[ip6_ifname].keys()):
                            
                            if not 'mac' in available_ips[ip6_ifname][known_ip_address]:
                                if self.DEBUG:
                                    print("\nWARNING, missing mac: ", available_ips[ip6_ifname][known_ip_address])
                                    print("ip6 mac?? " + str(ip6_mac) + ' =?= ' + str(available_ips[ip6_ifname][known_ip_address]['mac']))
                                    
                            elif 'mac' in available_ips[ip6_ifname][known_ip_address] and str(available_ips[ip6_ifname][known_ip_address]['mac']) == str(ip6_mac):
                                if 'ip' in available_ips[ip6_ifname][known_ip_address]:
                                    if self.DEBUG:
                                        print("matched ip6 address to an ip4 address because they have the same mac address")
                                    matched_ip4 = str(available_ips[ip6_ifname][known_ip_address]['ip'])
                                else:
                                    if self.DEBUG:
                                        print("WARNING, mac address match, but device did not have an ip4 address")
                                break
                            elif 'mac2' in available_ips[ip6_ifname][known_ip_address] and str(available_ips[ip6_ifname][known_ip_address]['mac2']) == str(ip6_mac):
                                if 'ip' in available_ips[ip6_ifname][known_ip_address]:
                                    if self.DEBUG:
                                        print("WARNING, matched ip6 address to an ip4 address because based on its SECOND mac address")
                                    matched_ip4 = str(available_ips[ip6_ifname][known_ip_address]['ip'])
                                else:
                                    if self.DEBUG:
                                        print("WARNING, mac2 address match, but device did not have an ip4 address")
                                matched_ip4 = known_ip_address
                                break
                        
                        
                        if self.DEBUG:
                            print("ip6 matched_ip4: ", matched_ip4)
                        if matched_ip4 == None:
                            if self.DEBUG:
                                print("\nWARNING, could not find matching ip4 device through MAC comparison. Creating a pure IPv6 device!")
                            
                            available_ips[ip6_ifname][ip6] = {'ip6':{ip6:{'ip6':ip6,'ip6_source':'neighbor'}},'mac':ip6_mac,'mac_source':'neighbor','ip4_services':{},'ip6_services':{}}
                            matched_ip4 = ip6
                        
                        if not matched_ip4 in list(available_ips[ip6_ifname].keys()):
                            if self.DEBUG:
                                print("\nERROR, could not find matched_ip4 in available_ips[ip6_ifname]: ", matched_ip4, list(available_ips[ip6_ifname].keys()))
                        elif ' router ' in line.lower():
                            if self.DEBUG:
                                print("this device seems to be an IP6 router: ", line)
                            if not 'tags' in available_ips[ip6_ifname][matched_ip4]:
                                available_ips[ip6_ifname][matched_ip4]['tags'] = []
                            available_ips[ip6_ifname][matched_ip4]['tags'].append('IPv6 Router')
                        
                        current_nmap_ip = None
                        
                        
                        if 'Host seems down' in quick_ip6_nmap_output:
                            if self.DEBUG:
                                print("\nWARNING, that ip6 address seemed to be down: ", ip6)
                            continue
                        
                        
                        for nmap_line in quick_ip6_nmap_output.splitlines():
                            if self.DEBUG:
                                print("  ip6 nmap_line: ", nmap_line)
                            if 'Nmap scan report for ' in nmap_line:
                                nmap_line = str(nmap_line).replace('Nmap scan report for ','').rstrip()
                                if self.DEBUG:
                                    print("nmap_line is ip6? -->" + str(nmap_line) + "<--")
                                
                                if valid_ip6(nmap_line):
                                    if not str(nmap_line) == str(ip6):
                                        if self.DEBUG:
                                            print("\nERROR, mismatch for ip6 addresses: -->" + str(ip6) +  "<-- =?= -->" + str(nmap_line) + "<--")
                                        break
                                    
                                    current_nmap_ip = str(nmap_line)
                                    if self.DEBUG:
                                        print("current_nmap_ip: ", current_nmap_ip)
                                    if not matched_ip4 in list(available_ips[ip6_ifname].keys()):
                                        if self.DEBUG:
                                            print("\nERROR, current_nmap_ip not on current interface: ", ip6_ifname, matched_ip4, "BASED ON LINE: ", line);
                                        
                                    else:
                                        if not 'ip6' in list(available_ips[ip6_ifname][matched_ip4].keys()):
                                            available_ips[ip6_ifname][matched_ip4]['ip6'] = {}
                                        if not str(ip6) in list(available_ips[ip6_ifname][matched_ip4]['ip6'].keys()):
                                            available_ips[ip6_ifname][matched_ip4]['ip6'][str(ip6)] = {'ip6':str(ip6),'ip6_source':'nmap'}
                                    
                            elif valid_ip6(current_nmap_ip) and '/tcp ' in nmap_line or '/udp ' in nmap_line:
                                port_parts = nmap_line.split()
                                if self.DEBUG:
                                    print("ip6 port_parts: ", port_parts)
                                if len(port_parts) == 3:
                                    port_number = str(port_parts[0])
                                    port_number = port_number.replace('/tcp','')
                                    port_number = port_number.replace('/udp','')
                                    if self.DEBUG:
                                        print("ip6 port_number, ip6_ifname, matched_ip4: ", port_number, ip6_ifname, matched_ip4)
                                    if port_number.isdigit():
                                        if not matched_ip4 in list(available_ips[ip6_ifname].keys()):
                                            if self.DEBUG:
                                                print("\nERROR, matched_ip not on this interface? ", matched_ip4, list(available_ips[ip6_ifname].keys()))
                                        else:
                                            if not 'ip6_services' in list(available_ips[ip6_ifname][matched_ip4].keys()):
                                                available_ips[ip6_ifname][matched_ip4]['ip6_services'] = {}
                                            available_ips[ip6_ifname][matched_ip4]['ip6_services'][port_number] = {'port':port_number}
                                            if '/tcp' in nmap_line:
                                                available_ips[ip6_ifname][matched_ip4]['ip6_services'][port_number]['protocol'] = 'tcp'
                                            else:
                                                available_ips[ip6_ifname][matched_ip4]['ip6_services'][port_number]['protocol'] = 'udp'
                                                
                                            available_ips[ip6_ifname][matched_ip4]['ip6_services'][port_number]['service'] = port_parts[2];
                                            available_ips[ip6_ifname][matched_ip4]['ip6_services'][port_number]['state'] = port_parts[1];
                                    else:
                                        if self.DEBUG:
                                            print("\nERROR, port number was not a number?: ", port_number)
                                else:
                                    if self.DEBUG:
                                        print("\nERROR, unexpected number of port parts (should be 3): ", len(port_parts))
                                        
                                        
            except Exception as ex:
                if self.DEBUG:
                    print("\nE R R O R ! !\ncaught general error matching IP6 to IP4: " + str(ex))
                
        line = None
        
        
        
        self.available_ips = available_ips
        if self.DEBUG:
            print("\n\n\n\ncheck_available_ips: DONE\n\n")
            print("outdated_avahi_data: ", outdated_avahi_data)
            print("\nself.available_ips is now: \n\n", json.dumps(self.available_ips, indent=4), "\n\n\n\n")
        












    #
    #  REMATCH
    #
    # After a scan the device's ip address, hostname or even MAC address may have changed. As long as only one has changed, the other two can be used to 'find' the device again, and update the list of devices the user wants to track
    
    def rematch(self):
        if self.DEBUG:
            print("\n\n\nIN REMATCH")
            
            #print("\n- self.saved_devices_from_controller: \n", json.dumps(self.saved_devices_from_controller,indent=4))
            print("\n- self.previously_found: \n", json.dumps(self.previously_found,indent=4))
            print("\n")
            
        # Keep track of which IP addresses, mac addresses and hostnames have been 'used' by previously re-matched devices. We should not try to match a device with such an attribute.
        used = {'ips':[],'macs':[],'hostnames':[],'ids':[]}
        
        
        # If the mac address is still the same, then re-matching the device is easy, since the mac is the basis for the thing_id.
        saved_devices_from_controller_keys = list(self.saved_devices_from_controller.keys())        
        if self.DEBUG:
            print("REMATCH: saved_devices_from_controller_keys: ", saved_devices_from_controller_keys)
        
        previously_found_keys = list(self.previously_found.keys())    
        if self.DEBUG:
            print("REMATCH: previously_found_keys: ", previously_found_keys)
        
        all_known_ids = []
        
        for ifname in list(self.available_ips.keys()):
            for known_ip_address in list(self.available_ips[ifname].keys()):
                if 'mac_id' in self.available_ips[ifname][known_ip_address] and len(str(self.available_ips[ifname][known_ip_address]['mac_id'])) > 4:
                    _id = str(self.available_ips[ifname][known_ip_address]['mac_id'])

                    all_known_ids.append(_id)
                    if _id in saved_devices_from_controller_keys or _id in previously_found_keys:
                        if self.DEBUG:
                            print("OK, found the same mac-based ID again in saved_devices_from_controller_keys and/or previously_found_keys: ", _id)
                        
                        
                        if _id in self.previously_found and 'ip' in self.previously_found[_id]:
                            if known_ip_address != self.previously_found[_id]['ip']:
                                if self.DEBUG:
                                    print("\nINTERESTING, it seems the IP address has changed for _id: ", _id, ". Updating self.previously_found.")
                                self.available_ips[ifname][known_ip_address]['message'] = 'IP address has changed from ' + str(self.previously_found[_id]['ip']) + ' to ' + str(known_ip_address) + '\n'
                                if str(self.previously_found[_id]['ip']) in used['ips']:
                                    if self.DEBUG:
                                        print("\nNOTICE. The IP that the device used to have is also in used[ips]: ", str(self.previously_found[_id]['ip']))
                                self.previously_found[_id]['ip'] = known_ip_address
                                self.should_save = True
                                
                        used['ips'].append(known_ip_address)
                        
                        if 'mac' in self.available_ips[ifname][known_ip_address] and valid_mac(self.available_ips[ifname][known_ip_address]['mac']):
                            used['macs'].append(str(self.available_ips[ifname][known_ip_address]['mac']))
                            
                            # it should be impossible to find a device with a changed mac again by it's mac_id
                            if _id in self.previously_found:
                                if str(self.previously_found[_id]['mac']) != str(self.available_ips[ifname][known_ip_address]['mac']):
                                    if self.DEBUG:
                                        print("\nVERY UNEXPECTEDLY, THE MACS WERE DIFFERENT: ", str(self.previously_found[_id]['mac']), str(self.available_ips[ifname][known_ip_address]['mac']))
                                self.previously_found[_id]['mac'] = str(self.available_ips[ifname][known_ip_address]['mac'])
                            
                        if 'hostname' in self.available_ips[ifname][known_ip_address] and len(str(self.available_ips[ifname][known_ip_address]['hostname'])) > 4:
                            used['hostnames'].append(str(self.available_ips[ifname][known_ip_address]['hostname']))
                            
                            if _id in self.previously_found:
                                if 'hostname' in self.previously_found[_id] and str(self.previously_found[_id]['hostname']) != str(self.available_ips[ifname][known_ip_address]['hostname']):
                                    if self.DEBUG:
                                        print("\nINTERESTING, it seems the HOSTNAME has changed for _id: ", _id, ". Updating self.previously_found:\n", self.previously_found[_id], "\n..based on self.available_ips data: ",self.available_ips[ifname][known_ip_address])
                                    if 'message' in self.available_ips[ifname][known_ip_address]:
                                        self.available_ips[ifname][known_ip_address]['message'] += 'Hostname has changed from ' + str(self.previously_found[_id]['hostname']) + ' to ' + str(self.available_ips[ifname][known_ip_address]['hostname']) + '\n'
                                    else:
                                        self.available_ips[ifname][known_ip_address]['message'] = 'Hostname has changed from ' + str(self.previously_found[_id]['hostname']) + ' to ' + str(self.available_ips[ifname][known_ip_address]['hostname']) + '\n'
                                    if str(self.previously_found[_id]['hostname']) in used['hostnames']:
                                        print("\nWARNING. The HOSTNAME that the device USED TO HAVE is also in used[hostnames]: ", str(self.previously_found[_id]['ip']))
                                    self.should_save = True
                                elif 'hostname' in self.previously_found[_id]:
                                    if self.DEBUG:
                                        print("OK, hostname is still the same as the one in self.previously_found")
                                else:
                                    if self.DEBUG:
                                        print("\nnINTERESTING: adding a hostname to a previously_found entry that didn't have a hostname before")
                                    self.should_save = True
                                self.previously_found[_id]['hostname'] = str(self.available_ips[ifname][known_ip_address]['hostname']).lower()
                            
                        elif _id in self.previously_found and 'hostname' in self.previously_found[_id]:
                            if self.DEBUG:
                                print("\nSTRANGE! previously_found has a hostname for this device, but it was not found in the scan:  Forgetting: ", self.previously_found[_id]['hostname'])
                            #TODO: it might not be a great idea to forget the hostname. Ideally after a little while we re-scan to check if the hostname has appeared, and if it's still not there, then forget it.
                            if not 'possibly_intermittent_hostname' in self.previously_found[_id]:
                                del self.previously_found[_id]['hostname']
                                self.previously_found[_id]['possibly_intermittent_hostname'] = 1
                                self.should_save = True
                            elif self.previously_found[_id]['possibly_intermittent_hostname'] < 10:
                                self.previously_found[_id]['possibly_intermittent_hostname'] += 1
                                self.should_save = True
                            self.thing_ids_with_possibly_intermittent_hostnames.append(_id)
                        
                        if _id in previously_found_keys:
                            if self.DEBUG:
                                print("also spotted this device ID in previously_found_keys: ", _id)
                            self.previously_found[_id]['last_rematch_timestamp'] = self.last_scan_timestamp
                        
                        if _id in saved_devices_from_controller_keys:
                            saved_devices_from_controller_keys.remove(_id)
                        if _id in previously_found_keys:
                            previously_found_keys.remove(_id)
                    
                        self.available_ips[ifname][known_ip_address]['thing_id'] = _id
                        self.available_ips[ifname][known_ip_address]['last_rematch_timestamp'] = self.last_scan_timestamp

                        
        
        ifname = None
        self.quick_scan_phase += 1
        
        
        if self.DEBUG:
            print("rematch: used after first easy check: \n", json.dumps(used,indent=4))
        
            # Now comes the hard part, where a device may have changed its mac address.
            print("unaccounted for saved_devices_from_controller (likely with changed mac address):", saved_devices_from_controller_keys)
            print("unaccounted for previously_found_keys (likely with changed mac address):", saved_devices_from_controller_keys)
        
        
        
        for previously_found_id in previously_found_keys:
            if previously_found_id in self.previously_found and 'hostname' in self.previously_found[previously_found_id]: # SIC just making sure the previously_found_id is actually still in there
                
                for ifname in list(self.available_ips.keys()):
                    for known_ip_address in list(self.available_ips[ifname].keys()):
                        if 'thing_id' in self.available_ips[ifname][known_ip_address]:
                            if self.DEBUG:
                                print("rematch: previously_found loop: skipping a device that already as a thing_id, indicating it has already been re-matched: ", known_ip_address)
                                print("- if curious:")
                                print("- self.available_ips[ifname][known_ip_address]:\n", self.available_ips[ifname][known_ip_address])
                                print("- self.previously_found[previously_found_id]:\n", self.previously_found[previously_found_id])
                                
                            continue
                            
                        if 'hostname' in self.available_ips[ifname][known_ip_address] and len(str(self.available_ips[ifname][known_ip_address])) > 4 and str(self.available_ips[ifname][known_ip_address]['hostname']) == str(self.previously_found[previously_found_id]['hostname']):
                            if self.DEBUG:
                                print("rematch: GREAT! hostname from a previously_found entry matches with hostname from available_ips scan: ", str(self.previously_found[previously_found_id]['hostname']))
                            if str(self.previously_found[previously_found_id]['hostname']) in used['hostnames']:
                                if self.DEBUG:
                                    print("rematch: OH NO! hostname from a previously_found was already used")
                                # TODO: delete the hostname? Or do some other disentangling?
                                del self.previously_found[previously_found_id]['hostname']
                                    
                            else:
                                if self.DEBUG:
                                    print("rematch: OK, updating ip and mac")
                                self.available_ips[ifname][known_ip_address]['thing_id'] = previously_found_id
                                if str(self.previously_found[previously_found_id]['ip']) != str(self.available_ips[ifname][known_ip_address]['ip']):
                                    self.available_ips[ifname][known_ip_address]['message'] = 'IP address changed from ' + str(self.previously_found[previously_found_id]['ip']) + ' to ' + str(self.available_ips[ifname][known_ip_address]['ip'])
                                self.previously_found[previously_found_id]['ip'] = str(self.available_ips[ifname][known_ip_address]['ip'])
                                
                                used['ips'].append(str(self.available_ips[ifname][known_ip_address]['ip']))
                                
                                if not 'mac' in self.available_ips[ifname][known_ip_address]:
                                    if self.DEBUG:
                                        print("\n\n\nERROR, rematch: no mac in available_ips device?: ", previously_found_id, self.available_ips[ifname][known_ip_address],"\n\n\n")
                                    arp_mac_fix_attempt = str(run_command('arp -a | grep ' + str(self.available_ips[ifname][known_ip_address]['ip'])))
                                    if str(self.available_ips[ifname][known_ip_address]['ip']) in arp_mac_fix_attempt:
                                        arp_mac_fix_attempt_mac = extract_mac(arp_mac_fix_attempt)
                                        if valid_mac(arp_mac_fix_attempt_mac):
                                            self.available_ips[ifname][known_ip_address]['mac'] = arp_mac_fix_attempt_mac
                                            if self.DEBUG:
                                                print("\n\n\nOK, REMATCH WAS ABLE TO FIX MISSING MAC IN DEVICE: ", json.dumps(self.available_ips[ifname][known_ip_address],indent=4))
                                        else:
                                            if self.DEBUG:
                                                print("\n\n\nWARNING, REMATCH WAS UNABLE TO FIX MISSING MAC IN DEVICE. DELETING IT: ", json.dumps(self.available_ips[ifname][known_ip_address],indent=4))
                                            del self.available_ips[ifname][known_ip_address]
                                    
                                else:
                                    if str(self.previously_found[previously_found_id]['mac']) != str(self.available_ips[ifname][known_ip_address]['mac']):
                                        self.available_ips[ifname][known_ip_address]['message'] = 'MAC address changed from ' + str(self.previously_found[previously_found_id]['mac']) + ' to ' + str(self.available_ips[ifname][known_ip_address]['mac'])
                                        if not 'previous_mac_addresses' in self.previously_found[previously_found_id]:
                                            self.previously_found[previously_found_id]['previous_mac_addresses'] = []
                                        self.previously_found[previously_found_id]['previous_mac_addresses'].append({'mac':str(self.previously_found[previously_found_id]['mac']),'change_detection_timestamp':int(time.time())})
                                        if len(self.previously_found[previously_found_id]['previous_mac_addresses']) > 10:
                                            self.previously_found[previously_found_id]['previous_mac_addresses'] = self.previously_found[previously_found_id]['previous_mac_addresses'][-10:]
                                    self.previously_found[previously_found_id]['mac'] = str(self.available_ips[ifname][known_ip_address]['mac'])
                                    used['macs'].append(str(self.available_ips[ifname][known_ip_address]['mac']))
                            
                            previously_found_keys.remove(previously_found_id)
        
        previously_found_id = None
        
        
        for _id in saved_devices_from_controller_keys:
            if self.DEBUG:
                print("\nrematch: self.saved_devices_from_controller: ", _id, self.saved_devices_from_controller[_id])
            
                print("\n\nrematch saved device: \n\n", json.dumps(self.saved_devices_from_controller[_id], indent=4), "\n\n")
            
            
            # Get the IP address, MAC and hopefully hostname from the thing info that the Candle controller provided when the addon was started
            hints={'ip':'', 'mac':'', 'hostname':'','id':_id,'details':''}
            for key in list(hints.keys()):
                
                #print("samson: ", self.saved_devices_from_controller[_id])
                
                if 'properties' in self.saved_devices_from_controller[_id]:
                    if self.DEBUG:
                        print("save_device has properties: ", key, " ..in?... ", list(self.saved_devices_from_controller[_id]['properties'].keys()), self.saved_devices_from_controller[_id]['properties'])
                    if key in self.saved_devices_from_controller[_id]['properties']:
                        if 'value' in self.saved_devices_from_controller[_id]['properties'][key]:
                            if key == 'details' and hints['ip'] == '':
                                if self.DEBUG:
                                    print("details -> ip")
                                hints['ip'] = self.saved_devices_from_controller[_id]['properties'][key]['value']
                            
                            hints[key] = self.saved_devices_from_controller[_id]['properties'][key]['value']
            
            if self.DEBUG:
                print("\n\nrematch: hints: ", hints)
            
            
            
            if hints['ip'] in used['ips']:
                if self.DEBUG:
                    print("\nWARNING, the IP seems to have been given to another device: ", hints['ip'], ", since it's in used['ips']: ", used['ips'])
                hints['ip'] = ''
                
            for ifname in list(self.available_ips.keys()):
                if self.DEBUG:
                    print("rematch: checking interface: " + str(ifname))
                
                ip_match = False
                mac_match = False
                hostname_match = False
                
                self.quick_scan_phase += 1
                
                #if hints['ip'] in self.available_ips and 'mac' in self.available_ips[ hints['ip'] ] and valid_mac(self.available_ips[ hints['ip'] ]['mac']) and mac_to_id(self.available_ips[ hints['ip'] ]['mac']) == _id:
                #    print("early mac to id match")
                #    if 'hostname' in self.available_ips[ hints['ip'] ] and len(self.available_ips[ hints['ip'] ]['hostname']) > 2:
                #        hints['hostname'] = self.available_ips[ hints['ip'] ]['hostname']
                
                
                # IP-first attempt
                ips = list(self.available_ips[ifname].keys())
                if self.DEBUG:
                    print("rematch: ips: ", ips)
                
                #for ip in ips:
                #    if 'mac' in self.available_ips[ifname][ip]:
                #        if self.DEBUG:
                #            print("rematch: early mac to check: ", self.available_ips[ifname][ip]['mac'], ", mac-to-id: \n", mac_to_id(self.available_ips[ifname][ip]['mac']), " =?= ", _id)
                    
                #    if 'mac' in self.available_ips[ifname][ip] and mac_to_id(self.available_ips[ifname][ip]['mac']) == _id:
                #        if self.DEBUG:
                #            print("rematch: early mac-to-id match at: ", self.available_ips[ifname][ip])
                
                
                # With any luck the mac address has changed, but the ip address hasn't.
                
                if valid_ip(hints['ip']) and str(hints['ip']) in ips:
                    if self.DEBUG:
                        print("rematch: ip match: ", str(hints['ip']))
                    
                    if 'thing_id' in self.available_ips[ifname][ hints['ip'] ]:
                        if self.DEBUG:
                            print("rematch: skipping a device that already as a thing_id, indicating it has already been re-matched: ", str(hints['ip']))
                        continue
                    
                    if valid_mac(hints['mac']) and 'mac' in self.available_ips[ifname][ hints['ip'] ] and self.available_ips[ifname][ hints['ip'] ]['mac'] == hints['mac']:
                        if self.DEBUG:
                            print("rematch: ip and mac match")
                        ip_match = True
                        mac_match = True
                        
                        used['ips'].append( hints['ip'] )
                        used['macs'].append(str(self.available_ips[ifname][ hints['ip'] ]['mac']))
                        if 'hostname' in self.available_ips[ifname][ hints['ip'] ] and len(self.available_ips[ifname][ hints['ip'] ]['hostname']) > 2:
                            used['hostnames'].append(str(self.available_ips[ifname][ hints['ip'] ]['hostname']))
                        #saved_devices_from_controller_keys.remove(str(self.available_ips[ifname][ hints['ip'] ]['mac_id']))
                        
                        self.available_ips[ifname][ hints['ip'] ]['thing_id'] = _id
                        self.available_ips[ifname][ hints['ip'] ]['last_rematch_timestamp'] = self.last_scan_timestamp
                        self.remake(self.available_ips[ifname][ hints['ip'] ])
                        continue
                        
                    elif len(hints['hostname']) > 2 and 'hostname' in self.available_ips[ifname][ hints['ip'] ] and self.available_ips[ifname][ hints['ip'] ]['hostname'] == hints['hostname']:
                        if self.DEBUG:
                            print("rematch: ip and hostname match")
                        ip_match = True
                        hostname_match = True

                        used['ips'].append(hints['ip'])
                        if 'mac' in self.available_ips[ifname][ hints['ip'] ] and valid_mac(self.available_ips[ifname][ hints['ip'] ]['mac']):
                            used['macs'].append(str(self.available_ips[ifname][ hints['ip'] ]['mac']))
                            
                            
                            for previously_found_id in previously_found_keys:
                                if previously_found_id in self.previously_found and 'hostname' in self.previously_found[previously_found_id] and str(self.previously_found[previously_found_id]['hostname']) == str(hints['hostname']):
                                    if self.DEBUG:
                                        print("rematch: GREAT! hostname from thing matches with hostname from previously_found: ", str(hints['hostname']))
                                    self.available_ips[ifname][ hints['ip'] ]['thing_id'] = previously_found_id
                                    self.previously_found[previously_found_id]['mac'] = str(self.available_ips[ifname][ hints['ip'] ]['mac'])
                                    self.previously_found[previously_found_id]['ip'] = str(self.available_ips[ifname][ hints['ip'] ]['ip'])
                                    
                            
                            #if _id in saved_devices_from_controller_keys:
                            #    saved_devices_from_controller_keys.remove(_id)
                            #if _id in previously_found_keys:
                            #    previously_found_keys.remove(_id)
                            
                            
                        used['hostnames'].append(str(hints['hostname']))
                        #saved_devices_from_controller_keys.remove(str(available_ips[ifname][ hints['ip'] ]['mac_id']))
                        
                        self.available_ips[ifname][ hints['ip'] ]['thing_id'] = _id
                        self.available_ips[ifname][ hints['ip'] ]['last_rematch_timestamp'] = self.last_scan_timestamp
                        
                        #self.remake(self.available_ips[ifname][ hints['ip'] ])
                        continue
                
                
                if ip_match == False: # IP did not match, or IP was already used
                    for ip in ips:
                        found = self.available_ips[ifname][ip]
                        if self.DEBUG:
                            print("rematch: looking for mac/hostname match in: ", found)
                        
                        mac_match = False
                        hostname_match = False
                        
                        # Unlikely to match the MAC again, as that would already have lead to a mac_id match earlier..
                        if valid_mac(hints['mac']) and 'mac' in found and found['mac'] == hints['mac']:
                            if self.DEBUG:
                                print("rematch: UNEXPECTEDLY Found mac again")
                                print("_id =?= mac_to_id: ", _id, mac_to_id(str(hints['mac'])))
                                if str(_id) == str(mac_to_id(str(hints['mac']))):
                                    print("UNEXPECTEDLY, the _id and mac_to_id match")
                                else:
                                    print("OK the _id and mac_to_id do not match")
                            mac_match = True
                        
                        if len(hints['hostname']) > 2 and 'hostname' in found and found['hostname'] == hints['hostname'] and not found['hostname'] in used['hostnames']:
                            if self.DEBUG:
                                print("rematch: Found hostname again")
                            hostname_match = True
                        
                        # Again, it should not be possible that the mac address matches here
                        if mac_match and hostname_match:
                            if self.DEBUG:
                                print("rematch: UNEXPECTEDLY very solid match, updating hints IP")
                            hints['ip'] = str(found['ip'])
                        
                        elif hostname_match:
                            if self.DEBUG:
                                print("rematch: hostname match only")
                            
                            if str(found['ip']) in used['ips']:
                                if self.DEBUG:
                                    print("\nWARNING, this IP already seems to be matched to another device?!: " + str(found['ip']))
                                
                                # AT THIS POINT ALL OPTIONS TO RE-MATCH IT HAVE BEEN EXHAUSTED? BUT WOULD THIS EVEN BE POSSIBLE?
                                
                            else:
                                # REMATCHED THROUGH HOSTNAME ONLY
                                #hints['ip'] = str(found['ip'])
                                
                                if 'ip' in found and valid_ip(found['ip']):
                                    used['ips'].append( str(found['ip']) )
                                if 'mac' in found and valid_mac(found['mac']):
                                    used['macs'].append(str(found['mac']))
                                    #saved_devices_from_controller_keys.remove(str(available_ips[ifname][ ip ]['mac_id']))
                                used['hostnames'].append(str(found['hostname']))
                                
                                self.available_ips[ifname][ip]['thing_id'] = _id
                                self.available_ips[ifname][ip]['thing_id']['last_rematch_timestamp'] = self.last_scan_timestamp
                                
                                #self.remake(found)
                                continue
        
        
        _id = None
        
        if self.DEBUG:
            
            print("\n\nREMATCH SANITY CHECK")
            for ifname in list(self.available_ips.keys()):
                for known_ip_address in list(self.available_ips[ifname].keys()):
                    if 'thing_id' in self.available_ips[ifname][known_ip_address]:
                        _id = self.available_ips[ifname][known_ip_address]['thing_id']
                        try:
                            if known_ip_address != self.previously_found[_id]['ip']:
                                print("ERROR: IP WAS NOT UP TO DATE: ", self.previously_found[_id])
                            if self.available_ips[ifname][known_ip_address]['mac'] != self.previously_found[_id]['mac']:
                                print("ERROR: MAC WAS NOT UP TO DATE: ", self.previously_found[_id])
                            if 'hostname' in self.available_ips[ifname][known_ip_address] and self.available_ips[ifname][known_ip_address]['hostname'] != self.previously_found[_id]['hostname']:
                                print("ERROR: HOSTNAME WAS NOT UP TO DATE: ", self.previously_found[_id])
                            if self.available_ips[ifname][known_ip_address]['mac_id'] != _id:
                                print("INTERESTING, THE THING_ID WAS NOT THE MAC_ID: ", self.available_ips[ifname][known_ip_address])
                        except Exception as ex:
                            print("ERROR, caught rematch sanity check exception: ", ex)

            print("\n\n\n\nREMATCH DONE\n\n")
            print("self.previously_found:\n", json.dumps(self.previously_found,indent=4))
            print("\nrematch: final used: \n", json.dumps(used,indent=4))
            print("\n FINAL saved_devices_from_controller_keys at the end (ideally an empty array): \n", saved_devices_from_controller_keys)
            print("\n FINAL previously_found_keys at the end (ideally an empty array): \n", previously_found_keys)
            print("\n\n\n")
        
        
        

    def remake_all(self):
        for _id in list(self.previously_found.keys()):
            name = 'Unnamed ' + str(self.previously_found[_id]['ip'])
            if 'hostname' in self.previously_found[_id] and len(str(self.previously_found[_id]['hostname'])) > 4:
                name = self.previously_found[_id]['hostname']
            device = PresenceDevice(self, _id, name, self.previously_found[_id])
            self.handle_device_added(device)
            if self.DEBUG:
                print("REMAKE_ALL: ADDED DEVICE: ", name)
            
            if str(_id) not in self.created_as_things:
                self.created_as_things.append(str(_id))
            
        
            

    def remake(self, item=None, new=False):
        try:
            if self.DEBUG:
                print("\n\nREMAKE\n\nin remake. item: ", item)
            
            if item == None:
                if self.DEBUG:
                    print("remake: error, provided item was None")
                return
            
            if self.DEBUG:
                if self.devices:
                    print("remake: self.devices length BEFORE: ", len(self.devices))
                else:
                    print("remake: no self.devices (yet)?")
            
            name = 'Unnamed'
            thing_info = {'thing':True}
            if 'ip' in item and valid_ip(item['ip']):
                thing_info['ip'] = item['ip']
            if 'mac' in item and valid_mac(item['mac']):
                thing_info['mac'] = item['mac']
            if 'hostname' in item and len(item['hostname']) > 2:
                thing_info['hostname'] = item['hostname'].lower()
                name = item['hostname']
            elif 'mac_vendor' in item and isinstance(item['mac_vendor'],str) and len(item['mac_vendor']) > 4:
                name = str(item['mac_vendor'])
        
            if name == 'Unnamed' and isinstance(item['ip'],str):
                name = name + ' (' + str(item['ip']) + ')'
        
            if self.DEBUG:
                print("remake: name: ", name)
                print("remake: thing_info: ", thing_info)
            
            thing_id = None
            if 'thing_id' in item and len(str(item['thing_id'])) > 2:
                thing_id = str(item['thing_id'])
            elif 'mac_id' in item and len(str(item['mac_id'])) > 2:    
                thing_id = str(item['mac_id'])
            elif 'id' in item and len(str(item['id'])) > 2:  
                thing_id = str(item['id'])
                
            if isinstance(thing_id,str):
                
                if not thing_id.startswith('presence-'):
                    thing_id = 'presence-' + thing_id
                
                if thing_id in self.previously_found:
                    if self.DEBUG:
                        print("remake: thing_id was already in self.previously_found. Updating it's ip, mac and hostname based on the info provided (if necessary)")
                    if 'ip' in self.previously_found[thing_id] and 'ip' in thing_info and valid_ip(self.previously_found[thing_id]['ip']) and valid_ip(thing_info['ip']) and self.previously_found[thing_id]['ip'] != thing_info['ip']:
                        if self.DEBUG:
                            print("INTERESTING, THE IP ADDRESS OF AN ACCEPTED THING SEEMS TO HAVE CHANGED: ", self.previously_found[thing_id]['ip'], " -> ", thing_info['ip'])
                        self.previously_found[thing_id]['ip'] = thing_info['ip']
                    
                    if 'mac' in self.previously_found[thing_id] and 'mac' in thing_info and valid_ip(self.previously_found[thing_id]['mac']) and valid_ip(thing_info['mac']) and self.previously_found[thing_id]['mac'] != thing_info['mac']:
                        if self.DEBUG:
                            print("INTERESTING, THE IP ADDRESS OF AN ACCEPTED THING SEEMS TO HAVE CHANGED: ", self.previously_found[thing_id]['mac'], " -> ", thing_info['mac'])
                        self.previously_found[thing_id]['mac'] = thing_info['mac']
                            
                    if 'hostname' in self.previously_found[thing_id] and 'hostname' in thing_info and self.previously_found[thing_id]['hostname'] and len(str(self.previously_found[thing_id]['hostname'])) > 2 and thing_info['hostname'] and len(str(thing_info['hostname'])) > 2 and str(self.previously_found[thing_id]['hostname']) != str(thing_info['hostname']):
                        if self.DEBUG:
                            print("INTERESTING, THE HOSTNAME OF AN ACCEPTED THING SEEMS TO HAVE CHANGED: ", str(self.previously_found[thing_id]['hostname']), " -> ", str(thing_info['hostname']))
                        self.previously_found[thing_id]['hostname'] = thing_info['hostname'].lower()
                    elif not 'hostname' in self.previously_found[thing_id] and 'hostname' in thing_info and thing_info['hostname'] and len(str(thing_info['hostname'])) > 2:
                        if self.DEBUG:
                            print("INTERESTING, THE HOSTNAME OF AN ACCEPTED THING WAS NOT KNOWN BEFORE, BUT IT HAS ONE NOW. ADDING TO self.previously_found: ", str(thing_info['hostname']))
                        
                #if new == True and str(thing_id) in self.previously_found:
                #    if self.DEBUG:
                #        print("ERROR, a new device, but it already has an entry in self.previously_found:\n", json.dumps(self.previously_found[str(thing_id)], indent=4))
                #    self.previously_found[str(thing_id)] = thing_info
                    
                #if new == True or not thing_id in self.previously_found:
                
                else:
                    self.previously_found[thing_id] = thing_info
                    
                    if self.DEBUG:
                        print("remake: device was not in self.previously_found yet. It is now: \n", json.dumps(self.previously_found, indent=4))
                
                if not "first_seen" in self.previously_found[thing_id]:
                    self.previously_found[thing_id]["first_seen"] = self.last_scan_timestamp

                if not 'thing' in self.previously_found[thing_id]:
                    self.previously_found[thing_id]['thing'] = True
                
                device = PresenceDevice(self, str(thing_id), name, self.previously_found[thing_id])
                self.handle_device_added(device)
                if self.DEBUG:
                    print("REMAKE: ADDED DEVICE")
                
                if str(thing_id) not in self.created_as_things:
                    self.created_as_things.append(str(thing_id))
                    #self.truth[str(thing_id)] = thing_info
                
                
                if 'ip' in item and valid_ip(item['ip']):
                    for ifname in list(self.available_ips.keys()):
                        if item['ip'] in list(self.available_ips[ifname].keys()):
                            if 'thing_id' in self.available_ips[ifname][ item['ip'] ] and str(self.available_ips[ifname][ item['ip'] ]['thing_id']) != str(thing_id):
                                if self.DEBUG:
                                    print("\nERROR, self.available_ips item already contained a thing_id, and they are not the same: ", self.available_ips[ifname][ item['ip'] ]['thing_id'], str(thing_id))
                            self.available_ips[ifname][ item['ip'] ]['thing_id'] = str(thing_id)
                            if self.DEBUG:
                                print("added thing_id for device in self.available_ips")
                            break
                                
                if self.devices:
                    if self.DEBUG:
                        print("remake: self.devices length AFTER: ", len(self.devices.keys()), list(self.devices.keys()))
                
                self.should_save = True
                
            else:
                if self.DEBUG:
                    print("\n\nERROR: remake: no valid thing_id in item: ", item)
                
                
                
        except Exception as ex:
            if self.DEBUG:
                print("\n\ncaught ERROR in remake: " + str(ex) + "\n\n")
            
        self.quick_scan_phase += 1
        
        
        
        #device = PresenceDevice(self, _id, name, None)
        #self.handle_device_added(device)




#
#  QUICK SCAN
#


    #
    #  This gives a quick impression of the network.
    #
    #  nMap is the best, and if installed forms the main source of truth
    #  Arpa is useful because it can find mobile phones much better than ping
    #  Avahi is great for devices that want to be found
    #  NBTscan is useful for older devices that don't support mDNS, but has been removed
    #  IP neighbour is yet another list, this time from the OS. It's a great source for IPv6
    

    def quick_scan(self):
        if self.busy_doing_light_scan == False and self.busy_doing_brute_force_scan == False:
            self.busy_doing_light_scan = True
            self.should_quick_scan = False
            if self.DEBUG:
                print("\n\nInitiating quick scan of network\n")
            
            try:
                self.last_scan_timestamp = int(time.time())
                self.script_outputs = {}
            
                self.check_available_interfaces()
                self.quick_scan_phase += 2
            
                self.available_ips = {}
                for available_interfaces in list(self.available_interfaces.keys()):
                    self.available_ips[str(available_interfaces)] = {}
                
                self.check_available_ips()
                self.quick_scan_phase += 2
            
                # see if all accepted things can be found again
                self.rematch()
                self.quick_scan_phase = 48
                self.remake_all()
                self.quick_scan_phase = 50
            
                self.should_save = True
                
                
            except Exception as ex:
                if self.DEBUG:
                    print("\n\nERROR\n\ncaught error in quick_scan: " + str(ex))
                
            self.busy_doing_light_scan = False
            
            
            
            if self.DEBUG:
                print("\nQUICK SCAN COMPLETE\n")
            
        else:
            if self.DEBUG:
                print("\n\nquick_scan: a scan is already being performed\n")










#
#   SECURITY SCANNING
#


    def update_available_nmap_scripts_list(self):
        if not os.path.isdir(self.nmap_scripts_dir):
            if self.DEBUG:
                print("ERROR: update_available_nmap_scripts_lis: could not find nMap scripts dir: ", self.nmap_scripts_dir)
            os.system('mkdir -p ' + str(self.nmap_scripts_dir))
        if os.path.isdir(self.nmap_scripts_dir):
            self.nmap_scripts = [f for f in os.listdir(str(self.nmap_scripts_dir)) if os.path.isfile(os.path.join(str(self.nmap_scripts_dir), str(f)))]


    def update_security_scan(self,script_path='https://svn.nmap.org/nmap/scripts/vulners.nse'):
        try:
            os.system('sudo nmap -script-updatedb')
            
            self.last_security_update_time = int(time.time())
            self.should_save = True
            
            if isinstance(script_path,str) and script_path.endswith('.nse') and not '#' in script_path and not '?' in script_path and not '..' in script_path and script_path.startswith('https://'):
                
                filename = str(os.path.basename(str(script_path)))
                if not filename.endswith('.nse'):
                    if self.DEBUG:
                        print("\nERROR, update_security_scan: filename somehow did not end with .nse: " + str(filename))
                    return False
                    
                target_path = os.path.join(str(self.nmap_scripts_dir),filename)
                if self.DEBUG:
                    print("update_security_scan: downloading script_path: " + str(script_path) + ' to: ' + str(target_path))
                    
                os.system('wget ' + str(script_path) + ' -O ' + str(target_path) + '_dl')
                if os.path.isfile(str(target_path) + '_dl'):
                    if os.path.getsize(str(target_path) + '_dl') == 0:
                        if self.DEBUG:
                            print("\nERROR, update_security_scan: downloaded the script, but it was empty: " + str(script_path) + ' to: ' + str(target_path))
                        os.system('rm ' + str(target_path) + '_dl')
                        return False
                    else:
                        os.system('mv ' + str(target_path) + '_dl ' + str(target_path))
                        self.update_available_nmap_scripts_list()
                
                return bool(os.path.isfile(str(target_path)))
                
            else:
                if self.DEBUG:
                    print("\nERROR, update_security_scan failed to download script, as it does not seem valid")
            
                
            
        except Exception as ex:
            if self.DEBUG:
                print("caught error updating security scan script: " + str(ex))
        
        return False



    def run_nmap_script(self,script=None,ifname=None,target=None):
        
        if not isinstance(script,str) or not isinstance(ifname,str):
            if self.DEBUG:
                print("run_nmap_script: invalid script or ifname provided: ", script, ifname)
            return False
            
        if ifname == '':
            return False
        
        if self.busy_doing_security_scan == True:
            if self.DEBUG:
                print("run_nmap_script: was already busy doing an intense scan: ", script, ifname, target)
            return False
        
        try:

            script_path = ''
            target_ips = None
            output_id = ifname
            if os.path.exists(self.nmap_scripts_dir):
                #nmap_command = 'sudo nmap --datadir ' + str(self.nmap_scripts_dir)
                nmap_command = 'sudo nmap --scan-delay=47ms' # --host-timeout 60
                
            
                if valid_ip(target):
                    target_ips =  ' ' + target
                    output_id = target
                elif valid_ip6(target):
                    target_ips =  ' -6 ' + target
                    output_id = target
                elif str(ifname) in list(self.available_interfaces.keys()) and \
                  'operstate' in self.available_interfaces[target] and \
                  self.available_interfaces[target]['operstate'].upper() == 'UP' and \
                  'addr_info' in self.available_interfaces[target] and \
                  self.available_interfaces[target]['addr_info'] and \
                  len(self.available_interfaces[target]['addr_info']) and \
                  'local' in self.available_interfaces[target]['addr_info'][0]:
                  
                    if valid_ip(self.available_interfaces[target]['addr_info'][0]['local']):
                        target_ips = ' ' + self.available_interfaces[target]['addr_info'][0]['local'] + '/24'
                        self.busy_doing_security_scan = True
                    elif valid_ip6(self.available_interfaces[target]['addr_info'][0]['local']):
                        if self.DEBUG:
                            print("user wants to scan an interface with an ip6 address (well not really)")
                        
                        #target_ips = ' -6 ' + self.available_interfaces[target]['addr_info'][0]['local'] + '/24'
                        #self.busy_doing_security_scan = True
                
                # TODO: the script above takes the first ip array item. Maybe setting ip4 or ip6 should be an option? Or prefer ip6 if available?
                # TODO: in case of ip6 the available ip6 addresses on that interface could all be looped over (since a brute-force scan is not an option with so many potential addresses)

                if isinstance(target_ips,str):
                
                    if self.DEBUG:
                        print("run_nmap_script: target_ips " + str(target_ips))
                    
                    if script in self.nmap_scripts:
                        script_path = ' --script ' + str(os.path.join(str(self.nmap_scripts_dir),str(script)))
                        if self.DEBUG:
                            print("run_nmap_script: script_path: " + str(script_path))
                    elif script == '-A':
                        #nmap_command += ' -A ' + 
                        script_path = ' -A'
                
                    #  + ' -sV'
                    # -Pn
        
                    if script_path and target_ips:
                        nmap_command = str(nmap_command) + str(script_path) + str(target_ips) + ' -vv'
                        if self.DEBUG:
                            print("run_nmap_script: nmap_command: " + str(nmap_command))
                        
                        self.script_outputs[output_id] = {'output':'Running scan...', 'ifname':ifname, 'start_timestamp':int(time.time()), 'command':str(nmap_command)}
                        
                        from subprocess import Popen, PIPE, CalledProcessError

                        def execute_command(cmd):
                            with subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as process:
                                for line in process.stdout:
                                    #print(line, end='')  # Outputs the line immediately
                                    if isinstance(line,str):
                                        self.script_outputs[output_id]['output'] += line
                                    time.sleep(0.001)
                                if process.returncode != 0 or self.running == False:
                                    raise subprocess.CalledProcessError(process.returncode, cmd)

                        ## Example usage
                        #execute_command(["mvn", "clean", "install"])
                        
                        
                        #script_output = run_command(nmap_command)
                        script_output = execute_command(nmap_command.split())
                        if self.DEBUG:
                            print("\n\nrun_nmap_script: script_output: \n" + str(script_output) + "\n\n")
                        
                        if self.script_outputs[output_id]:
                            self.script_outputs[output_id]['end_timestamp'] = int(time.time())
                            if isinstance(script_output,str):
                                self.script_outputs[output_id]['output'] = script_output
                            else:
                                self.script_outputs[output_id]['output'] = 'Scan failed'
                    
                        if self.busy_doing_security_scan:
                            self.busy_doing_security_scan = False
                    
                        return True
        
        except Exception as ex:
            if self.DEBUG:
                print("caught error in run_nmap_script: " + str(ex))
            self.busy_doing_security_scan = False
            
        
                
        return False











    
    def get_avahi_lines(self):
        if self.DEBUG:
            print("in get_avahi_lines")
        avahi_lines = []
        # "--ignore-local",
        # ,"--cache"
        avahi_browse_command = ["avahi-browse","--parsable","--all","--resolve","--no-db-lookup","--terminate"] # avahi-browse -p -l -a -r -k -t
        
        try:
            avahi_scan_result = subprocess.check_output(avahi_browse_command) #.decode()) # , universal_newlines=True, stdout=subprocess.PIPE
            avahi_encoding = 'latin1'
            try:
                avahi_encoding = chardet.detect(avahi_scan_result)['encoding']
                if self.DEBUG:
                    print("detected avahi output encoding: " + str(avahi_encoding))
            except Exception as ex:
                if self.DEBUG:
                    print("error getting avahi output encoding: " + str(ex))
                
            avahi_scan_result = avahi_scan_result.decode(avahi_encoding)
            for line in avahi_scan_result.split('\n'):
                # replace ascii codes in the string. E.g. /032 is a space
                for x in range(127):
                    anomaly = "\\" + str(x).zfill(3)
                    if anomaly in line:
                        line = line.replace(anomaly,chr(x))
                avahi_lines.append(line)
        
        except Exception as ex:
            if self.DEBUG:
                print("Error in get_avahi_lines: " + str(ex))
                
        return avahi_lines
        


    def tcpdump_listener(self):

        try:
            #if self.shell == None:
            #    self.shell = subprocess.Popen(['/bin/bash'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            
            if self.tcpdump == None:
                self.tcpdump = subprocess.Popen(["sudo","tcpdump","-i","any","port","5353","and","host","224.0.0.251","-n"], stderr=subprocess.DEVNULL, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                #self.tcpdump = subprocess.Popen(["sudo","tcpdump","-i","any","'udp port 5353 and (host 224.0.0.251 or host ff02::fb)'","-n"], stderr=subprocess.DEVNULL, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

                # sudo tcpdump -i any 'udp port 5353 and (host 224.0.0.251 or host ff02::fb)'

                def read_stdout():
                    while self.running:
                        msg = self.tcpdump.stdout.readline()
                        self.messages.append(msg.decode())
                        time.sleep(0.0001)
                    if self.DEBUG:
                        print("tcpdump read_stdout closed")
                    self.tcpdump = None
                    
                self.stdout_thread = threading.Thread(target=read_stdout)
                self.stdout_thread.daemon = True
                self.stdout_thread.start()
                
            #self.shell.stdin.write((str(command) + '\n').encode())
            #self.shell.stdin.flush()
        except Exception as ex:
            if self.DEBUG:
                print("caught error in tcpdump_listener: " + str(ex))


    

    def handle_device_saved(self, device_id, device):
        """User saved a thing. Also called when the add-on starts."""
        try:
            if self.DEBUG:
                print("\nreceived message at handle_device_saved. device_id: ", device_id)
            if device_id.startswith('presence'):
                if self.DEBUG:
                    print("\nhandle_device_saved. device_id = " + str(device_id) + ", device = " + str(device))
                    print("\n\n")
                
                self.saved_devices_from_controller[device_id] = device
                #if self.DEBUG:
                #    print("\n\nself.saved_devices_from_controller is now: \n\n", self.saved_devices_from_controller, '\n\n')
                #for ifname in list(self.available_ips.keys()):
                #    for known_ip_address in self.available_ips[ifname]:
                #        if 'mac_id' in self.available_ips[ifname][known_ip_address]:
                #            if not 'thing_id' in self.available_ips[ifname][known_ip_address] and isinstance(self.available_ips[ifname][known_ip_address]['mac_id'],str) and device_id == 'presence-' + str(self.available_ips[ifname][known_ip_address]['mac_id']):
                #                self.available_ips[ifname][known_ip_address]['thing_id'] = device_id
                
                
                if device_id not in self.accepted_as_things:
                    #print("Adding to created_as_things list: " + str(device_id.split("-")[1]))
                    
                    
                    #original_title = "Unknown"
                    #try:
                    #    if str(device['title']) != "":
                    #        original_title = str(device['title'])
                    #except Exception as ex:
                    #    if self.DEBUG:
                    #        print("Error getting original_title from data provided by the controller: " + str(ex))
                    
                    #self.created_as_things.append({device_id:{'name':original_title}})
                    self.accepted_as_things.append(device_id)
                    if self.DEBUG:
                        print("Added " + str(device['title']) + " to accepted_as_things list")
                    
        except Exception as ex:
            if self.DEBUG:
                print("Error dealing with existing saved devices: " + str(ex))



   

    def remove_thing(self, device_id):
        """User removed a thing from the interface."""
        if self.DEBUG:
            print("Removing presence detection device: " + str(device_id))

        try:
            #print("THING TO REMOVE:" + str(self.devices[device_id]))
            if str(device_id) in self.previously_found:
                del self.previously_found[device_id]
            #print("2")
            obj = self.get_device(device_id)
            #print("3")
            if obj:
                self.handle_device_removed(obj)
                if self.DEBUG:
                    print("Succesfully removed presence detection device")
            else:
                if self.DEBUG:
                    print("Error, could not get device object to remove")
        except Exception as ex:
            if self.DEBUG:
                print("Removing presence detection thing failed: " + str(ex))
        #del self.devices[device_id]
        self.should_save = True # saving changes to the json persistence file
        return True
        
    

    # DEPRECATED
    # TODO: remove this. The clock and the functions below still depend on it.
    def select_interface(self):
        try:
            eth0_output = subprocess.check_output(['ifconfig', 'eth0']).decode('utf-8')
            #print("eth0_output = " + str(eth0_output))
            wlan0_output = subprocess.check_output(['ifconfig', 'wlan0']).decode('utf-8')
            #print("wlan0_output = " + str(wlan0_output))
            
            #mlan0_output = str(subprocess.check_output(['ifconfig', 'mlan0']).decode('utf-8'))
            
            #uap0_output = str(subprocess.check_output(['ifconfig', 'uap0']).decode('utf-8'))

            
            if "inet " in eth0_output and self.prefered_interface == "eth0":
                self.selected_interface = "eth0"
            if not "inet " in eth0_output and self.prefered_interface == "eth0":
                self.selected_interface = "wlan0"
            if "inet " in wlan0_output and self.prefered_interface == "wlan0":
                self.selected_interface = "wlan0"
        except Exception as ex:
            if self.DEBUG:
                print("Error in select_interface: " + str(ex))
            self.selected_interface = "wlan0"
        
    
    def ping(self, ip_address, count, interface=None):
        if interface == None:
            interface = self.selected_interface
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        #command = ["ping", param, count, "-i", 1, str(ip_address)]
        command = "ping -I " + str(interface) + " " + str(param) + " " + str(count) + " -i 0.5 " + str(ip_address)
        #print("command: " + str(command))
        #return str(subprocess.check_output(command, shell=True).decode())
        try:
            result = subprocess.run(command, shell=True, universal_newlines=True, stdout=subprocess.DEVNULL) #.decode())
            #print("ping done")
            return result.returncode
        except Exception as ex:
            if self.DEBUG:
                print("error pinging! Error: " + str(ex))
            return 1


    def arping(self, ip_address, count, interface=None):
        if interface == None:
            interface = self.selected_interface
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = "sudo arping -i " + str(interface) + " " + str(param) + " " + str(count) + " " + str(ip_address)
        if self.DEBUG:
            print("arping command: " + str(command))
        try:
            result = subprocess.run(command, shell=True, universal_newlines=True, stdout=subprocess.DEVNULL) #.decode())
            return result.returncode
        except Exception as ex:
            if self.DEBUG:
                print("error arpinging! Error: " + str(ex))
            return 1


    def arp(self, ip_address, interface=None):
        if interface == None:
            interface = self.selected_interface
        if valid_ip(ip_address):
            command = "arp -i " + str(interface) + " " + str(ip_address)
            try:
                result = subprocess.run(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE) #.decode())
                for line in result.stdout.split('\n'):
                    mac_addresses = re.findall(r'(([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})', str(line))
                    if len(mac_addresses):
                        #print("util: arp: mac in line: " + line)
                        return str(line)
                
                return str(result.stdout)

            except Exception as ex:
                if self.DEBUG:
                    print("Arp error: " + str(ex))
                result = 'error'
            return result
            #return str(subprocess.check_output(command, shell=True).decode())
    
    
    
    def get_vendor(self,mac):
        if self.DEBUG:
            print("get_vendor: mac: ", mac)
            
        counter = 0
        if valid_mac(mac) and self.mac_vendor_csv:
            
            mac = mac.replace(':','')
            mac_half = mac[0:6]
            mac_half_upper = mac_half.upper()
            if self.DEBUG:
                print("looking up mac: " + str(mac_half_upper))
            for row in self.mac_vendor_csv:
                
                counter += 1
                
                #if counter == 20:
                #    print("ROW type: ", type(row))
                #    print("ROW json.dumps: ", json.dumps(row))
                #    print("ROW str: ", str(row))
                
                if mac_half_upper in row:
                    if self.DEBUG:
                        print("mac_vendor_lookup: found matching row: ", row)
                    
                    if len(row) > 2:
                        if self.DEBUG:
                            print("mac_vendor_lookup: returning vendor string: " + str(row[2]))
                        return str(row[2])
                    break
            
            if self.DEBUG:
                print("looking up mac: no luck in newer OUI.csv: " + str(mac_half_upper))
                
            # Try looking in the older data
            return get_vendor_old(mac)
                    
        else:
            if self.DEBUG:
                print("mac_vendor_lookup: invalid mac provided or csv not loaded")
        return None
    
    
    # saves to persistence file
    def save_to_json(self):
        """Save found devices to json file."""
        try:
            if self.DEBUG:
                print("Saving updated list of found devices to json file")
            #if self.previously_found:
            #with open(self.persistence_file_path, 'w') as fp:
                #json.dump(self.previously_found, fp)
            
            data_to_write = {'previously_found':self.previously_found,
                            'mayor_version':self.mayor_version,
                            'meso_version':self.meso_version,
                            'last_security_update_time':self.last_security_update_time,
                    }
                
            j = json.dumps(data_to_write, indent=4) # Pretty printing to the file
            f = open(self.persistence_file_path, 'w')
            print(j, file=f)
            f.close()
                
        except Exception as ex:
            print("Saving to json file failed: " + str(ex))
        self.should_save = False


    def start_pairing(self, timeout):
        """Starting the pairing process."""
        #self.quick_scan()
        #self.brute_force_scan()
        #if self.busy_doing_brute_force_scan == False:
        #    self.should_brute_force_scan = True
        #    self.brute_force_scan()

    def cancel_pairing(self):
        """Cancel the pairing process."""
        self.save_to_json()
        self.thing_pairing_done = True

    def unload(self):
        """Add-on is shutting down."""
        if self.DEBUG:
            print("networkscanner is being unloaded")
        self.running = False
        time.sleep(1)
        self.save_to_json()
        return True
        
        
        


class presenceAction(Action):
    """An Action represents an individual action on a device."""

    def __init__(self, id_, device, name, input_):
        """
        Initialize the object.
        id_ ID of this action
        device -- the device this action belongs to
        name -- name of the action
        input_ -- any action inputs
        """
        self.id = id_
        self.device = device
        self.name = name
        self.input = input_
        self.status = 'created'
        self.time_requested = timestamp()
        self.time_completed = None

    def as_action_description(self):
        """
        Get the action description.
        Returns a dictionary describing the action.
        """
        description = {
            'name': self.name,
            'timeRequested': self.time_requested,
            'status': self.status,
        }

        if self.input is not None:
            description['input'] = self.input

        if self.time_completed is not None:
            description['timeCompleted'] = self.time_completed

        return description

    def as_dict(self):
        """
        Get the action description.
        Returns a dictionary describing the action.
        """
        d = self.as_action_description()
        d['id'] = self.id
        return d

    def start(self):
        """Start performing the action."""
        self.status = 'pending'
        self.device.action_notify(self)

    def finish(self):
        """Finish performing the action."""
        self.status = 'completed'
        self.time_completed = timestamp()
        self.device.action_notify(self)





        
