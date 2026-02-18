"""Network scanner API handler."""

import os
import re
import json
import time
import requests
import subprocess
from .util import *

try:
    from gateway_addon import APIHandler, APIResponse
    #print("succesfully loaded APIHandler and APIResponse from gateway_addon")
except:
    print("ERROR,Import APIHandler and APIResponse from gateway_addon failed.")




class NetworkScannerAPIHandler(APIHandler):
    """Network scanner API handler."""

    def __init__(self, adapter, verbose=False):
        """Initialize the object."""
        #print("INSIDE API HANDLER INIT")
        
        self.adapter = adapter
        self.DEBUG = self.adapter.DEBUG

        if self.DEBUG:
            print("init of network presence api handler")
        
        # Intiate extension addon API handler
        try:
            manifest_fname = os.path.join(
                os.path.dirname(__file__),
                '..',
                'manifest.json'
            )

            with open(manifest_fname, 'rt') as f:
                manifest = json.load(f)

            APIHandler.__init__(self, manifest['id'])
            self.manager_proxy.add_api_handler(self)
            

            if self.DEBUG:
                print("self.manager_proxy = " + str(self.manager_proxy))
                print("Created new API HANDLER: " + str(manifest['id']))
        
        except Exception as e:
            print("\nERROR: failed to init API handler: " + str(e))
        
        #self.rb = RadioBrowser()
                        

#
#  HANDLE REQUEST
#

    def handle_request(self, request):
        """
        Handle a new API request for this handler.

        request -- APIRequest object
        """
        #print("in handle_request")
        try:
        
            if request.method != 'POST':
                return APIResponse(status=404)
            
            if request.path == '/ajax':
                
                try:
                    #if self.DEBUG:
                    #    print("API handler is being called")
                    #    print("request.body: " + str(request.body))
                    
                    action = str(request.body['action'])
                    
                    if self.DEBUG:
                        print("got api request. action: " + str(action))
                    
                    if action == 'init':
                        if self.DEBUG:
                            print("in init")
                        
                        state = False
                        
                        try:
                            if self.adapter.nmap_scripts_dir:
                                self.adapter.nmap_scripts = [f for f in os.listdir(str(self.adapter.nmap_scripts_dir)) if os.path.isfile(os.path.join(str(self.adapter.nmap_scripts_dir), str(f)))]
                                #print("self.adapter.nmap_scripts: ", self.adapter.nmap_scripts)
                                
                                state = True
                        except Exception as ex:
                            if self.DEBUG:
                                print("caught error trying to scan nmap scripts dir: " + str(ex))
                        
                        
                        
                        return APIResponse(
                          status=200,
                          content_type='application/json',
                          content=json.dumps({'state':'ok',
                                              'nmap_installed':self.adapter.nmap_installed,
                                              'nmap_scripts':self.adapter.nmap_scripts,
                                              'nmap_vulners_file_exists':self.adapter.nmap_vulners_file_exists,
                                              'ignore_candle_controllers':self.adapter.ignore_candle_controllers,
                                              'debug':self.adapter.DEBUG
                                          }),
                        )
                        
                    
                    
                    elif action == 'scan' or action == 'poll':
                        state = False
                        nmap_vulners_file_exists = False
                        pairing_done = False
                        try:
                            #avahi_lines = self.adapter.get_avahi_lines()
                            #avahi_scan_result = subprocess.run(avahi_browse_command, universal_newlines=True, stdout=subprocess.PIPE).decode('latin-1')
                            
                            if self.adapter.nmap_vulners_file_exists == False:
                                if os.path.isfile(self.adapter.nmap_vulnerabilities_script_path):
                                    self.adapter.nmap_vulners_file_exists = True
                            
                            if action == 'scan':
                                if self.adapter.busy_doing_light_scan == False and self.adapter.busy_doing_brute_force_scan == False:
                                    self.adapter.available_ips = {}
                                    self.adapter.available_interfaces = {}
                                    self.adapter.avahi_lines = []
                                    self.adapter.should_quick_scan = True
                                    self.adapter.quick_scan_phase = 0
                                    self.adapter.accepted_as_things = []
                                    state = True
                            else:
                                state = True
                                pairing_done = False
                                if self.adapter.thing_pairing_done:
                                    pairing_done = True
                                    self.adapter.thing_pairing_done = False
                            
                            
                            for target in list(self.adapter.script_outputs.keys()):
                                if self.adapter.script_outputs[target]['start_timestamp'] and self.adapter.script_outputs[target]['start_timestamp'] < time.time() - 3600:
                                    if self.DEBUG:
                                        print("pruning old network scan output: ", target)
                                    del self.adapter.script_outputs[target]
                            
                        except Exception as ex:
                             if self.DEBUG:
                                 print("scan/poll: error: " + str(ex))
                        
                        
                        return APIResponse(
                          status=200,
                          content_type='application/json',
                          content=json.dumps({'state':state,
                                              'last_scan_timestamp':self.adapter.last_scan_timestamp,
                                              'quick_scan_phase':self.adapter.quick_scan_phase,
                                              'avahi_lines':self.adapter.avahi_lines,
                                              'nmap_installed':self.adapter.nmap_installed,
                                              'available_interfaces':self.adapter.available_interfaces,
                                              'available_ips':self.adapter.available_ips,
                                              'previously_found':self.adapter.previously_found,
                                              'should_quick_scan':self.adapter.should_quick_scan,
                                              'busy_doing_light_scan': self.adapter.busy_doing_light_scan,
                                              'busy_doing_brute_force_scan': self.adapter.busy_doing_brute_force_scan,
                                              'busy_doing_security_scan': self.adapter.busy_doing_security_scan,
                                              'script_outputs':self.adapter.script_outputs,
                                              'nmap_vulnerability_scan_file_exists':nmap_vulners_file_exists,
                                              'own_ip':self.adapter.own_ip,
                                              'last_security_update_time':self.adapter.last_security_update_time,
                                              'pairing_done':pairing_done,
                                              'scan_time_delta':self.adapter.scan_time_delta,
                                              'waiting_two_minutes':self.adapter.waiting_two_minutes,
                                              'controller_start_time':self.adapter.controller_start_time,
                                              'debug':self.adapter.DEBUG
                                          }),
                        )
                    
                    
                    elif action == 'track_thing':
                        state = True
                        try:
                            self.adapter.remake(request.body['details']);
                        except Exception as ex:
                            state = False
                            if self.DEBUG:
                                print("track_thing: error: " + str(ex))
                            
                                 
                        return APIResponse(
                          status=200,
                          content_type='application/json',
                          content=json.dumps({'state':state}),
                        )
                        
                        
                    elif action == 'update_security_scan':
                        state = False
                        try:
                            state = self.adapter.update_security_scan()
                        except Exception as ex:
                            if self.DEBUG:
                                print("caught error trying to update security scan: " + str(ex))
                            
                        return APIResponse(
                          status=200,
                          content_type='application/json',
                          content=json.dumps({
                                  'state':state
                                  }),
                        )
                        
                    
                    elif action == 'run_nmap_script':
                        state = False
                        output = ''
                        try:
                            if 'script' in request.body and 'ifname' in request.body and 'target' in request.body:
                                state = self.adapter.run_nmap_script(str(request.body['script']), str(request.body['ifname']), request.body['target'])
                        except Exception as ex:
                            if self.DEBUG:
                                print("api handler: caught error in run_nmap_script: " + str(ex))
                                state = False
                        
                        return APIResponse(
                          status=200,
                          content_type='application/json',
                          content=json.dumps({'state':state,'output':self.adapter.script_outputs}),
                        )
                        
                    
                    else:
                        return APIResponse(
                            status=404,
                            content_type='application/json',
                            content=json.dumps("API error, invalid action"),
                        )
                        
                except Exception as ex:
                    if self.DEBUG:
                        print("Ajax issue: " + str(ex))
                    return APIResponse(
                        status=500,
                        content_type='application/json',
                        content=json.dumps("Error in API handler"),
                    )
                    
            else:
                if self.DEBUG:
                    print("invalid path: " + str(request.path))
                return APIResponse(status=404)
                
        except Exception as e:
            if self.DEBUG:
                print("Failed to handle UX extension API request: " + str(e))
            return APIResponse(
                status=500,
                content_type='application/json',
                content=json.dumps("General API Error"),
            )
        

