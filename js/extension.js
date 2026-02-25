(function() {
	class NetworkScanner extends window.Extension {
	    constructor() {
	      	super('networkscanner');
			
			//console.log("Adding networkscanner addon to menu");
			this.addMenuEntry('Network Scanner');
            
			
			//console.log("window.API: ", window.API);
			
            this.debug = false;
            this.interval = null;
			this.avahi_lines = [];
			this.avahi_parsed = {};
			
			this.own_ip = null;
			this.own_hostname = null;
			this.spotted_candle_hostnames = {};
			
			this.ignore_candle_controllers = false;
			
			this.poll_timeouts = 0;
			this.scan_time_delta = 0;
			
			this.nmap_installed = false;
			this.nmap_scripts = [];
			this.script_outputs = {};
			this.last_script_outputs = '';
			this.found_vulnerabilities = {};
			
			this.showing_details_for = [];
			
			this.available_ips = {};
			this.previously_available_ips = null;
			this.previously_found = {};
			this.previous_previously_found = null;
			
			this.settled_count = 0;
			this.last_security_update_time = 0;
			this.waiting_two_minutes = null;
			
			//this.rescan_button_el = null;
			
			this.should_quick_scan = true;
			this.busy_doing_light_scan = true;
			this.busy_doing_brute_force_scan = false;
			this.busy_doing_security_scan = 0;
			
			this.previous_vulnerabilities_json = '';
			
			this.switch_candles_menu_el = null;
			this.menu_scrim_listener_added = false;

            // Kiosk?
			this.kiosk = false;
            if(document.getElementById('virtualKeyboardChromeExtension') != null){
                document.body.classList.add('kiosk');
                this.kiosk = true;
            }

            this.content = '';
			
			//console.log("this.id: ", this.id);
			
			fetch(`/extensions/${this.id}/views/content.html`)
	        .then((res) => res.text())
	        .then((text) => {
	         	this.content = text;
	  		 	if( document.location.href.endsWith(`extensions/${this.id}`) ){
	  		  		this.show(true);
	  		  	}
	        })
	        .catch((err) => console.error('networkscanner: failed to fetch content:', err));
            
            this.get_init_data();
            
			this.things = null;
			
			
			
			
			
	    }



		
		hide() {
			//console.log("networkscanner hide called");
			try{
                clearInterval(this.interval);
                this.interval = null;
			}
			catch(e){
				//console.log("internet radio: no interval to clear? " + e);
			}    
		}
        
        
        

	    show(first_page=false) {
			//console.log("networkscanner show called");
			//console.log("this.content:");
			//console.log(this.content);
			try{
				clearInterval(this.interval);
				this.interval = null;
			}
			catch(e){
				//console.log("no interval to clear?: " + e);
			}
            
			if(this.settled_count > 4){
				this.settled_count = 4;
			}else{
				this.settled_count = 0;
			}
            
			
			if(this.content == ''){
				//console.error("network scannere: error, content was empty");
				return;
			}
			this.view.innerHTML = this.content;
			
			this.showing_details_for = [];
			
			
			this.content_el = this.view.querySelector('#extension-networkscanner-content');
			this.scanning_progress_bar_el = this.view.querySelector('#extension-networkscanner-scanning-progress-bar');
			
			
			
            
            // Easter egg when clicking on title
            
			this.view.querySelector('#extension-networkscanner-title').addEventListener('click', (event) => {
                //this.scan();
				const music = new Audio('/extensions/networkscanner/audio/ping.mp3');
				music.loop = false;
				music.play();
				
				this.previously_available_ips = null;
				this.previous_previously_found = null;
				this.last_script_outputs = '';
				this.showing_details_for = [];
				this.settled_count = 0;
				this.regenerate_items();
			});
			
			this.view.querySelector('#extension-networkscanner-network-scan-animation').addEventListener('click', (event) => {
                //this.scan();
				const music = new Audio('/extensions/networkscanner/audio/ping.mp3');
				music.loop = false;
				music.play();
			});
            
			
			
            
			const rescan_button_el = this.view.querySelector('#extension-networkscanner-rescan-button');
			
			if(rescan_button_el){
				rescan_button_el.addEventListener('click', (event) => {
					this.scan();
				});
			}
			
			
			const security_scan_update_button_el = this.view.querySelector('#extension-networkscanner-security-update-button');
			
			if(security_scan_update_button_el){
				security_scan_update_button_el.addEventListener('click', (event) => {
	                security_scan_update_button_el.classList.add('extension-networkscanner-hidden');
					this.content_el.classList.add('extension-networkscanner-busy-doing-security-scan');
					
			        window.API.postJson(
			          `/extensions/${this.id}/api/ajax`,
		                {'action':'update_security_scan'}

			        ).then((body) => {
						if(this.debug){
							console.log("networkscanner debug: update security script response: ", body);
						}
						if(typeof body.state == 'boolean' && body.state == true){
							if(this.debug){
								console.log("networkscanner debug: update succeeded");
							}
						}
						else{
							security_scan_update_button_el.classList.remove('extension-networkscanner-hidden');
						}
						this.content_el.classList.remove('extension-networkscanner-busy-doing-security-scan');
					})
					.catch((err) => {
						if(this.debug){
							console.error("networkscanner debug: caught error calling update_security_scan: ", err);
						}
						security_scan_update_button_el.classList.remove('extension-networkscanner-hidden');
						this.content_el.classList.remove('extension-networkscanner-busy-doing-security-scan');
					})
					
				});
			}
			
			
			
			
			const full_security_scan_button_el = this.view.querySelector('#extension-networkscanner-full-security-scan-button');
			if(full_security_scan_button_el){
				full_security_scan_button_el.addEventListener('click', () => {
					const full_security_scan_interface_select_el = this.view.querySelector('#extension-networkscanner-full-security-scan-interface-select');
					if(full_security_scan_interface_select_el && full_security_scan_interface_select_el.value){
						if(this.debug){
							console.log("networkscanner debug: starting security scan on interface: ", full_security_scan_interface_select_el.value);
						}
						if(!this.content_el){
							this.content_el = this.view.querySelector('#extension-networkscanner-content');
						}
						if(this.content_el){
							this.content_el.classList.add('extension-networkscanner-busy-doing-security-scan');
						}
						
						this.run_nmap_script('vulners.nse',full_security_scan_interface_select_el.value);
					}
				})
			}
			
			
			API.getThings()
			.then((things) => {
				this.things = things;
				if(this.debug){
					console.log("networkscanner debug: this.things is now: ", this.things);
				}
				setTimeout(() => {
					this.poll();
				},100);
			})
			.catch((err) => {
				if(this.debug){
					onsole.error("networkscanner debug: show: caught error getting list of things from window.API: ", err);
				}
				setTimeout(() => {
					this.poll();
				},100);
			})
			
			
			
		}
		
		
		//
		//  POLL
		//
		
		poll(){
			if(this.debug){
				console.log("networkscanner debug: in poll");
			}
			
	        window.API.postJson(
	          `/extensions/${this.id}/api/ajax`,
                {'action':'poll'}

	        ).then((body) => {
                
				this.parse_api_response(body);
				this.poll_timeouts = 0;
				
	        }).catch((err) => {
				if(this.debug){
					console.warn("networkscanner debug: error getting poll data: ", err);
				}
	  			
				if(this.poll_timeouts < 6){
					this.poll_timeouts++;
				}
				else{
					document.getElementById('extension-networkscanner-overview-list').innerHTML = "<div id=\"extension-networkscanner-lost-connection-message\" class=\"extension-networkscanner-area\"><h2>Connection error</h2><p>Could not get latest data from the controller. Perhaps it's rebooting?</p></div>";
					this.available_ips = {};
					this.previously_found = {};
					this.avahi_lines = [];
				}
				
	        })
			.then(() => {
	            setTimeout(() => {
					if(window.location.href.endsWith(`/extensions/${this.id}`)){
						this.poll();
					}
					else{
						if(this.debug){
							console.log("networkscanner debug: user navigated away from Network Scanner page. Not calling this.poll again.");
						}
					}
	            },3000);
			})
			
		
		}
		
		
		
		
		
		
		
		//
		//  START SCAN
		//
	
		scan(){
			if(this.debug){
				console.log("networkscanner debug: requesting scan");
			}
			
			if(!this.content_el){
				this.content_el = this.view.querySelector('#extension-networkscanner-content');
			}
			if(this.content_el){
				this.content_el.classList.add('extension-networkscanner-busy-doing-network-scan');
			}
			
			if(!this.scanning_progress_bar_el){
				this.scanning_progress_bar_el = this.view.querySelector('#extension-networkscanner-scanning-progress-bar');
			}
			this.scanning_progress_bar_el.style.width = '0%';
			
			//document.getElementById('extension-networkscanner-rescan-button').style.display = 'none';
			
			// update list of known things
			API.getThings().then((things) => {
				this.things = things;
				if(this.debug){
					console.log("networkscanner debug: start scan: this.things is now: ", this.things);
				}
			})
			
	        window.API.postJson(
	          `/extensions/${this.id}/api/ajax`,
                {'action':'scan'}

	        ).then((body) => {
				
				if(typeof body.state == 'boolean' && body.state == true){
					if(this.content_el){
						this.content_el.classList.add('extension-networkscanner-busy-doing-network-scan');
					}
					//document.getElementById('extension-networkscanner-busy-scanning').style.display = 'block';
					//document.getElementById('extension-networkscanner-rescan-button').style.display = 'none';

					this.settled_count = 0;

					this.available_ips = null;
					this.previously_available_ips = null;
					this.previously_found = null;
					this.previous_previously_found = null;
					this.avahi_lines = [];
					
					document.getElementById('extension-networkscanner-overview-list').innerHTML = '';
	                
				}
				else{
					//document.getElementById('extension-networkscanner-busy-scanning').style.display = 'none';
					//document.getElementById('extension-networkscanner-rescan-button').style.display = 'block';
					if(this.content_el){
						this.content_el.classList.remove('extension-networkscanner-busy-doing-network-scan');
					}
				}
					
                
                
                
	        }).catch((err) => {
	  			console.error("network scanner: caught error requesting scan: ", err);
				//document.getElementById('extension-networkscanner-busy-scanning').style.display = 'none';
				document.getElementById('extension-networkscanner-overview-list').innerHTML = '<h2>Error</h2><p>A (connection) error occured</p>';
	        });	
			
		}
	
	
    	// Init
        get_init_data(){
	  		
	        window.API.postJson(
	          `/extensions/${this.id}/api/ajax`,
                {'action':'init'}

	        ).then((body) => {
                
                this.parse_api_response(body);
			
	        }).catch((err) => {
	  			console.error("networkscanner: caught error calling init: ", err);
	        });
        }


		parse_api_response(body){
            
			if(!this.content_el){
				this.content_el = this.view.querySelector('#extension-networkscanner-content');
			}
			
            if(typeof body.debug == 'boolean'){
				if(this.debug != body.debug){
					if(document.getElementById('extension-networkscanner-debug-warning') != null){
						this.debug = body.debug;
                    	if(this.debug){
                            document.getElementById('extension-networkscanner-debug-warning').style.display = 'block';
                        }
						else{
							document.getElementById('extension-networkscanner-debug-warning').style.display = 'none';
						}
                    }
				}
            }
			
			
			
			
			if(typeof body.ignore_candle_controllers == 'boolean'){
				this.ignore_candle_controllers = body.ignore_candle_controllers;
				//this.regenerate_items();
			}
			
			if(typeof body.nmap_installed == 'boolean'){
				this.nmap_installed = body.nmap_installed;
			}
			
			if(typeof body.nmap_scripts != 'undefined' && body.nmap_scripts != null){
				this.nmap_scripts = body.nmap_scripts;
				//console.log("init:  this.nmap_scripts is now: ", this.nmap_scripts);
			}
			
			if(typeof body.avahi_lines != 'undefined'){
				this.avahi_lines = body.avahi_lines;
				//this.regenerate_items();
			}
			
			if(typeof body.own_ip == 'string'){
				this.own_ip = body.own_ip;
			}
			
			if(typeof body.scan_time_delta != 'undefined'){
				this.scan_time_delta = body.scan_time_delta;
				if(this.debug){
					console.log("networkscanner debug: last periodic scan took: ", this.scan_time_delta + ' seconds');
				}
			}
			
			if(typeof body.waiting_two_minutes == 'boolean' && this.waiting_two_minutes == null){
				const waiting_two_minutes_hint_el = this.view.querySelector('extension-networkscanner-waiting-two-minutes-message');
				if(waiting_two_minutes_hint_el){
					if(body.waiting_two_minutes == true){
						waiting_two_minutes_hint_el.classList.remove('extension-networkscanner-hidden');
					}
					else{
						waiting_two_minutes_hint_el.classList.add('extension-networkscanner-hidden');
						this.waiting_two_minutes = false;
					}
				}
			}
			
			if(typeof body.controller_start_time == 'number' && this.waiting_two_minutes == null){
				const waiting_two_minutes_countdown_el = this.view.querySelector('extension-networkscanner-waiting-two-minutes-countdown');
				if(waiting_two_minutes_countdown_el){
					const elapsed_time_since_boot = (Date.now()/1000) - body.controller_start_time;
					if(elapsed_time_since_boot > 0 && elapsed_time_since_boot < 120){
						waiting_two_minutes_countdown_el.textContent = Math.floor(elapsed_time_since_boot) + ' seconds remaining';
					}
				}
			}
			
			
			
			if(typeof body.last_security_update_time == 'number'){
				if(body.last_security_update_time != this.last_security_update_time){
					if(this.debug){
						console.log("networkscanner debug: it seems the security defenitions were updated");
					}
					this.last_security_update_time = body.last_security_update_time;
					const last_securty_update_time_el = this.view.querySelector('#extension-networkscanner-security-last-update-time');
					if(last_securty_update_time_el){
						if(this.last_security_update_time == 0){
							last_securty_update_time_el.textContent = 'Never';
						}
						else{
							last_securty_update_time_el.textContent = new Date(parseInt(this.last_security_update_time) * 1000).toDateString();
						}
					}
				}
			}
			
			
			
			if(typeof body.should_quick_scan == 'boolean'){
				this.should_quick_scan = body.should_quick_scan;
			}
			if(typeof body.busy_doing_light_scan == 'boolean'){
				this.busy_doing_light_scan = body.busy_doing_light_scan;
			}
			if(typeof body.busy_doing_brute_force_scan == 'boolean'){
				this.busy_doing_brute_force_scan = body.busy_doing_brute_force_scan;
			}
			if(typeof body.busy_doing_security_scan == 'number'){
				this.busy_doing_security_scan = body.busy_doing_security_scan;
			}
			
			if(this.content_el){
				if(this.busy_doing_light_scan == false && this.busy_doing_brute_force_scan == false && this.should_quick_scan == false){
					this.content_el.classList.remove('extension-networkscanner-busy-doing-network-scan');
				}
				else{
					this.content_el.classList.add('extension-networkscanner-busy-doing-network-scan');
				}
			
				if(this.busy_doing_security_scan == 0){
					this.content_el.classList.remove('extension-networkscanner-busy-doing-security-scan');
				}
				else{
					this.content_el.classList.add('extension-networkscanner-busy-doing-security-scan');
				}
			}
			
			if(typeof body.quick_scan_phase == 'number'){
				//console.log("received quick_scan_phase: ", typeof body.quick_scan_phase, body.quick_scan_phase);
				if(!this.scanning_progress_bar_el){
					this.scanning_progress_bar_el = this.view.querySelector('#extension-networkscanner-scanning-progress-bar');
				}
				if(this.scanning_progress_bar_el){
					const width_percentage = (body.quick_scan_phase * 2) + '%';
					//console.log("updating progress bar width to: ", width_percentage);
					this.scanning_progress_bar_el.style.width = width_percentage;
				}
				this.quick_scan_phase = body.quick_scan_phase;
			}
			
			
			if(typeof body.available_ips != 'undefined' && typeof body.previously_found != 'undefined'){
				this.available_ips = body.available_ips;
				this.previously_found = body.previously_found;
				
				if(typeof body.pairing_done == 'boolean' && body.pairing_done == true){
					API.getThings()
					.then((things) => {
						this.things = things;
						this.regenerate_items();
					})
					.catch((err) => {
						if(this.debug){
							console.error("networkscanner debug: pairing done, but caught error getting list of things from window.API: ", err);
						}
					})
				}
				else{
					this.regenerate_items();
				}
				
			}
			
			
			if(typeof body.script_outputs != 'undefined'){
				if(this.last_script_outputs != JSON.stringify(body.script_outputs)){
					if(this.debug){
						console.log("networkscanner debug: script_outputs was different, calling show_script_outputs");
					}
					this.last_script_outputs = JSON.stringify(body.script_outputs);
					this.script_outputs = body.script_outputs;
					this.show_script_outputs();
				}
				else{
					if(this.debug){
						console.log("networkscanner debug: script_outputs was the same as before, not calling show_script_outputs");
					}
				}
			}
			
			
			if(this.kiosk == false && typeof body.own_hostname == 'string' && typeof body.spotted_candle_hostnames != 'undefined'){
				if(this.debug){
					console.log("networkscanner debug: body.own_hostname: ", body.own_hostname);
					console.log("networkscanner debug: body.spotted_candle_hostnames: ", body.spotted_candle_hostnames);
					console.log("networkscanner debug: this.switch_candles_menu_el: ", this.switch_candles_menu_el);
				}
				if(this.own_hostname != body.own_hostname || JSON.stringify(Object.keys(this.spotted_candle_hostnames)) != JSON.stringify(Object.keys(body.spotted_candle_hostnames))){
					this.own_hostname = body.own_hostname;
					this.spotted_candle_hostnames = body.spotted_candle_hostnames;
					this.update_switch_candles_menu();
				}
				else if(this.switch_candles_menu_el == null){
					this.update_switch_candles_menu();
				}
				else if(this.switch_candles_menu_el.innerHTML == ''){
					this.update_switch_candles_menu();
				}
				else{
					//console.log("update_switch_candles_menu should be ok"); 
				}
			}
			else{
				if(this.debug){
					console.warn("networkscanner debug: body.own_hostname or body.spotted_candle_hostname invalid: ", body.own_hostname, body.spotted_candle_hostname);
				}
			}
		}





		run_nmap_script(script_name=null,ifname=null,target=null){
			if(this.debug){
				console.log("networkscanner debug: in run_nmap_script.  script_name,ifname,target: ", script_name,ifname,target);
			}
			if(typeof script_name == 'string' && script_name != '' && typeof ifname == 'string' && ifname.length > 2){
				
		        window.API.postJson(
		          `/extensions/${this.id}/api/ajax`,
	                {'action':'run_nmap_script','script':script_name,'ifname':ifname,'target':target}

		        ).then((body) => {
					if(this.debug){
						console.warn("networkscanner debug: run_nmap_script: response body: ", body);
					}
					if(typeof body.state == 'boolean' && body.state == true){
						if(this.debug){
							console.log("networkscanner debug: security script running/ran");
						}
						if(typeof body.output != 'undefined'){
							if(this.debug){
								console.log("networkscanner debug: run_nmap_script: got body.output: ", body.output);
							}
							this.show_script_outputs(body.output);
						}
					}
					else{
						if(this.debug){
							console.warn("networkscanner debug: run_nmap_script state was not true");
						}
					}
					
					if(this.validate_ip(target) && typeof this.script_outputs[target] == 'undefined'){
						this.script_outputs[target] = "...";
					}
					
		        }).catch((err) => {
					if(this.debug){
						console.error("networkscanner debug: caught error (likely timeout) calling run_nmap_script: ", err);
					}
		        });
				
				return true
			}
			else{
				if(this.debug){
					console.error("networkscanner debug: invalid parameters provided.  script_name,target: ", script_name,target);
				}
			}
			return false
		}
    
	
    	show_script_outputs(script_output=null){
			if(script_output == null){
				script_output = this.script_outputs;
			}
    		if(this.debug){
				console.log("networkscanner debug: in show_script_outputs.  script_output to display: ", script_output);
			}
			
			if(script_output){
				
				function stripHtml(html)
				{
				   let tmp = document.createElement("DIV");
				   tmp.innerHTML = html;
				   return tmp.textContent || tmp.innerText || "";
				}
				
				for (const [ip, details] of Object.entries(script_output)) {
					if(this.debug){
						console.log("networkscanner debug: show_script_outputs: ip, details: ", ip, details);
					}
					if(typeof details.ifname == 'string'){
						if(this.debug){
							console.log("networkscanner debug: show_script_outputs: details.ifname: ", details.ifname);
						}
						if(details.ifname == ip){
							const interface_scan_output_el = this.view.querySelector('#extension-networkscanner-interface-security-scan-output');
							if(interface_scan_output_el){
								interface_scan_output_el.textContent = stripHtml(details.output);
								this.parse_security_scan_output(stripHtml(details.output), details.ifname);
							}
						}
						else{
							let output_el = this.view.querySelector('#extension-networkscanner-item-output-' + details.ifname + '-' + ip.replaceAll('.','-'));
							if(output_el && typeof details.output == 'string'){
								output_el.textContent = stripHtml(details.output); //details.output;
								output_el.parentNode.classList.remove('extension-networkscanner-waiting-for-output');
							}
							else{
								if(this.debug){
									console.error("networkscanner debug: invalid script output or output element not found.  typeof details.output, output_el: ", typeof details.output, output_el);
								}
							}
						}
						
					}
					else{
						if(this.debug){
							console.error("networkscanner debug: no ifname in script output.  ip, details: ", ip, details);
						}
					}
					
				}
			}
			
    	}
	
		parse_security_scan_output(all_lines, ifname=null){
			//console.log("in parse_security_scan_output. all_lines,ifname: ", typeof ifname, ifname, typeof all_lines, all_lines);
			
			if(typeof ifname != 'string'){
				console.error("networkscanner: parse_security_scan_output: no valid ifname provided");
				return
			}
			
			if( typeof all_lines == 'string' && all_lines.indexOf('Nmap scan report for ') != -1 && all_lines.indexOf('https://vulners.com/') != -1){
				
				let found_vulnerabilities = {};
				
				const all_lines_chunks = all_lines.split('Nmap scan report for ');
				//console.log("parse_security_scan_output: all_lines_chunks count: ", all_lines_chunks.length);
				for(let lc = 0; lc < all_lines_chunks.length; lc++){
					const device_lines = all_lines_chunks[lc].split('\n');
					
					//console.log("parse_security_scan_output: device_lines: ", device_lines);
					if(device_lines.length < 2){
						//console.log("parse_security_scan_output: skipping very short device: ", device_lines);
						continue
					}
					if(device_lines[0].indexOf('host down') != -1){
						//console.log("parse_security_scan_output: host down spotted, skipping: ", device_lines[0]);
						continue
					}
					else if(this.validate_ip(device_lines[0])){
						const device_ip = device_lines[0];
						//console.log("parse_security_scan_output: first device line is a valid ip: ", device_ip);
						
						found_vulnerabilities[device_ip] = {};
						
						if( all_lines_chunks[lc].indexOf('| vulners: ') != -1){
							const vulnerability_chunks = all_lines_chunks[lc].split('| vulners: ');
							//console.log("vulnerability_chunks: ", vulnerability_chunks);
						
							for(let vc = 0; vc < vulnerability_chunks.length; vc++){
								let lines = vulnerability_chunks[vc].split('\n');
								//console.log("lines: ", lines);
								let vulnerable_service_parts = [];
								
								if(lines[0].indexOf('cpe:') != -1){
									vulnerable_service_parts = lines[0].split(':');
								}
								else if(lines[1].indexOf('cpe:') != -1){
									vulnerable_service_parts = lines[1].split(':');
								}
									
							
								if(vulnerable_service_parts.length >= 5){
									
									let vulnerable_service_name = vulnerable_service_parts[3];
									if(vulnerable_service_parts[2] != vulnerable_service_parts[3]){
										vulnerable_service_name = vulnerable_service_parts[2] + " - " + vulnerable_service_name;
									}
									vulnerable_service_name = vulnerable_service_name + ' ' + vulnerable_service_parts[4] // version
									found_vulnerabilities[device_ip][vulnerable_service_name] = {'system':vulnerable_service_parts[2],'service':vulnerable_service_parts[3],'version':vulnerable_service_parts[4],'items':[]}
									
									
									for(let dl = 0; dl < lines.length; dl++){
										if(lines[dl].indexOf('https://vulners.com/') != -1 && lines[dl].indexOf('\t') != 1){
											let exploit_parts = lines[dl].split('\t');
											if(exploit_parts.length >= 3){
												const exploited = (lines[dl].indexOf('*EXPLOIT*') > -1) ? true : false;
												//console.log("exploited: ", typeof exploited, exploited);
												found_vulnerabilities[device_ip][vulnerable_service_name]['items'].push({'name':exploit_parts[1],'severity':exploit_parts[2],'url':exploit_parts[3],'exploit':exploited});

											}
											
										}
									}
								}
								
							}
						}
						
					}
					else{
						if(this.debug){
							console.warn("networkscanner debug: parse_security_scan_output: device fell through");
						}
					}
				}
				
				
				const vulnerabilities_json = JSON.stringify(found_vulnerabilities,null,4);
				if(vulnerabilities_json != this.previous_vulnerabilities_json){
					this.previous_vulnerabilities_json = vulnerabilities_json;
					this.found_vulnerabilities = found_vulnerabilities;
					if(this.debug){
						console.warn("networkscanner debug: FINAL this.found_vulnerabilities is now: ", this.found_vulnerabilities);
					}
					this.render_security_scan_output(ifname);
				}
				else{
					if(this.debug){
						console.log('found_vulnerabilities was the same as this.previous_found_vulnerabilities. Not re-rendering')
					}
				}
				
			}
			
		}
			
		
	
	
		render_security_scan_output(ifname=null){
		
			if(typeof ifname != 'string'){
				console.error("render_security_scan_output: no valid ifname provided");
				return
			}
		
			const interface_scan_nice_output_el = this.view.querySelector('#extension-networkscanner-interface-security-scan-nice-output');
			if(interface_scan_nice_output_el){
				interface_scan_nice_output_el.innerHTML = '';
				
				for (const [ip, services] of Object.entries(this.found_vulnerabilities)){
					
					const vulnerable_device_container_el = document.createElement('div');
					vulnerable_device_container_el.classList.add('extension-networkscanner-vulnerable-device-item');
					vulnerable_device_container_el.classList.add('extension-networkscanner-area');
					
					const vulnerable_device_title_el = document.createElement('h2');
					vulnerable_device_title_el.textContent = ip;
					
					if(typeof this.available_ips[ifname] != 'undefined' && typeof this.available_ips[ifname][ip] != 'undefined' && typeof this.available_ips[ifname][ip]['ip'] == 'string' && this.available_ips[ifname][ip]['ip'] == ip && typeof this.available_ips[ifname][ip]['hostname'] == 'string'){
						vulnerable_device_title_el.textContent = ip + ' - ' + this.available_ips[ifname][ip]['hostname'];
					}
					vulnerable_device_container_el.appendChild(vulnerable_device_title_el);
					
					
					for (const [service_name, service_details] of Object.entries(services)){
						//console.log("service_name, service_details: ", service_name, service_details);
						
						
						
						const vulnerable_device_service_container_el = document.createElement('details');
						vulnerable_device_service_container_el.classList.add('extension-networkscanner-vulnerable-device-service-item');
						
						const vulnerable_device_service_summary_el = document.createElement('summary');
						
						const vulnerable_device_service_title_el = document.createElement('h4');
						vulnerable_device_service_title_el.textContent = service_name;
						
						vulnerable_device_service_summary_el.appendChild(vulnerable_device_service_title_el);
						vulnerable_device_service_container_el.appendChild(vulnerable_device_service_summary_el);
						
						
						
						const vulnerable_device_service_list_el = document.createElement('ul');
						
						if(typeof service_details['items'] == 'undefined'){
							continue
						}
						
						let severity_summary = {'total':service_details['items'].length, 'high':0,'medium':0,'low':0};
						
						for (let ser = 0; ser < service_details['items'].length; ser++){
							//console.log("vulner: ", service_details['items'][ser]);
							const vulnerable_device_service_list_item_el = document.createElement('li');
							vulnerable_device_service_list_item_el.classList.add('extension-networkscanner-flex-wrap');
							vulnerable_device_service_list_item_el.classList.add('extension-networkscanner-flex-space-between');
							vulnerable_device_service_list_item_el.classList.add('extension-networkscanner-flex-center');
							
							let vulnerability_name_el = document.createElement('span');
							vulnerability_name_el.classList.add('extension-networkscanner-vulnerable-device-vulnerability-name');
							vulnerability_name_el.textContent = service_details['items'][ser]['name']
							vulnerable_device_service_list_item_el.appendChild(vulnerability_name_el);
							
							let vulnerability_link_wrapper_el = document.createElement('span');
							let vulnerability_link_el = document.createElement('span');
							if(this.kiosk){
								vulnerability_link_el.textContent = service_details['items'][ser]['url'];
							}
							else{
								vulnerability_link_el = document.createElement('a');
								vulnerability_link_el.classList.add('text-button');
								vulnerability_link_el.setAttribute('href', service_details['items'][ser]['url']);
								vulnerability_link_el.setAttribute('target', '_blank');
								vulnerability_link_el.setAttribute('rel', 'noreferrer');
								vulnerability_link_el.textContent = 'Details';
							}
							vulnerability_link_el.classList.add('extension-networkscanner-vulnerable-device-vulnerability-url');
							
							vulnerability_link_wrapper_el.appendChild(vulnerability_link_el);
							vulnerability_link_wrapper_el.classList.add('extension-networkscanner-vulnerable-device-vulnerability-url');
							vulnerable_device_service_list_item_el.appendChild(vulnerability_link_wrapper_el);
							
							const severity_number_el = document.createElement('span');
							severity_number_el.classList.add('extension-networkscanner-vulnerable-device-severity-score');
							severity_number_el.textContent = service_details['items'][ser]['severity'];
							severity_number_el.setAttribute('title','Severity');
							vulnerable_device_service_list_item_el.appendChild(severity_number_el);
							 
							if(service_details['items'][ser]['severity'] > 8){
								vulnerable_device_service_list_item_el.classList.add('extension-networkscanner-vulnerable-device-high-severity');
								severity_summary['high']++;
							}
							else if(service_details['items'][ser]['severity'] > 6){
								vulnerable_device_service_list_item_el.classList.add('extension-networkscanner-vulnerable-device-medium-severity');
								severity_summary['medium']++;
							}
							else{
								severity_summary['low']++;
							}
							
							
							const exploit_state_el = document.createElement('span');
							exploit_state_el.classList.add('extension-networkscanner-vulnerable-device-exploit');
							if(service_details['items'][ser]['exploit'] === true){
								exploit_state_el.textContent = '!';
								vulnerable_device_service_list_item_el.classList.add('extension-networkscanner-vulnerable-device-exploit-spotted');
							}else{
								exploit_state_el.textContent = '-';
							}
							vulnerable_device_service_list_item_el.appendChild(exploit_state_el);
							
							vulnerable_device_service_list_el.appendChild(vulnerable_device_service_list_item_el);
						}
						
						
						const severity_summary_wrapper_el = document.createElement('div');
						severity_summary_wrapper_el.classList.add('extension-networkscanner-vulnerable-device-summary')
						
						for (const [counter_key, counter_value] of Object.entries(severity_summary)) {
							const severity_counter_el = document.createElement('span');
							severity_counter_el.classList.add('extension-networkscanner-vulnerable-device-summary-' + counter_key);
							if(counter_key != 'total'){
								severity_counter_el.classList.add('extension-networkscanner-vulnerable-device-summary-sub-count');
							}
							severity_counter_el.textContent = counter_key + ': ' + counter_value;
							severity_summary_wrapper_el.appendChild(severity_counter_el);
						}
						vulnerable_device_service_summary_el.classList.add('extension-networkscanner-flex-wrap');
						vulnerable_device_service_summary_el.classList.add('extension-networkscanner-flex-space-between');
						vulnerable_device_service_summary_el.classList.add('extension-networkscanner-flex-center');
						vulnerable_device_service_summary_el.appendChild(severity_summary_wrapper_el);
						
						
						vulnerable_device_service_container_el.appendChild(vulnerable_device_service_list_el);
						
						vulnerable_device_container_el.appendChild(vulnerable_device_service_container_el);
					}
					
					interface_scan_nice_output_el.appendChild(vulnerable_device_container_el);
					
					
				}
			}
			
		}
	
	
	
	
		//
		//  REGENERATE ITEMS
		//
	
		regenerate_items(items=null, force=false){
			try {
				if(this.debug){
					//console.log("\nin regenerate_items");
				}
				
				
		        const overview_list_el = document.getElementById('extension-networkscanner-overview-list');
                if(overview_list_el == null){
					if(this.debug){
						console.error("networkscanner debug: regenerate_items: overview_list_el was null");
					}
                    return;
                }
				
				if(!this.content_el){
					this.content_el = this.view.querySelector('#extension-networkscanner-content');
				}
				
				
				//console.log("this.quick_scan_phase: ", this.quick_scan_phase);
				
				if(JSON.stringify(this.previously_found) == this.previous_previously_found && JSON.stringify(this.available_ips) == this.previously_available_ips && overview_list_el.innerHTML != '' && force == false){
					
					if(this.settled_count < 20){
						this.settled_count++;
						if(this.debug){
							console.log("networkscanner debug: content is settling.  this.settled_count: ", this.settled_count);
						}
					}
					
					if(this.settled_count == 10){
						//document.getElementById('extension-networkscanner-busy-scanning').style.display = 'none';
						//document.getElementById('extension-networkscanner-rescan-button').style.display = 'block';
						if(this.debug){
							console.log("networkscanner debug: regenerate items: detected devices seems to have settled");
						}
					}
					
					if(this.debug){
						//console.log("not regenerating content");
					}
					
					return
					
				}
				else{
					if(this.debug){
						console.log("networkscanner debug: regenerate items: content changed");
					}
					this.previous_previously_found = JSON.stringify(this.previously_found);
					this.previously_available_ips = JSON.stringify(this.available_ips);
					//document.getElementById('extension-networkscanner-busy-scanning').style.display = 'block';
					//document.getElementById('extension-networkscanner-rescan-button').style.display = 'none';
					this.settled_count = 0;
				}
				
				
				if(this.debug){
					//console.log("network scanner regenerating list. this.avahi_lines: ", this.avahi_lines);
				}
		        
                
				let avahi_parsed = {};
				let interfaces = {};
				
				
				// Generate HTML for detected devices
				
				const create_item_link = (url,title,css_class="") => {
					let target = '';
					if(this.kiosk == false){
						target = ' target="_blank"';
					}
					return '<a href="' + url + '" class="extension-networkscanner-list-item-link ' + css_class + '" rel="noreferer" ' + target + '>' + title + '</a>';
				}
				
				
				const info_tags = ['Google','Apple','Amazon','TP-Link','Asus','D-Link','Cisco','Belkin','Draytek','Edimax','Linksys','Netgear','GL.iNet','Sitecom','Ubiquiti','Zyxel','Xiaomi','Tuya','Expressif','Microtik','Buffalo','Acer','Lenovo','SMC','Tenda','Trendnet','Totolink','Hootoo','Amped','Synology','AudioAccessory','Printer','BorderRouter','HomePod','Sensor','XServe','Server','Router','MacBook','Laptop','Samba','Time Machine','Homebridge','Candle','Privacy','MQTT','Airplay','Android','iPhone','Samsung','Sony','Pixel','Fairphone','Motorola','OnePlus','Oppo','Honor'];
				const protocol_tags = ['Airplay'];
				
				if(this.avahi_lines.length == 0){
					if(this.debug){
						console.warn("networkscanner debug: no avahi data?");
					}
					//overview_list_el.innerHTML = '<p>Nothing found</p>';
				}
				else{
					
					
					// Extract useful information from Avahi data
                    for (var i = 0; i < this.avahi_lines.length; i++) {
						let line = this.avahi_lines[i];
						let item_html = '';
						if(line.startsWith('=')){
							if(this.debug){
								//console.log("");
								//console.log("networkscanner debug: avahi line: ", line);
							}
							let line_parts = line.split(';');
							
							if(this.debug){
								for (var j = 0; j < line_parts.length; j++) {
									//console.log(j, ": ", line_parts[j]);
								}
							}
							
							const device_id = line_parts[6];
							if(this.debug){
								//console.log("networkscanner debug: avahi device id: ", device_id);
							}
								
							if(device_id){
								if( typeof interfaces[line_parts[1]] == 'undefined'){
									interfaces[line_parts[1]] = [];
								}
								
								if(interfaces[line_parts[1]].indexOf(line_parts[7]) == -1){
									interfaces[line_parts[1]].push(line_parts[7]);
								}
								
								
								if( typeof avahi_parsed[device_id] == 'undefined'){
									avahi_parsed[device_id] = {
										'network_interfaces':[],
										'ports':{},
										'ipv4':false,
										'ipv6':false,
										'tags':[],
										'urls':[],
										'vendor':null,
										'name':'Unknown',
										'ip4':null,
										'ip6':{},
										'local_url':line_parts[6],
										'secure_admin_url':null,
										'admin_url':null,
										'admin_port':null,
										'secure_admin_port':null,
										'info':{}
									}
								}
								
								// Name
								if(line_parts[3].indexOf('Candle Homebridge') == -1 && line_parts[3].indexOf('CandleMQTT-') == -1){
									avahi_parsed[device_id]['name'] = line_parts[3];
								}
								
								
								
								// IP's
								if(typeof line_parts[7] == 'string'){
									if(this.validate_ip(line_parts[7])){
										avahi_parsed[device_id]['ip4'] = line_parts[7];
									}
									else if(line_parts[2] == 'IPv6'){
										if(typeof avahi_parsed[device_id]['ip6'][ line_parts[7] ] == 'undefined'){
											avahi_parsed[device_id]['ip6'][line_parts[7]] = {'ip6':line_parts[7],'ip6_source':'avahi'}
										}
									}
								}
								
								
								// Network interfaces
								if(avahi_parsed[device_id].network_interfaces.indexOf(line_parts[1]) == -1){
									avahi_parsed[device_id].network_interfaces.push(line_parts[1]);
								}
								
								// IPv4 and IPv6
								if(line_parts[2] == 'IPv4'){
									avahi_parsed[device_id].uses_ipv4 = true;
								}
								else if(line_parts[2] == 'IPv6'){
									avahi_parsed[device_id].has_ipv6 = true;
								}
								
								// port and protocol
								avahi_parsed[device_id].ports[line_parts[8]] = {'port':line_parts[8],'protocol':line_parts[4]}
								
								// info parts
								if(line_parts[9].indexOf('=' != -1)){
									let info_parts = line_parts[9].split('" "');
									for (var k = 0; k < info_parts.length; k++) {
										if(info_parts[k].startsWith('"')){info_parts[k] = info_parts[k].substr(1)}
										if(info_parts[k].endsWith('"')){info_parts[k] = info_parts[k].substr(0,info_parts[k].length-1)}
										if(this.debug){
											//console.log("networkscaner debug: avahi --info_part (useful for tags): ", info_parts[k]);
										}
										let info_key_val = info_parts[k].split('=');
										if(info_key_val[1] && info_key_val[1].length){
											avahi_parsed[device_id]['info'][info_key_val[0]] = info_key_val[1];
											if(info_key_val[0] == 'admin_url'){
												avahi_parsed[device_id].admin_url = info_key_val[1];
											}
											else if(info_key_val[0] == 'adminurl'){
												avahi_parsed[device_id].admin_url = info_key_val[1];
											}
											else if(info_key_val[0] == 'secure_admin_url'){
												avahi_parsed[device_id].secure_admin_url = info_key_val[1];
											}
											else if(info_key_val[0] == 'admin_port'){
												avahi_parsed[device_id].admin_port = info_key_val[1];
											}
											else if(info_key_val[0] == 'secure_admin_port'){
												avahi_parsed[device_id].secure_admin_port = info_key_val[1];
											}
											else if(info_key_val[0] == 'url'){
												if(avahi_parsed[device_id].urls.indexOf(info_key_val[1]) == -1){
													avahi_parsed[device_id].urls.push(info_key_val[1]);
												}
											}
											else if(info_key_val[0] == 'model'){
												avahi_parsed[device_id].model = info_key_val[1];
											}
											// tags extracted from info fields
											for (var l = 0; l < info_tags.length; l++) {
												if(info_key_val[1].toLowerCase().indexOf(info_tags[l].toLowerCase()) != -1){
													if(avahi_parsed[device_id]['tags'].indexOf(info_tags[l]) == -1){
														avahi_parsed[device_id]['tags'].push(info_tags[l]);
													}
												}
											}
										}
									}
								}
								
								// tags extracted from network protocol
								for (var m = 0; m < protocol_tags.length; m++) {
									if(line_parts[4].indexOf(protocol_tags[m]) != -1){
										if(avahi_parsed[device_id].tags.indexOf(protocol_tags[m]) == -1){
											avahi_parsed[device_id].tags.push(protocol_tags[m]);
										}
									}
								}
								
								// tags extracted from name
								for (var l = 0; l < info_tags.length; l++) {
									if(line_parts[3].toLowerCase().indexOf(info_tags[l].toLowerCase()) != -1){
										if(avahi_parsed[device_id]['tags'].indexOf(info_tags[l]) == -1){
											avahi_parsed[device_id]['tags'].push(info_tags[l]);
										}
									}
								}
								
								
							}
							else{
								if(this.debug){
									console.warn("no valid device ID: ", line_parts[7]);
								}
							}
							
						}
						
                    }
					
					if(this.debug){
						console.warn("network scanner avahi_parsed: ", avahi_parsed);
					}
					this.avahi_parsed = avahi_parsed;
					//for (const [hostname, avahi_details] of Object.entries(this.avahi_parsed)) {
						
					//}
					
					
					
					
				} // End of parsing avahi lines
				
				
				if(this.available_ips){
					overview_list_el.innerHTML = '';
					
					let found_thing_ids = [];
					
					// This is the full security scan select for the complete interface scan
					let full_security_scan_interface_select_el = document.createElement('select');
					full_security_scan_interface_select_el.classList.add('text-button');
					full_security_scan_interface_select_el.setAttribute('id','extension-networkscanner-full-security-scan-interface-select');
					
					const now_stamp = Date.now();
				
					for (const [ifname, interface_details] of Object.entries(this.available_ips)) {
						if(this.debug){
							console.log("networkscanner debug: ifname: ", ifname);
						}
				
						let interface_container_el = document.createElement("div");
						interface_container_el.classList.add('extension-networkscanner-interface-container');
				
						
				
						for (let [device_name, device] of Object.entries(interface_details)) {
							
							
							// Check if this device is muted or if tracking is disabled. 
							// If so, then it should not be shown as the result of a scan either.

							//console.warn("this.previously_found: ", this.previously_found);

							let should_skip = false;
							for (const [thing_id, previously_found_details] of Object.entries(this.previously_found)) {
								if(
									
									(typeof device.thing_id == 'string' && device.thing_id == thing_id) || 
									(typeof device.ip == 'string' && typeof previously_found_details['ip'] == 'string' && device.ip == previously_found_details['ip']) || 
									(typeof device.mac == 'string' && typeof previously_found_details['mac'] == 'string' && device.mac == previously_found_details['mac']) ||
									(typeof device.hostname == 'string' && typeof previously_found_details['hostname'] == 'string' && device.hostname == previously_found_details['hostname'])
								){
									// device thing_id or IP and/or MAC and/or hostname matches
									//console.warn("MATCH with previously_found.  thing_id, previously_found_details: ", thing_id, previously_found_details,"\ndevice_name, device:" ,device_name, device);
									if(typeof previously_found_details['data_collection'] == 'boolean' && previously_found_details['data_collection'] == false){
										should_skip = true;
										if(this.debug){
											//console.warn("not showing this device because it's data_collection is switched off");
										}
										break
									}
									else if(typeof previously_found_details['data_mute_end_time'] == 'number' && previously_found_details['data_mute_end_time'] > now_stamp / 1000){
										should_skip = true;
										if(this.debug){
											//console.warn("not showing this device because it's muted");
										}
										break
									}
									else{
										//console.warn("device may be shown: ", JSON.stringify(device,null,2));
									}
								}
							}
							//console.warn("should_skip: ", should_skip);
							if(should_skip){
								continue
							}
							
							let item_wrapper_el = document.createElement("div");
							item_wrapper_el.classList.add('extension-networkscanner-list-item');
							
							let item_top_el = document.createElement("div");
							item_top_el.classList.add('extension-networkscanner-list-item-top');
							
							let item_bottom_el = document.createElement("div");
							item_bottom_el.classList.add('extension-networkscanner-list-item-bottom');
							
							//let item_footer_menu_el = document.createElement('div');
							//item_footer_menu_el.classList.add('extension-networkscanner-item-footer-tabs');
							
							let security_container_output_el = document.createElement('div');
							security_container_output_el.classList.add('extension-networkscanner-item-security-output');
							if(typeof device.ip == 'string'){
								security_container_output_el.setAttribute('id','extension-networkscanner-item-output-' + ifname + '-' + device.ip.replaceAll('.','-')); //+ ifname + '-'
							}
							
							
							// for device with a stable mac address the mac_id will be the thing_id.
							if(typeof device['mac_id'] == 'string' && found_thing_ids.indexOf(device['mac_id']) == -1){
								found_thing_ids.push(device['mac_id']);
							}
							// for devices with better privacy protection they may have a thing_id based on a mac address that no longer exists
							if(typeof device['thing_id'] == 'string' && found_thing_ids.indexOf(device['thing_id']) == -1){
								found_thing_ids.push(device['thing_id']);
							}
							
							if(typeof device['thing_id'] == 'string'){
								if(this.debug){
									console.warn("networkscanner debug: THING ID SPOTTED: ", device['thing_id'], device);
								}
							}
							
							
							if(this.ignore_candle_controllers === true && typeof device.candle == 'boolean' && device.candle == true){
								if(this.debug){
									console.log("networkscanner debug: skipping Candle device because ignore_candle_controllers was true");
								}
								continue
							}
							
							const my_ifname = ifname;
							
							let my_ip4 = null;
							if(typeof device.ip == 'string' && this.validate_ip(device.ip)){
								my_ip4 = device.ip;
								if(this.debug){
									console.warn("networkscanner debug: this.own_ip:", ifname, this.own_ip);
								}
								if(this.own_ip != null){
									if(typeof this.own_ip == 'string' && this.own_ip == device.ip){
										item_wrapper_el.classList.add('extension-networkscanner-list-item-self');
									}
									else if(Array.isArray(this.own_ip) && 
										(
											(typeof device.ip == 'string'  && this.own_ip.indexOf(device.ip) != -1) || 
											(typeof device.ip6 == 'string' && this.own_ip.indexOf(device.ip6) != -1) 
											// TODO: device.ip6 is a dictionary
										)
									){
										item_wrapper_el.classList.add('extension-networkscanner-list-item-self');
									}
								}
								
							}
								
							let link_url = null;
							
							// Name, which can be hostname, or if that's not availble, the IP address
							let name_link_el = document.createElement("a");
							let name_el = document.createElement("h3");
							name_el.classList.add('extension-networkscanner-list-item-title');
							
							if(typeof device.hostname == 'string' && device.hostname.length > 2){
								name_el.innerText = device.hostname;
								name_link_el.appendChild(name_el);
								if(this.kiosk == false){
									name_link_el.setAttribute('href', 'http://' + device.hostname );
									name_link_el.target='_blank';
									name_link_el.rel='norefferer';
								}
								item_top_el.appendChild(name_link_el);
								if(typeof device.ip == 'string' && device.ip.indexOf('.') != -1 && link_url != device.ip){
									// IP4 address
									
									let ip4_el = document.createElement("div");
									if(this.kiosk == false){
										ip4_el = document.createElement("a");
										ip4_el.href = 'http://' + device.ip;
										ip4_el.target='_blank';
										ip4_el.rel='norefferer';
									}
									ip4_el.classList.add('extension-networkscanner-list-item-ip4');
									ip4_el.innerText = device.ip;
									item_top_el.appendChild(ip4_el);
									
									
								}
							}
							else if(typeof device.ip == 'string' && this.validate_ip(device.ip)){
								name_el.innerText = device.ip;
								if(this.kiosk == false){
									name_link_el.appendChild(name_el);
									name_link_el.setAttribute('href', 'http://' + device.ip );
									name_link_el.target='_blank';
									name_link_el.rel='norefferer';
									item_top_el.appendChild(name_link_el);
								}
								else{
									item_top_el.appendChild(name_el);
								}
								
							}
							else{
								// This should never happen
								name_el.innerText = 'Unnamed';
								item_top_el.appendChild(name_el);
							}
							
							
							
							
							
							
							
							
							
							if(typeof device.hostname == 'string'){
								if(this.debug){
									console.log("networkscanner debug: device.hostname: ", device.hostname);
								}
								const avahi_keys = Object.keys(this.avahi_parsed);
								if(this.debug){
									console.log("networkscanner debug: this.avahi_parsed keys: ", avahi_keys);
								}
								for(let k = 0; k < avahi_keys.length; k++){
									if(avahi_keys[k].toLowerCase() == device.hostname){
										if(this.debug){
											console.log("networkscanner debug: avahi hostname match: ", device.hostname);
										}
										const avahi_attribute_keys = Object.keys(this.avahi_parsed[avahi_keys[k]]);
										if(this.debug){
											console.log("networkscanner debug: avahi_attribute_keys: ", avahi_attribute_keys);
										}
										for(let ak = 0; ak < avahi_attribute_keys.length; ak++){
											const current_key = avahi_attribute_keys[ak];
											if(current_key == 'tags' && typeof device[current_key] != 'undefined'){
												
												for(let at = 0; at < this.avahi_parsed[avahi_keys[k]][current_key].length; at++){
													if(device[current_key].indexOf( this.avahi_parsed[avahi_keys[k]][current_key][at] ) == -1){
														if(this.debug){
															//console.log("networkscanner debug: copying tag from avahi: ", this.avahi_parsed[avahi_keys[k]][current_key][at], " to: ", device['tags']);
														}
														device['tags'].push(this.avahi_parsed[avahi_keys[k]][current_key][at])
													}
												}
											}
											else if(current_key == 'ports' && typeof device[current_key] != 'undefined'){
												for(let at = 0; at < this.avahi_parsed[avahi_keys[k]][current_key].length; at++){
													if(device[current_key].indexOf( this.avahi_parsed[avahi_keys[k]][current_key][at] ) == -1){
														if(this.debug){
															console.log("networkscanner debug: copying tag from avahi: ", this.avahi_parsed[avahi_keys[k]][current_key][at], " to: ", device['tags']);
														}
														device['tags'].push(this.avahi_parsed[avahi_keys[k]][current_key][at])
													}
												}
											}
											else if(current_key == 'ip6' && typeof device[current_key] != 'undefined'){
												device[current_key] = { ...device[current_key], ...this.avahi_parsed[avahi_keys[k]][current_key] };
											}
											else if(['mac','ip','hostname'].indexOf(current_key) != -1){
												// don't even think about adding these if they are somehow missing
											}
											else if(typeof device[current_key] == 'undefined' || (typeof device[current_key] == 'string' && typeof this.avahi_parsed[avahi_keys[k]][current_key] == 'string' && device[current_key].toLowerCase().indexOf('candle') == -1 && this.avahi_parsed[avahi_keys[k]][current_key].toLowerCase.indexOf('candle') != -1)){
												if(this.debug){
													//console.log("networkscanner debug: copying avahi current_key to device: -->" + current_key + "<--", this.avahi_parsed[avahi_keys[k]][current_key]);
												}
												device[current_key] = this.avahi_parsed[avahi_keys[k]][current_key];
												
											}
											else{
												if(this.debug){
													console.log("networkscanner debug:not copying this data from avahi: ", current_key, this.avahi_parsed[avahi_keys[k]][current_key]);
												}
											}
										}
										
										//device = { ...device, ...this.avahi_parsed[avahi_keys[k]] };
										if(this.debug){
											console.log("networkscanner debug: device with avahi details added: ", device);
										}
										break
									}
								}
							}
							
							
							if(typeof device.ip6 == 'object' && device.ip6 != null){
								for (const [ip6_address, ip6_details] of Object.entries(device.ip6)) {
									
									let ip6_el = document.createElement('div');
									if(this.kiosk == false){
										ip6_el = document.createElement('a')
										ip6_el.href = 'http://[' + ip6_address + ']';
										ip6_el.target='_blank';
										ip6_el.rel='norefferer';
									}
									ip6_el.classList.add('extension-networkscanner-list-item-ip6');
									ip6_el.textContent = ip6_address;
									if( !(ip6_address.startsWith('fe80:') || ip6_address.startsWith('fc00:') || ip6_address.startsWith('fd00:')) ){
										ip6_el.classList.add('extension-networkscanner-list-item-tag-danger');
									}
									item_top_el.appendChild(ip6_el);
								}
								
							}
							
							
					
							if(typeof device.mac == 'string' && device.mac.indexOf(':') != -1){
								let mac_el = document.createElement("div");
								mac_el.setAttribute('title','MAC address');
								mac_el.classList.add('extension-networkscanner-list-item-mac');
								mac_el.innerText = device.mac;
								item_top_el.appendChild(mac_el);
							}
							
							if(typeof device.previous_mac_addresses != 'undefined' && Array.isArray(device.previous_mac_addresses) && device.previous_mac_addresses.length > 0){
								if(this.debug){
									console.log("networkscanner debug: device.previous_mac_addresses.length: ", device.previous_mac_addresses.length);
								}
								let mac_changes_el = document.createElement("div");
								mac_changes_el.textContent = 'This devices seems to periodically change its MAC address';
								mac_changes_el.classList.add('extension-networkscanner-list-item-mac-changes');;
								
								mac_changes_el.addEventListener('click', () => {
									mac_changes_el.innerHTML = '<p class="extension-networkscanner-list-item-mac-changes-explanation">Frequent MAC address changes are a form of privacy protection. Though as you can see here, if its IP address and/or hostname remain the same, it can still be tracked.</p>';
									for(let pmc = 0; pmc < device.previous_mac_addresses.length; pmc++){
										let mac_changes_item_el = document.createElement("div");
										const mac_timestamp_change_date = new Date(device.previous_mac_addresses[pmc]['change_detection_timestamp'] * 1000)
										mac_changes_line = device.previous_mac_addresses[pmc]['mac'] + ' on ' + mac_timestamp_change_date.toString();
										mac_changes_el.appendChild(mac_changes_item_el);
									}
								})
								item_top_el.appendChild(mac_changes_el);
							}
							
							
							
							if(typeof device.mac_vendor == 'string' && device.mac_vendor.length > 1){
								let mac_vendor_el = document.createElement("div");
								mac_vendor_el.setAttribute('title','Device vendor according to MAC address');
								mac_vendor_el.classList.add('extension-networkscanner-list-item-mac-vendor');
								mac_vendor_el.innerText = device.mac_vendor;
								item_top_el.appendChild(mac_vendor_el);
							}
							
							if(typeof device.model == 'string' && device.model.length > 4){
								let model_el = document.createElement("div");
								model_el.setAttribute('title','Model');
								model_el.classList.add('extension-networkscanner-list-item-model');
								model_el.innerText = device.model;
								item_top_el.appendChild(model_el);
							}
							
							if(typeof device.message == 'string' && device.message.length > 1){
								let message_el = document.createElement("div");
								message_el.classList.add('extension-networkscanner-list-item-message');
								message_el.textContent = device.message;
								item_top_el.appendChild(message_el);
							}
							
							
							// Add tags
							if(typeof device.tags == 'undefined'){
								device.tags = [];
							}
							
							if(typeof device.mac_vendor == 'string'){
								const lowercase_mac_vendor = device.mac_vendor.toLowerCase();
								for (var l = 0; l < info_tags.length; l++) {
									if(lowercase_mac_vendor.indexOf(info_tags[l].toLowerCase()) != -1 && device.tags.indexOf(info_tags[l]) == -1){
										device.tags.unshift(info_tags[l]);
									}
								}
							}
							
							if(device.tags.length){
								// first, improve the tags
								if(device.tags.indexOf('XServe') != -1){
									if(device.tags.indexOf('Server') == -1){
										device.tags.push('Server');
									}
									device.tags.splice(device.tags.indexOf('XServe'), 1);
								}
								if(device.tags.indexOf('Samba') != -1){
									if(device.tags.indexOf('File server') == -1){
										device.tags.push('File server');
									}
									device.tags.splice(device.tags.indexOf('Samba'), 1);
								}
								if(device.tags.indexOf('MQTT') != -1){
									if(device.tags.indexOf('MQTT Server') == -1){
										device.tags.push('MQTT Server');
									}
									device.tags.splice(device.tags.indexOf('MQTT'), 1);
								}
								if(device.tags.indexOf('Router') != -1 && device.tags.indexOf('BorderRouter') != -1){
									device.tags.splice(device.tags.indexOf('Router'), 1);
								}
					
								if(device.tags.indexOf('MacBook') != -1 && device.tags.indexOf('Apple') == -1){
									device.tags.push('Apple');
								}
								//console.log("improved avahi device tags: ", device.tags);
							}
							if(device.tags.indexOf('Candle') != -1 && device.tags.indexOf('candle') != -1 && typeof device.candle == 'boolean' && device.candle == true){
								device.tags.push('Candle');
							}
							
							
							if(device.tags.length){
								if(this.debug){
									console.log("networkscanner debug: device tags: ", device.tags);
								}
							}
							
					
							// icons background
							let icon_el = document.createElement("div");
							icon_el.classList.add('extension-networkscanner-list-item-background-icon');
						
							if(device.tags.length){
								if(device.tags.indexOf('Candle') != -1){
									icon_el.classList.add('extension-networkscanner-list-item-background-icon-candle');
									item_top_el.appendChild(icon_el);
								}
								else if(device.tags.indexOf('Printer') != -1){
									icon_el.classList.add('extension-networkscanner-list-item-background-icon-printer');
									item_top_el.appendChild(icon_el);
								}
								else if(device.tags.indexOf('MacBook') != -1 || device.tags.indexOf('Laptop') != -1){
									icon_el.classList.add('extension-networkscanner-list-item-background-icon-laptop');
									item_top_el.appendChild(icon_el);
								}
								else if(device.tags.indexOf('Music') != -1 || device.tags.indexOf('AudioAccessory') != -1){
									icon_el.classList.add('extension-networkscanner-list-item-background-icon-audio');
									item_top_el.appendChild(icon_el);
								}
								else if(device.tags.indexOf('Server') != -1 || device.tags.indexOf('Synology') != -1){
									icon_el.classList.add('extension-networkscanner-list-item-background-icon-server');
									item_top_el.appendChild(icon_el);
								}
								else if(device.tags.indexOf('Router') != -1 || device.tags.indexOf('IPv6 Router') != -1 || (device.tags.indexOf('Web server') != -1 && device.tags.indexOf('DNS server') != -1 && device.ip.endsWith('.1')) ){
									icon_el.classList.add('extension-networkscanner-list-item-background-icon-router');
									item_top_el.appendChild(icon_el);
								}
					
					
								// Tags
								let tags_container_el = document.createElement("div");
								tags_container_el.classList.add('extension-networkscanner-list-item-tags');
								for (var k = 0; k < device.tags.length; k++) {
									let tag_el = document.createElement("span");
									tag_el.classList.add('extension-networkscanner-list-item-tag');
									tag_el.classList.add('extension-networkscanner-list-item-tag-' + device.tags[k].toLowerCase().replaceAll(' ','-') );
									if(device.tags[k] == 'Google' || device.tags[k] == 'Amazon' || device.tags[k] == 'Facebook'){
										tag_el.classList.add('extension-networkscanner-list-item-tag-danger');
									}
									if(device.tags[k] == 'SSH Server'){
										tag_el.classList.add('extension-networkscanner-list-item-tag-warning');
									}
									tag_el.innerText = device.tags[k];
									tags_container_el.appendChild(tag_el);
								}
								item_top_el.appendChild(tags_container_el);
							}
							
							
							
							
							
							
							if(typeof device.thing_id == 'string' && device.thing_id.startsWith('presence-')){
								
								if(this.check_if_thing_exists(device.thing_id)){
									if(this.debug){
										console.log("networkscanner debug: tracking: THING_ID: FOUND IN ACCEPTED THINGS: ", device.thing_id);
									}
									let thing_id_el = document.createElement("a");
									thing_id_el.classList.add('text-button');
									thing_id_el.classList.add('extension-networkscanner-list-item-thing-id');
									const thing_href = '/things/' + device.thing_id;
									thing_id_el.innerText = 'Tracking device presence';
									thing_id_el.setAttribute('href',thing_href);
									item_bottom_el.appendChild(thing_id_el);
									
								}
								else{
									if(this.debug){
										console.log("networkscanner debug: tracking: THING_ID: -NOT- FOUND IN THINGS");
									}
									let thing_id_el = document.createElement("div");
									thing_id_el.classList.add('extension-networkscanner-list-item-add-thing-button');
									thing_id_el.classList.add('extension-networkscanner-hide-while-network-scanning');
									
									//let add_thing_button_el = document.createElement("div");
									//add_thing_button_el.classList.add('extension-networkscanner-list-item-add-thing-button-icon');
									
									let add_thing_text_el = document.createElement("span");
									add_thing_text_el.innerText = 'Add new tracking thing';
									thing_id_el.appendChild(add_thing_text_el);
									//thing_id_el.appendChild(add_thing_button_el);
									
									thing_id_el.addEventListener('click', () => {
										setTimeout(() => {
											document.getElementById('add-button').click();
										},0);
									})
									
									item_bottom_el.appendChild(thing_id_el);
								}
								
							}
							else if(typeof device.ip == 'string' && typeof device.mac == 'string' && typeof device.mac_id == 'string'){
								let add_thing_button_el = document.createElement("button");
								add_thing_button_el.classList.add('extension-networkscanner-list-item-track-thing-button');
								add_thing_button_el.classList.add('text-button');
								add_thing_button_el.innerText = 'Track presence';
								add_thing_button_el.addEventListener('click', () => {
									add_thing_button_el.style.display = 'none'
									let item = {'ip':device.ip,'mac':device.mac,'id':device.mac_id}
									if(typeof device.hostname == 'string'){
										item['hostname'] = device.hostname;
									}
									if(typeof device.thing_id == 'string'){
										item['id'] = device.thing_id;
									}
									
							        window.API.postJson(
							          `/extensions/${this.id}/api/ajax`,
						                {'action':'track_thing','ifname':ifname,'details':item}

							        ).then((body) => {
										if(this.debug){
											console.warn('networkscanner debug: track_thing response body: ', body);
										}
										
							        }).catch((err) => {
							  			if(this.debug){
											console.error("networkscanner debug: caught error calling track_thing: ", err);
										}
							        });
								})
								item_bottom_el.appendChild(add_thing_button_el);
							}
							
					
							if(typeof device.secure_admin_url == 'string'){
								// Admin URL
								let admin_url = null;
								if(device.secure_admin_url){
									admin_url = device.secure_admin_url;
									if(!admin_url.startsWith('http')){admin_url = 'https://' + admin_url}
									if(device.secure_admin_port){
										const port_part = ':' + device.secure_admin_port;
										if(device.secure_admin_url.indexOf(port_part) == -1){
											let slash_count = device.secure_admin_url.split("/").length - 1;
											if(slash_count == 2 && !device.secure_admin_url.endsWith(port_part)){
												admin_url = admin_url + port_part;
											}else{
												//const base_url = 
												// TODO: insert the port if need be, or append it if possible
											}
										}
										
										
									}
								}
								else if(device.secure_admin_port){
									admin_url = device.local_url + ':' + device.secure_admin_port;
									if(!admin_url.startsWith('http')){admin_url = 'https://' + admin_url}
								}
								else if(device.admin_url){
									admin_url = device.admin_url;
									if(!admin_url.startsWith('http')){admin_url = 'http://' + admin_url}
								}
								else if(device.admin_port){
									admin_url = device.local_url + ':' + device.admin_port;
									if(!admin_url.startsWith('http')){admin_url = 'http://' + admin_url}
								}
								if(admin_url){
									let admin_el = document.createElement("div");
									admin_el.classList.add('extension-networkscanner-list-item-admin-link');
									admin_el.innerHTML = create_item_link(admin_url,'Administration','text-button');
									item_bottom_el.appendChild(admin_el);
								}
							}
					
					
							
							
							
								
								
								
								
							//
							//  ADD SECURITY AREA
							//
						
						
							if(this.nmap_installed && this.nmap_scripts && my_ifname && my_ip4){
								
								// contains the select element
								const security_container_el = document.createElement('div');
								security_container_el.classList.add('extension-networkscanner-item-security-container');
								security_container_el.classList.add('extension-networkscanner-fade-while-network-scanning');
								security_container_el.classList.add('extension-networkscanner-fade-while-security-scanning');
								
								if(typeof this.script_outputs[my_ip4] != 'undefined'){
									if(this.script_outputs[my_ip4] == 'Running scan...'){
										security_container_el.classList.add('extension-networkscanner-waiting-for-output');
									}
								}
								else{
									security_container_el.classList.add('extension-networkscanner-hidden');
								}
								
								item_bottom_el.appendChild(security_container_el);
							
								
							
								// Show security button
								let show_security_button_el = document.createElement("button");
								show_security_button_el.classList.add('extension-networkscanner-list-item-show-security-button');
								show_security_button_el.classList.add('extension-networkscanner-fade-while-network-scanning');
								
								show_security_button_el.classList.add('text-button');
								show_security_button_el.innerText = 'Security scan';
								show_security_button_el.addEventListener('click', () => {
									if(!my_ip4){
										console.error("Security scan button click: invalid my_ip4: ", my_ip4);
										return
									}
									security_container_el.classList.remove('extension-networkscanner-hidden');
									
								
								})
							
								item_bottom_el.appendChild(show_security_button_el);
							
								//show_security_button_el.remove();
								security_container_el.innerHTML = '<p>Which scan would you like to run?</p>';
								
								// ITEM SECURITY SCAN BUTTON
								let item_full_security_scan_button_el = document.createElement("button");
								item_full_security_scan_button_el.classList.add('text-button');
								item_full_security_scan_button_el.classList.add('extension-networkscanner-item-full-security-scan-button');
								item_full_security_scan_button_el.classList.add('extension-networkscanner-fade-while-network-scanning');
								item_full_security_scan_button_el.textContent = 'Vulnerability scan';
								item_full_security_scan_button_el.addEventListener('click', () => {
									
									if(this.run_nmap_script('vulners.nse',my_ifname, my_ip4)){
										if(!this.content_el){
											this.content_el = this.view.querySelector('#extension-networkscanner-content');
										}
										if(this.content_el){
											this.content_el.classList.add('extension-networkscanner-simple-row-view');
										}
										//security_container_el.scrollIntoView();
										setTimeout(() => {
											security_container_el.scrollIntoView({behavior: "smooth", block: "start"});
										},100);
										
									}
								})
								security_container_el.appendChild(item_full_security_scan_button_el);

								// ITEM information SCAN BUTTON
								let item_full_information_scan_button_el = document.createElement("button");
								item_full_information_scan_button_el.classList.add('text-button');
								item_full_information_scan_button_el.classList.add('extension-networkscanner-item-full-security-scan-button');
								item_full_information_scan_button_el.classList.add('extension-networkscanner-fade-while-network-scanning');
								item_full_information_scan_button_el.textContent = 'Information scan';
								item_full_information_scan_button_el.addEventListener('click', () => {
									if(this.run_nmap_script('-A',my_ifname, my_ip4)){
										if(!this.content_el){
											this.content_el = this.view.querySelector('#extension-networkscanner-content');
										}
										if(this.content_el){
											this.content_el.classList.add('extension-networkscanner-simple-row-view');
										}
										//security_container_el.scrollIntoView();
										//security_container_output_el.scrollIntoView({behavior: "smooth", block: "center"});
										setTimeout(() => {
											security_container_el.scrollIntoView({behavior: "smooth", block: "start"});
										},100);
									}
								})
								security_container_el.appendChild(item_full_information_scan_button_el);
								
								
								
								// ITEM security scan SHOW SELECT BUTTON
								let item_security_show_more_scan_button_el = document.createElement("button");
								item_security_show_more_scan_button_el.classList.add('text-button');
								item_security_show_more_scan_button_el.classList.add('extension-networkscanner-item-security-show-more-button');
								item_security_show_more_scan_button_el.classList.add('extension-networkscanner-fade-while-network-scanning');
								item_security_show_more_scan_button_el.textContent = 'Advanced';
								item_security_show_more_scan_button_el.addEventListener('click', () => {
									item_security_show_more_scan_button_el.remove();
								})
								security_container_el.appendChild(item_security_show_more_scan_button_el);
								
								
								
								// ITEM PRECISION SCANS SELECT
								let security_select_el = document.createElement('select');
							
								let first_security_option_el = document.createElement('option');
								first_security_option_el.setAttribute('value','');
								first_security_option_el.textContent = '-';
								first_security_option_el.setAttribute('selected',true);
								security_select_el.appendChild(first_security_option_el);
							
								let vulners_security_option_el = document.createElement('option');
								vulners_security_option_el.setAttribute('value','vulners.nse');
								vulners_security_option_el.textContent = 'VULNERABILITY SCAN';
								security_select_el.appendChild(vulners_security_option_el);
								
								let information_security_option_el = document.createElement('option');
								information_security_option_el.setAttribute('value','-A');
								information_security_option_el.textContent = 'INFORMATION SCAN';
								security_select_el.appendChild(information_security_option_el);
								
								let empty_security_option_el = document.createElement('option');
								empty_security_option_el.setAttribute('value','');
								empty_security_option_el.textContent = '';
								security_select_el.appendChild(empty_security_option_el);
								
								this.nmap_scripts.sort();
								
								for(let sc = 0; sc < this.nmap_scripts.length; sc++){
									let security_option_el = document.createElement('option');
									security_option_el.setAttribute('value',this.nmap_scripts[sc]);
									security_option_el.textContent = this.nmap_scripts[sc].replace('.nse','').replaceAll('_',' ');
									security_select_el.appendChild(security_option_el);
								}
								// Dropdown to select nmap script
								security_select_el.addEventListener('change', () => {
									if(this.debug){
										console.log("networkscanner debug: security_select_el changed to: ", security_select_el.value);
										console.log("networkscanner debug: my_ip4: ", my_ip4);
									}
									
									if(this.run_nmap_script(security_select_el.value, my_ifname, my_ip4)){
										security_container_el.classList.add('extension-networkscanner-waiting-for-output');
										security_container_output_el.innerHTML = '<div class="extension-networkscanner-spinner"><div></div><div></div><div></div><div></div></div>';
										
										if(!this.content_el){
											this.content_el = this.view.querySelector('#extension-networkscanner-content');
										}
										if(this.content_el){
											this.content_el.classList.add('extension-networkscanner-simple-row-view');
										}
										security_container_output_el.scrollIntoView({behavior: "smooth", block: "center"});
									}
									else{
										security_container_output_el.innerHTML = 'Error, could not run scan';
									}
								})
								security_container_el.appendChild(security_select_el);
							
								item_bottom_el.appendChild(security_container_el);
								

							}
							
							item_bottom_el.appendChild(security_container_output_el);
							
							let security_container_output_copy_button_el = document.createElement("div");
							security_container_output_copy_button_el.classList.add('extension-networkscanner-list-item-security-output-copy-button');
							security_container_output_copy_button_el.textContent = 'Copy';
							security_container_output_copy_button_el.addEventListener('click', () => {
								this.clip(security_container_output_el);
								security_container_output_copy_button_el.classList.add('extension-networkscanner-list-item-tag-ok');
								setTimeout(() => {
									security_container_output_copy_button_el.classList.remove('extension-networkscanner-list-item-tag-ok');
								},1000);
							})
							item_bottom_el.appendChild(security_container_output_copy_button_el);
							
							// Add info details
							let details_container_el = document.createElement("div");
							details_container_el.classList.add('extension-networkscanner-list-item-details');
							
							if(typeof device.ip == 'string' && this.showing_details_for.indexOf(device.ip) == -1){
								details_container_el.classList.add('extension-networkscanner-hidden');
							}
					
							if(typeof device.urls != 'undefined' || typeof device.ports != 'undefined' || typeof device.info != 'undefined' || typeof device.ip4_services != 'undefined' || typeof device.ip6_services != 'undefined'){
								
								// More details button
								let expand_button_el = document.createElement("button");
								expand_button_el.classList.add('extension-networkscanner-list-item-show-details-button');
								expand_button_el.classList.add('text-button');
								expand_button_el.innerText = 'More details';
								expand_button_el.addEventListener('click', () => {
									expand_button_el.remove();
									
									if(typeof device.ip == 'string'){
										this.showing_details_for.push(device.ip)
									}
									
									
									if(details_container_el){
										details_container_el.classList.remove('extension-networkscanner-hidden');
									}
									else{
										if(this.debug){
											console.error("networkscanner debug: could not find details element to reveal");
										}
									}
									
								});
								if(typeof device.ip == 'string' && this.showing_details_for.indexOf(device.ip) == -1){
									item_bottom_el.appendChild(expand_button_el);
								}
								//console.log("added more details button to item_footer_menu_el? ", item_footer_menu_el);
					
					
								
					
								if(typeof device.urls != 'undefined'){
									// Add links
									let links_container_el = document.createElement("ul");
									links_container_el.classList.add('extension-networkscanner-list-item-links');
									for (var p = 0; p < device.urls.length; p++) {
										let link_el = document.createElement("li");
										link_el.classList.add('extension-networkscanner-list-item-link');
										link_el.innerHTML = create_item_link(device.urls[p],device.urls[p]);
										links_container_el.appendChild(link_el);
									}
									details_container_el.appendChild(links_container_el);
								}
							
								
								const service_protocols = [4,6];
								for(let sp = 0; sp < service_protocols.length; sp++){
									const device_attribute_name = 'ip' + service_protocols[sp] + '_services';
									
									const service_title_el = document.createElement('h4');
									service_title_el.textContent = 'IPv' + service_protocols[sp] + ' ports';
									service_title_el.classList.add('extension-networkscanner-list-item-ip-services-title');
									
									
									if(typeof device[device_attribute_name] != 'undefined' && Object.keys(device[device_attribute_name]).length){
										details_container_el.appendChild(service_title_el);
										
										// Add ipX_services details
										let ip_services_container_el = document.createElement("ul");
										ip_services_container_el.classList.add('extension-networkscanner-list-item-ip-services-list');
										ip_services_container_el.classList.add('extension-networkscanner-list-item-ip' + service_protocols[sp] + '-services');
										for (const [service, service_details] of Object.entries(device[device_attribute_name])) {
											let service_el = document.createElement("li");
										
											if(this.debug){
												//console.log("networkscanner debug: ipX, service, service_details: ", service_protocols[sp], service, service_details);
											}
											for (const [service_attribute, service_attribute_value] of Object.entries(service_details)) {
											
												if(this.debug){
													//console.log("networkscanner debug:  - ipX service_attribute, service_attribute_value: ", service_attribute, service_attribute_value);
												}
												let service_attribute_container_el = document.createElement("div");
												service_attribute_container_el.classList.add('extension-networkscanner-list-item-port-' + service_attribute);
												/*
												let service_attribute_el = document.createElement("span");
												service_attribute_el.classList.add('extension-networkscanner-list-item-service-key');
												service_attribute_el.classList.add('extension-networkscanner-list-item-service-key-' + service_attribute);
												service_attribute_el.innerText = service_attribute;
												service_el.appendChild(service_attribute_el);
											
												service_attribute_container_el.appendChild(service_attribute_el);
												*/
												let service_value_el = document.createElement("span");
												service_value_el.setAttribute('title',service_attribute);
												service_value_el.classList.add('extension-networkscanner-list-item-service-value');
												service_value_el.classList.add('extension-networkscanner-list-item-service-value-' + service_attribute_value);
												service_value_el.innerText = service_attribute_value;
												service_el.appendChild(service_value_el);
											
												service_attribute_container_el.appendChild(service_value_el);
											
												service_el.appendChild(service_attribute_container_el);
											}
										
											ip_services_container_el.appendChild(service_el);
										}
										details_container_el.appendChild(ip_services_container_el);
									}
									
								}
								
							
							
								if(typeof device.ports != 'undefined'){
									// Add port details
									let ports_container_el = document.createElement("ul");
									ports_container_el.classList.add('extension-networkscanner-list-item-ports');
									for (const [port, port_details] of Object.entries(device.ports)) {
										let port_el = document.createElement("li");
										
										if(this.kiosk == false){
											let port_nr_el = document.createElement("a");
											port_nr_el.classList.add('extension-networkscanner-list-item-port-nr');
											port_nr_el.innerText = port;
											port_nr_el.href = 'http://' + device.local_url + ':' + port;
											port_nr_el.target='_blank';
											port_nr_el.rel='norefferer';
											port_el.appendChild(port_nr_el);
										}
										else{
											let port_nr_el = document.createElement("span");
											port_nr_el.classList.add('extension-networkscanner-list-item-port-nr');
											port_nr_el.innerText = port;
											port_el.appendChild(port_nr_el);
										}
						
										let protocol_el = document.createElement("span");
										protocol_el.classList.add('extension-networkscanner-list-item-port-protocol');
										protocol_el.innerText = port_details.protocol;
										port_el.appendChild(protocol_el);
						
										ports_container_el.appendChild(port_el);
									}
									details_container_el.appendChild(ports_container_el);
								}
								
								
							
								if(typeof device.info != 'undefined'){
									// Add info key-value pairs
									let info_container_el = document.createElement("ul");
									info_container_el.classList.add('extension-networkscanner-list-item-info');
									for (const [info_key, info_value] of Object.entries(device.info)) {
										let info_el = document.createElement("li");
						
										let info_key_el = document.createElement("span");
										info_key_el.classList.add('extension-networkscanner-list-item-info-key');
										info_key_el.innerText = info_key;
										info_el.appendChild(info_key_el);
						
										let info_value_el = document.createElement("span");
										info_value_el.classList.add('extension-networkscanner-list-item-info-value');
										info_value_el.innerText = info_value;
										info_el.appendChild(info_value_el);
						
										info_container_el.appendChild(info_el);
									}
									details_container_el.appendChild(info_container_el);
								}
					
					
							}
							
							
							item_bottom_el.appendChild(details_container_el);
		
							item_wrapper_el.appendChild(item_top_el);
							item_wrapper_el.appendChild(item_bottom_el);
		
							interface_container_el.append(item_wrapper_el);
						}
						
						
						let title = ifname;
						if(ifname == 'uap0'){
							title = 'Hotspot';
						}
						else if(ifname == 'eth0'){
							title = 'Wired connection';
						}
						else if(ifname == 'eth1'){
							title = 'Wired connection 2';
						}
						else if(ifname == 'wlan0' || ifname == 'mlan0'){
							title = 'WiFi connection';
						}
						else if(ifname == 'wlan1' || ifname == 'mlan1'){
							title = 'WiFi connection 2';
						}
						else if(ifname == 'usb0'){
							title = 'USB Tethering';
						}
						else if(ifname == 'usb1'){
							title = 'USB Tethering 2';
						}
					
						if(interface_container_el.innerHTML == ''){
							interface_container_el.innerHTML = '<div class="extension-networkscanner-list-item extension-networkscanner-list-item-self"><div class="extension-networkscanner-spinner"><div></div><div></div><div></div><div></div></div></div>';
						}
						else{
							// Add full security scan interface select option
							let full_security_scan_interface_select_option_el = document.createElement('option');
							full_security_scan_interface_select_option_el.setAttribute('value',ifname);
							full_security_scan_interface_select_option_el.textContent = title;
							full_security_scan_interface_select_el.appendChild(full_security_scan_interface_select_option_el);
						}
						
						
						if(this.debug){
							console.log("networkscanner debug: adding interface title: ", title);
						}
						const interface_title_el = document.createElement('h3');
						interface_title_el.classList.add('extension-networkscanner-interface-container-title');
						interface_title_el.textContent = title;
						overview_list_el.appendChild(interface_title_el);
						
						overview_list_el.appendChild(interface_container_el);
						
						
						this.show_script_outputs();
					
					} // End of regenerating network items
					
					
					
					const full_security_scan_interface_select_container_el = this.view.querySelector('#extension-networkscanner-full-security-scan-interface-select-container');
					if(full_security_scan_interface_select_container_el){
						full_security_scan_interface_select_container_el.innerHTML = '';
						if(full_security_scan_interface_select_el.children){
							const security_map_image_el = this.view.querySelector('#extension-networkscanner-map-image');
							full_security_scan_interface_select_el.addEventListener('change', () => {
								if(security_map_image_el){
									if(full_security_scan_interface_select_el.value == 'uap0'){
										security_map_image_el.setAttribute('src','/extensions/networkscanner/images/candle_network_scanner_map_hotspot.svg');
									}
									else{
										security_map_image_el.setAttribute('src','/extensions/networkscanner/images/candle_network_scanner_map_home.svg');
									}
								}
							})
							full_security_scan_interface_select_container_el.appendChild(full_security_scan_interface_select_el);

						}
					}
						
					
					
					if(this.debug){
						console.log("networkscanner debug: all found_thing_ids: ", found_thing_ids);
					}
					
					const missing_items_container_el = this.view.querySelector('#extension-networkscanner-missing-list');
					missing_items_container_el.innerHTML = '';
					
					for (const [thing_id, details] of Object.entries(this.previously_found)) {
						if(found_thing_ids.indexOf(thing_id) == -1){
							if(this.debug){
								console.log("networkscanner debug: previously_found device that was not found (yet) in the scan: ", thing_id, details);
							}
							const missing_item_el = document.createElement('div');
							missing_item_el.classList.add('extension-networkscanner-list-item');
							missing_item_el.classList.add('extension-networkscanner-missing-list-item');
							
							let missing_html = '';
							if(typeof details.hostname == 'string'){
								missing_html = missing_html + '<h4>' + details.hostname + '</h4>';
							}
							if(typeof details.ip == 'string'){
								missing_html = missing_html + '<p>' + details.ip + '</p>';
							}
							if(typeof details.mac == 'string'){
								missing_html = missing_html + '<p>' + details.mac + '</p>';
							}
							
							if(typeof details.candle == 'boolean' && details.candle == true){
								missing_html = missing_html + '<p>Candle controller</p>';
							}
							else if(typeof details.mac_vendor == 'string'){
								missing_html = missing_html + '<p>' + details.mac_vendor + '</p>';
							}
							missing_item_el.innerHTML = missing_html;
							missing_items_container_el.appendChild(missing_item_el);
						}
					}
					
				}
				
			}
			catch (err) {
				console.error("Network scanner: caught error in regenerate_items: ", err); // pass exception object to error handler
			}
		}
	
    
	
	
	
	
	
	
	
	
	
		
		update_switch_candles_menu(){
			if(this.kiosk == true){
				return
			}
			if(this.debug){
				console.log("networkscanner debug: in update_switch_candles_menu. own_hostname, spotted_candle_hostnames: ", this.own_hostname, this.spotted_candle_hostnames);
			}
			let candle_hostnames = [];
			
			for (const [candle_hostname, candle_hostname_details] of Object.entries(this.spotted_candle_hostnames)) {
				if(candle_hostname == this.own_hostname){
					console.log("networkscanner debug: update_switch_candles_menu: skipping own hostname: ", this.own_hostname);
					continue
				}
				candle_hostnames.push(candle_hostname);
				/*
				if(typeof candle_hostname_details['last_spotted'] == 'number' && candle_hostname_details['last_spotted'] > (Date.now() / 1000) - 300){
					console.log("update_switch_candles_menu: OK, this hostname was spotted recently: ", candle_hostname);
					candle_hostnames.push(candle_hostname);
				}
				else{
					console.log("update_switch_candles_menu: skipping hostname that was spotted a while ago... ", candle_hostname);
				}
				*/
			}
			if(this.debug){
				console.log("networkscanner debug: update_switch_candles_menu: candle_hostnames: ", candle_hostnames);
			}
			if(candle_hostnames.length){ // TODO:    > 1
				candle_hostnames.sort();
				if(this.debug){
					console.log("networkscanner debug: update_switch_candles_menu: candle_hostnames: ", candle_hostnames);
				}
				if(!this.switch_candles_menu_el){
					if(this.debug){
						console.log("switch_candles_menu_el did not exist?");
					}
					this.switch_candles_menu_el = document.getElementById('extension-networkscanner-switch-candles-menu');
				}
				if(this.debug){
					console.log("networkscanner debug: this.switch_candles_menu_el? ", typeof this.switch_candles_menu_el, this.switch_candles_menu_el);
				}
				if(this.switch_candles_menu_el){
					if(this.debug){
						console.log("networkscanner debug: weird, this.switch_candles_menu_el suddenly exists?", this.switch_candles_menu_el);
					}
				}
				else{
					if(this.debug){
						console.log("networkscanner debug: update_switch_candles_menu: creating and inserting switch candles container");
					}
					const main_menu_wordmark_el = document.getElementById('menu-wordmark');
					if(main_menu_wordmark_el){
						if(this.debug){
							console.log("networkscanner debug: update_switch_candles_menu: found the word-mark element");
						}
						this.switch_candles_menu_el = document.createElement('div');
						this.switch_candles_menu_el.setAttribute('id','extension-networkscanner-switch-candles-menu');
						main_menu_wordmark_el.insertAdjacentElement('afterend', this.switch_candles_menu_el);
					}
					else{
						//console.error("networkscanner debug: update_switch_candles_menu: wordmark el not found");
					}
				}
				if(this.switch_candles_menu_el){
					//console.log("clearing switch_candles_menu_el html first before redrawing");
					this.switch_candles_menu_el.innerHTML = '';
					
					const switch_candles_own_item_el = document.createElement('div');
					switch_candles_own_item_el.classList.add('extension-networkscanner-center');
					
					const switch_candles_own_item_span_el = document.createElement('span');
					switch_candles_own_item_span_el.textContent = this.own_hostname.replace('.local','');
					switch_candles_own_item_el.appendChild(switch_candles_own_item_span_el);
					
					switch_candles_own_item_el.addEventListener('click', () => {
						if(this.switch_candles_menu_el.classList.contains('extension-networkscanner-switch-candles-menu-expanded')){
							window.location.reload(true); // reload and clear html cache
						}
						else{
							this.switch_candles_menu_el.classList.add('extension-networkscanner-switch-candles-menu-expanded');
						}
						
					});
					this.switch_candles_menu_el.appendChild(switch_candles_own_item_el);
					
					
					const switch_other_candles_list_el = document.createElement('ol');
					for(let ch = 0; ch < candle_hostnames.length; ch++){
						
						const switch_other_candles_item_el = document.createElement('li');
						
						const switch_other_candles_item_link_el = document.createElement('a');
						switch_other_candles_item_link_el.textContent = candle_hostnames[ch].replace('.local','');
						
						let other_candle_url = location.protocol + '//' + candle_hostnames[ch];
						if(other_candle_url.indexOf('.') == -1){
							other_candle_url += '.local';
						}
						if(this.debug){
							console.log("networkscanner debug: other_candle_url: ", other_candle_url);
						}
						switch_other_candles_item_link_el.setAttribute('href',other_candle_url);
						switch_other_candles_item_link_el.addEventListener('click', () => {
							document.getElementById('connectivity-scrim').classList.remove('hidden');
						})
						
						switch_other_candles_item_el.appendChild(switch_other_candles_item_link_el);
						
						switch_other_candles_list_el.appendChild(switch_other_candles_item_el);
					}
					this.switch_candles_menu_el.appendChild(switch_other_candles_list_el);
					
				}
				else{
					if(this.debug){
						console.error("networkscanner debug: still no this.switch_candles_menu_el: ", this.switch_candles_menu_el);
					}
				}
			}
			else if(this.switch_candles_menu_el){
				if(this.debug){
					console.warn("networkscanner debug: update_switch_candles_menu: other candle controller(s) disappeared. Removing switch candles menu.");
				}
				this.switch_candles_menu_el.remove();
				this.switch_candles_menu_el = null;
			}
			
			if(this.menu_scrim_listener_added == false){
				this.menu_scrim_listener_added = true;
				const menu_scrim_el = document.getElementById('menu-scrim');
				if(menu_scrim_el){
					menu_scrim_el.addEventListener('click', () => {
						if(this.debug){
							console.log("networkscanner debug: clicked on menu scrim");
						}
						if(!this.switch_candles_menu_el){
							this.switch_candles_menu_el = document.getElementById('extension-networkscanner-switch-candles-menu');
						}
						if(this.switch_candles_menu_el){
							this.switch_candles_menu_el.classList.remove('extension-networkscanner-switch-candles-menu-expanded');
						}
						else{
							if(this.debug){
								console.error("networkscanner debug:  click on menu scrim: switch_candles_menu_el was still null");
							}
						}
					})
				}
				
			}
			
		}
		
		
		
		//
		//  HELPER FUNCTIONS
		//
		
		check_if_thing_exists(thing_id){
			if(typeof thing_id == 'string' && thing_id.startsWith('presence-')){
				for(let t = 0; t < this.things.length; t++){
					if(typeof this.things[t]['href'] == 'string' && this.things[t]['href'].endsWith('/' + thing_id)){
						return true
						break
					}
				}
			}
			else{
				if(this.debug){
					console.error("networkscanner debug: check_if_thing_exists: invalid thing_id provided: ", typeof thing_id, thing_id);
				}
			}
			return false
		}
	
	
    
        // Copy to clipboard
        clip(element) {
			if(typeof element == 'string'){
				element = this.view.querySelector('#' + element_id);
			}
			if(element){
	            var range = document.createRange();
	            range.selectNode(element);
	            window.getSelection().removeAllRanges(); // clear current selection
	            window.getSelection().addRange(range); // to select text
	            document.execCommand("copy");
	            window.getSelection().removeAllRanges();// to deselect
	            //alert("Copied to clipboard");
			}
            
        }
    
		// Validate IP address
		validate_ip(ip){
			if(typeof ip != 'string'){
				return false
			}
			var ipformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
			return ip.match(ipformat)
		}
	
    
    }

	new NetworkScanner();
	
})();


