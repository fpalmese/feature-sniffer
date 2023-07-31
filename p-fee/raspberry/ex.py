#!/usr/bin/python3
import subprocess
import time
import os
import signal
import df
import re 

class NexmonManager:

	def __init__(self):
		self.pcap = None
		self.band = 20
		self.chan = 7
		self.add= ""
		self.cap_name = None
	
	# This function is called every time before starting the capture to retrieve the configuration settings
	def prepare(self, message):
		self.add = ""
		
		# Parse the channel
		settings = message.splitlines()
		channel = ""
		for char in settings[0]:
    			if (char.isnumeric()):
        			channel = channel + char
		self.chan = int(channel)
		#print(self.chan)

		# Parse the devices 
		if (len(settings)==2):
			no_brackets_add = re.search(r'\((.*?)\)',settings[1]).group(1)
			devices = no_brackets_add.replace('", "', ', ')
			devices = devices[1:-1]
			print(devices)
			if ("," in devices): 
				devices = devices.split(', ')	
			self.add = devices
			#print(self.add)

		print("Now Nexmon is monitoring channel " + str(self.chan) + " devices: " + str(self.add))

	# This function is called when the topic is "start" to configure Nexmon for the capture
	def configure(self):		
		string_out=""
		# if there are no devices to filter or if they are more than one, run the command without the device filter (in case of more devices, it is applied later on the dataframe)
		if self.add=="" or isinstance(self.add, list) : 
			proc = subprocess.run(
                                f"./makecsiparams -c {self.chan}/{self.band} -C 1 -N 1",
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                shell=True,
                                cwd='/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams',
                                text=True
                        )
			string_out = proc.stdout
		else: 
			proc = subprocess.run(
                		f"./makecsiparams -c {self.chan}/{self.band} -C 1 -N 1 -m {self.add}",
                		stdout=subprocess.PIPE,
                		stderr=subprocess.PIPE,
                		shell=True,
                		cwd='/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams',
                		text=True
        		)
			string_out = proc.stdout
		
		print(string_out)
		
		wpa = subprocess.run(
			f"sudo pkill wpa_supplicant",
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			shell=True,
			cwd='/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams',
			text=True
		)

		monitor_mode = subprocess.run("sudo iw phy `iw dev wlan0 info | gawk '/wiphy/ {printf \"phy\" $2}'` interface add mon0 type monitor && sudo ifconfig mon0 up",
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			shell=True,
			cwd='/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams',
			text=True
		)
		#print(a.returncode, a.stderr)
		proc2= subprocess.run(f"sudo ifconfig wlan0 up && sudo nexutil -Iwlan0 -s500 -b -l34 -v{string_out}",
			stdout=subprocess.PIPE, 
			stderr=subprocess.PIPE,  
			shell=True,
			cwd='/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams',
			text=True
		)
		#print(proc2.returncode)

	# This function is called when the topic is "start" to start the capture. The name of the capture is the payload of the message
	def capture(self, file_name):
		self.cap_name = file_name
		self.pcap = subprocess.Popen(
                        ["sudo","tcpdump", "-i", "wlan0", "-w", self.cap_name + ".pcap", "udp", "port", "5500"],
                        cwd='/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams',
                        preexec_fn=os.setsid
                )


	# This function is called when the topic is "stop" to stop the capture
	def stop(self):
		# kill the tcpdump
		os.killpg(os.getpgid(self.pcap.pid), signal.SIGINT)
		print('Capture stopped')

	# This function is called when the topic is "download" to download the .csv file 
	def download(self, file_name):
		self.cap_name = file_name 
		df.main(str(self.cap_name), self.add)	
