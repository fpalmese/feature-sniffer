#!/usr/bin/python3
import paho.mqtt.client as mqtt
import time
from ex import NexmonManager
import df
import subprocess

started = False
nm = NexmonManager()

def on_connect(client, userdata, flags, rc):
    print("Connected with result code " + str(rc))
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe([("start", 1), ("stop", 1), ("prepare", 1), ("download", 1) ])


def on_message(client, userdata, message):
	print("Message received: " + message.topic + " : " + str(message.payload.decode()))
	global started 
	if (message.topic == 'start' and started==False):
		proc = subprocess.run("cat /sys/class/net/wlan0/carrier",
        		stdout=subprocess.PIPE,
        		stderr=subprocess.PIPE,
        		shell=True,
        		text=True
        	)
		if (proc.returncode!=0):
        		print ("Connecting")
        		time.sleep(10)
		started = True
		nm.configure()
		nm.capture(str(message.payload.decode()))
	if (message.topic == 'stop' and started==True):
		nm.stop()
		started = False
	if (message.topic == 'download' and started==False):
		nm.download(str(message.payload.decode()))
	if (message.topic == 'prepare' and started==False):
		nm.prepare(message.payload.decode())

broker_address = "localhost"  # Broker address
port = 1883  # Broker port

client = mqtt.Client()  # create new instance
client.on_connect = on_connect  # attach function to callback
client.on_message = on_message  # attach function to callback

client.connect(broker_address, port=port)  # connect to broker

client.loop_forever()
