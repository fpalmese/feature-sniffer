#!/usr/bin/python3
import csiread
import pandas as pd
import cmath
import paho.mqtt.client as mqtt
import subprocess
import os

def main (name, addresses):

	print(name, addresses)
	csifile = "/home/pi/nexmon/patches/bcm43455c0/7_45_189/nexmon_csi/utils/makecsiparams/" + name + ".pcap"
	csidata = csiread.Nexmon(csifile, chip='43455c0', bw=20)
	csidata.read()
	print(csidata.csi.shape)

	dataFrame = createDf(csidata, addresses)
	print(dataFrame)
	if (os.path.exists(name + '.csv')):
		try:
			os.remove(name + '.csv')
		except: 
			print("File not exists")
	dataFrame.to_csv (name + '.csv')	
	

	_ = subprocess.run(f"mosquitto_pub -t output -r -f {name}.csv",
		stdout=subprocess.PIPE,
	 	stderr=subprocess.PIPE,
		shell=True,
	 	text=True
	)		

# create the dataframe
def createDf(csidata, addresses):

	timestamp = []
	source_address = []
	csi = []
	frame_n = []
	phase = []
	magnitude = []
	subcarrier = []

	for i in range(0, csidata.csi.shape[0]):
		#time = pd.to_datetime((csidata.sec[i]+ csidata.usec[i] * 1e-6), unit='s').tz_localize(tz.tzlocal())
		time= csidata.sec[i]+ csidata.usec[i] * 1e-6
		timestamp.append(time)
		source_address.append(macString(csidata.src_addr[i]).upper())
		csi.append(csidata.csi[i])
		frame_n.append(csidata.seq[i])
		for j in range(0, csidata.csi.shape[1]):
			# assign the subcarriers: from 0 to 31 and then from -32 to -1
			if j<32:
				subcarrier.append(j)
			else:
				subcarrier.append(j-64)
			phase.append(cmath.phase(csidata.csi[i][j])) # phase of each csi data
			magnitude.append(abs(csidata.csi[i][j])) # magnitude of each csi data

	df = pd.DataFrame(list (zip(frame_n, timestamp, source_address, csi)), columns= ['Frame_num','Timestamp', 'Source_Address', 'CSI'])
	s= df.apply(lambda x: pd.Series(x['CSI']), axis=1).stack().reset_index(level=1, drop=True)
	s.name = 'CSI'
	df = df.drop('CSI', axis=1).join(s)
	df['CSI'] = pd.Series(df['CSI'], dtype=complex)
	df['Phase'] = phase
	df['Magnitude'] = magnitude
	df['Subcarrier'] = subcarrier
    
	if isinstance (addresses, list): 
	# cancello le righe dove gli addresses non sono tra quelli che devo filtrare
		df = df[df['Source_Address'].isin(addresses)]
    
	return df


# Convert MAC addresses
def macString(byteList):
    if len(byteList) != 6:
        string = ""
    else:
        string = str(format(byteList[0],'02x'))
        for i in range(1,6):
            string = string + ":" + str(format(byteList[i],'02x'))
    return string


