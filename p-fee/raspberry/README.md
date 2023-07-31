Before following this guide, install [Nexmon CSI Extractor](https://github.com/seemoo-lab/nexmon_csi).

# File organization

The following file were in pi folder:
- df.py is the script which takes in input a pcap file, parses it to extract the CSI features and return a .csv file
- ex.py is the script which prepares Nexmon and starts/stops the CSI captures
- mqtt_subscriber.py is the script which connects to the broker and subscribes to the topics start, stop, prepare, download.

The file nex.sh, which automates the commands that needs to be repeated at each reboot, was instead insert in the "nexmon" folder, so to move it: 
```shell
mv nex.sh /home/pi/nexmon
```

To activate it open: 
```shell
nano /etc/rc.local
```
and insert a command which runs the nex.sh file by specifying its path.

# MQTT suscriber service 
We need a service which activates the script mqtt_subscriber.py. First you need to install mosquitto and paho-mqtt, then run the following commanfìds:
```shell
sudo cp mqtt_subscriber.service /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl enable mqtt_subscriber.service
sudo service mqtt_subscriber start
```
To check if it is running: 
```shell
service mqtt_subscriber status
```






