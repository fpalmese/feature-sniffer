The files in this folder are needed to control Nexmon from the web interface. So, first of all you need to install OpenWrt and the LuCI web interface on your access point, then: 
- insert csi.lua in the /usr/lib/lua/luci/controller/admin folder
- insert csi.htm in the /usr/lib/lua/luci/view/forensics folder

Pay attention that in the csi.lua file you need to change the address of the broker (after the -h flag) with the IP address of the Raspberry in every publication and subscription. 


