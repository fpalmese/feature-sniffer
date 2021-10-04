# Feature-Sniffer
This repo contains Feature-Sniffer, a tool for capturing traffic features on-the-fly in an Access Point with OpenWrt firmware.


# Installation:
-After installing OpenWrt in your Access Point, install the packages in requirements.txt with: 

```bash
opkg update && opkg install requirements.txt
```
- Copy the homeDirectory/features folder into your access point home folder (be sure that the shell scripts contained are set as executable)
- Copy the filesDirectory/features folder into your access point output folder
- Copy the "controller" in the /usr/lib/lua/luci/controller folder
- Copy the "view" folder in the /usr/lib/lua/luci/view 
- 
- Edit the controller file by setting your own homeDirectory path and filesDirectory path (directory that will contain the output and configurations)
- Compile the C package with the following steps:
    -Download from the OpenWrt the SDK for your system architecture
    -
    -
    - ...
- Upload the compiled package into your access point and install it with opkg
- You are now ready to use Feature-Sniffer
