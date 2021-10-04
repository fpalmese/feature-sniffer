# Feature-Sniffer
This repo contains Feature-Sniffer, a tool for capturing traffic features on-the-fly in an Access Point with OpenWrt firmware.


# Installation:
- After installing OpenWrt in your Access Point, install the packages in requirements.txt with: 

```bash
opkg update && opkg install requirements.txt
```
- Copy the homeDirectory/forensics folder into your access point home folder (be sure that the shell scripts contained are set as executable)
- Copy the filesDirectory/forensics folder into your access point output folder (all the configurations and output will be stored here)
- Copy the "luci-app/controller/admin/forensics.lua" file in the "/usr/lib/lua/luci/controller/admin" folder in the Access Point
- Copy the "luci-app/view/forensics/features.htm" file in the "/usr/lib/lua/luci/view/forensics" in the Access Point
- Set your homeDirectory in the controller file (/usr/lib/lua/luci/controller/admin/forensics.lua), in the variable homeDirectory
- Compile the C package by following the [OpenWRT guide](https://openwrt.org/docs/guide-developer/helloworld/start), using the Makefile in the C/Makefile (adjust PATHs) and the files in the C/ folder
- Upload the compiled package into your access point (use scp or sftp for uploading) and install it with opkg
- You are now ready to use Feature-Sniffer through your Access Point control panel, in the Forensics section of LuCI web interface.
