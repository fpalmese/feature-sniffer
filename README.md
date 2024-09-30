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

# Usage
Once the Feature-Sniffer has been installed, go into your access point control panel:
Go to the Forensics section and you will have the following homepage:
![home](https://user-images.githubusercontent.com/67421482/136516517-ac16a982-223a-4b61-89da-47d00a7e9018.png)
Create a new configuration with the button and insert your configuration parameters as you prefer. The configuration tab will be as follows:
![config](https://user-images.githubusercontent.com/67421482/136049439-2d8a724d-d33d-4f80-885b-0e1854cc071d.png)
Once your configuration is ready you can control it by using the control buttons in the homepage: Start, Stop, Output, Delete


# Public Dataset
CSI Datasets: https://polimi365-my.sharepoint.com/:f:/g/personal/10692910_polimi_it/EidULtKKJBROtWtvuj_vwfwBI5XSz-nhXqW6YaLDQK_G_w?e=TT3Kwi

Activity Recognition with Smart Cameras: https://polimi365-my.sharepoint.com/:f:/g/personal/10692910_polimi_it/EtV-T0IpA79Po33weynEUKcBnY9bApxKb-9nQYgPHFZvdw?e=CfhCTn



# Citation
If you use the proposed framework or the datasets in your research, please cite our work in IEEE Internet of Things Journal:

F. Palmese, A. E. C. Redondi and M. Cesana, "Designing a Forensic-Ready Wi-Fi Access Point for the Internet of Things," in IEEE Internet of Things Journal, 2023 doi: 10.1109/JIOT.2023.3304423
