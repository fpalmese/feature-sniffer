module("luci.controller.admin.forensics",package.seeall)
homeDirectory = "/home/forensics"

filesDirectory = tostring(luci.sys.exec("cat "..homeDirectory.."/init/baseDirectory")):gsub("\n", "")


function index()
	entry({"admin", "forensics"}, alias("/admin/forensics/forensics/features"), "Forensics", 30).dependent=true
	entry({"admin", "forensics","forensics","capture"}, cbi("forensics/capture"), "Traffic Capture", 30).dependent=true
	entry({"admin", "forensics", "forensics","features"}, template("forensics/features"), ("Feature Sniffer")).leaf = true
	entry({"admin", "forensics", "forensics","save_config"},call("handle_save_config"),nil)
	entry({"admin", "forensics", "forensics","open_existing_config"},call("handle_open_existing_config"),nil)
	entry({"admin", "forensics", "forensics","start_existing_config"},call("handle_start_existing_config"),nil)
	--entry({"admin", "forensics", "forensics","start_existing_config_python"},call("handle_start_existing_config_python"),nil)
	entry({"admin", "forensics", "forensics","stop_existing_config"},call("handle_stop_existing_config"),nil)
	entry({"admin", "forensics", "forensics","delete_existing_config"},call("handle_delete_existing_config"),nil)
	entry({"admin", "forensics", "forensics","check_output_readiness"},call("handle_check_output_readiness"),nil)
	entry({"admin", "forensics", "forensics","download_config_output"},call("handle_download_config_output"),nil)
	entry({"admin", "forensics", "forensics","prepare_config_output"},call("handle_prepare_config_output"),nil)
	entry({"admin", "forensics", "forensics","upload_pcap_features"},call("handle_upload_pcap_features"),nil)
	entry({"admin", "forensics", "forensics","get_predefined_configs"},call("handle_get_predefined_configs"),nil)
	entry({"admin", "forensics", "forensics","load_predefined_config"},call("handle_load_predefined_config"),nil)
	entry({"admin", "forensics", "forensics","get_config_description"},call("handle_get_config_description"),nil)
	entry({"admin", "forensics", "forensics","get_features_configs"},call("handle_get_features_configs"),nil)
	entry({"admin", "forensics", "forensics","get_base_directory"},call("handle_get_base_directory"),nil)	
	entry({"admin", "forensics", "forensics","change_base_directory"},call("handle_change_base_directory"),nil)	
	
end


--count keys in a table
local function tableCount(tab)
	local count = 0
	for _ in pairs(tab) do
		count = count + 1
	end
	return count
end


--function to split a string into strings and save into a table
local function split(inputstr, sep)
        if sep == nil then
                sep = "%s"
        end
        local t={}
        for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
                table.insert(t, str)
        end
        return t
end

local function trim(inputstr)
   return (inputstr:gsub("^%s*(.-)%s*$", "%1"))
end




local function checkMac(mac)
	str = mac:upper()
	str = str:gsub("A","\65")
	str = str:gsub("B","\65")
	str = str:gsub("C","\65")
	str = str:gsub("D","\65")
	str = str:gsub("E","\65")
	str = str:gsub("F","\65")
	str = str:gsub("0","\65")
	str = str:gsub("1","\65")
	str = str:gsub("2","\65")
	str = str:gsub("3","\65")
	str = str:gsub("4","\65")
	str = str:gsub("5","\65")
	str = str:gsub("6","\65")
	str = str:gsub("7","\65")
	str = str:gsub("8","\65")
	str = str:gsub("9","\65")
	return str:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
end


local function parseFloat(number)
    return string.format("%0.6f", number)
end


function handle_save_config()
	--input arguments from HTTP request
	local configName = luci.http.formvalue("configName")
	local oldName = luci.http.formvalue("oldName")
	--remove spaces, . and / from configName and oldName (if exists)
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	
	
	--if creating a new config or changing the name, check that new name does not exist already
	if(oldName == nil or oldName~=configName) then
		--check if the (new) configName already exists
		local checkExists = tonumber(luci.sys.call("test -d "..filesDirectory.."/features/configs/"..configName))
		if(checkExists==0)then
			luci.http.status(400,"Bad Request")
			luci.http.write_json("Config Name already exists, please choose another one.")
			return
		end
	end
	
	--check if the oldName directory exists, if it does: it is an edit
	if(oldName ~= nil) then
		oldName = oldName:gsub("%.", "")
		oldName = oldName:gsub("\/", "")
		oldName = oldName:gsub(" ", "")
		local checkExists = tonumber(luci.sys.call("test -d "..filesDirectory.."/features/configs/"..oldName))
		if(checkExists~=0)then
			luci.http.status(400,"Bad Request")
			luci.http.write_json("Error in saving the configuration")
			return
		end
		--change name of the config name if oldName and configName are different
		if(oldName~= configName)then
			luci.sys.call("mv "..filesDirectory.."/features/configs/"..oldName.." "..filesDirectory.."/features/configs/"..configName)
		end
		--stop the config and remove pidfile
		local pidfile = filesDirectory.."/features/configs/"..configName.."/pid"
		luci.sys.call("kill -s SIGINT $(cat "..pidfile..")")
		--luci.sys.call("rm "..pidfile)
	end
	
	--get input parameters
	local features = luci.http.formvalue("features")
	local devices = luci.http.formvalue("devices")
	local labels = luci.http.formvalue("labels")
	local winTime = tonumber(luci.http.formvalue("windowTime"))
	local addLabel = tonumber(luci.http.formvalue("addLabel"))
	local splitByMac = tonumber(luci.http.formvalue("splitByMac"))
	local relativeTime = tonumber(luci.http.formvalue("relativeTime"))
	local printHeaders = tonumber(luci.http.formvalue("printHeaders"))
	local rotateTime = tonumber(luci.http.formvalue("rotateTime"))
	local rotateFiles = tonumber(luci.http.formvalue("rotateMaxFiles"))
	local readFile = luci.http.formvalue("readFile")
	local captureFilter  = luci.http.formvalue("captureFilter")
	local description = luci.http.formvalue("description")
	local checkParameters = true
	local routerAddress = luci.http.formvalue("routerAddr")
	local interface  = luci.http.formvalue("interface")
	local csvSeparator = math.floor(tonumber(luci.http.formvalue("csvSeparator")))
	local errorString = ""
	------------------------------
	--start check of parameters
	checkParameters = checkParameters and (configName~="")
	checkParameters = checkParameters and (type(winTime) == "number") and winTime<=10 and winTime >0.01
	if(addLabel~=nil)then
		checkParameters = checkParameters and ((addLabel ==1) or (addLabel ==0))
	end
	if(splitByMac~=nil)then
		checkParameters = checkParameters and ((splitByMac ==1) or (splitByMac ==0))
	end
	if(relativeTime~=nil)then
		checkParameters = checkParameters and ((relativeTime ==1) or (relativeTime ==0))
	end
	if(printHeaders~=nil)then
		checkParameters = checkParameters and ((printHeaders ==1) or (printHeaders ==0))
	end
	if(csvSeparator~=nil)then
		checkParameters = checkParameters and csvSeparator<=7 and csvSeparator >=1
	end
	
	if(rotateTime~=nil)then
		checkParameters = checkParameters and (type(rotateTime) == "number")
		if rotateTime < 0 then
			rotateTime = 0
		end
	end
	if(rotateFiles~=nil)then
		checkParameters = checkParameters and (type(rotateFiles) == "number")
		if rotateFiles < 0 then
			rotateFiles = 0
		end
	end
	
	if(interface ~=nil)then
		checkParameters = checkParameters and (interface:match('^[a-zA-Z0-9_-]+$'))
		if(checkParameters) then 
			ifExists = tonumber(luci.sys.call("ip link show "..interface))
			checkParameters = checkParameters and (ifExists==0)
		end
		if(not checkParameters)then
			errorString = errorString.."Invalid interface! "
		end
	end
	
	if(readFile ~=nil)then
		readFile = readFile:gsub("\n", "")
		readFile = readFile:gsub("\t", "")
		readFile = readFile:gsub(" ", "")
		ifExists = tonumber(luci.sys.exec("test -f "..readFile.." && echo 1"))
		checkParameters = checkParameters and (ifExists==1)
		if(not checkParameters)then
			errorString = errorString.."Invalid file path! "
		end
	end
	
	if(captureFilter ~=nil and trim(captureFilter)~= "" )then
		ifExists = tonumber(luci.sys.call("tcpdump -c 1 '"..captureFilter.."'"))
		checkParameters = checkParameters and (ifExists==0)
		if(not checkParameters)then
			errorString = errorString.."Invalid capture filter! "
		end
	end

	if(not checkParameters) then
		luci.http.status(400,"Bad Request")
		luci.http.write_json(errorString)
		return
	end
	-----------------------------------
	----- end check of parameters -----
	-----------------------------------
	
	--create directory for new config and check the result (if error)
	local mkdirRes = tonumber(luci.sys.call("mkdir -p "..filesDirectory.."/features/configs/"..configName.."/output"))
	if(mkdirRes~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Config name already exists or is invalid, please choose another one.")
		return
	end
	local filepath = filesDirectory.."/features/configs/"..configName.."/settings.cfg"

	--take the router address from the interface (if interface not specified use the br-lan)
	if(interface==nil and readFile==nil)then
		interface = "br-lan"
	end
	if(routerAddress == nil) then
		routerAddress = luci.sys.exec("ip -o -f inet addr show | awk '/ "..interface.."\/ {print $4}'")	
		if(trim(routerAddress) == "")then 
		routerAddress = luci.sys.exec("ip -o -f inet addr show | awk '/ br-lan\/ {print $4}'")
		end
	end
	
	routerAddress = routerAddress:gsub("\n","")
	local routerAddr = split(routerAddress,"\/")
	--insert ip and mask (not imput files)
	local filecontent = "ip=\""..routerAddr[1].."\";\n"
	filecontent = filecontent.."mask="..tonumber(routerAddr[2])..";\n"
	--add interface if exists
	if(interface~=nil)then
		filecontent = filecontent.."interface=\""..interface.."\";\n"
	end
	if(splitByMac~=nil)then
		filecontent = filecontent.."splitByMac="..splitByMac..";\n"
	end
	if(csvSeparator~=nil)then
		filecontent = filecontent.."csvSeparator="..csvSeparator..";\n"
	end
	if(relativeTime~=nil)then
		filecontent = filecontent.."relativeTime="..relativeTime..";\n"
	end
	if(readFile~=nil)then
		filecontent = filecontent.."readFile=\""..readFile.."\";\n"
	end
	if(addLabel~=nil)then
		filecontent = filecontent.."addLabel="..addLabel..";\n"
	end
	if(printHeaders~=nil)then
		filecontent = filecontent.."printHeaders="..printHeaders..";\n"
	end
	if(rotateTime~=nil)then
		filecontent = filecontent.."rotateTime="..rotateTime..";\n"
		if(rotateFiles~=nil)then
			filecontent = filecontent.."rotateMaxFiles="..rotateFiles..";\n"
		end
	end
	
	if(captureFilter~=nil)then
		filecontent = filecontent.."captureFilter=\""..captureFilter.."\";\n"
	end
	
	filecontent = filecontent.."winTime="..parseFloat(winTime)..";\n"
	
	local cntDev=0
	if(devices~=nil) then
		filecontent = filecontent.."devicesMacs= ("
		deviceTable = split(devices,",")
		for i in pairs(deviceTable) do
			if(checkMac(deviceTable[i]))then
				filecontent = filecontent.."\""..deviceTable[i].."\","
				cntDev = cntDev+1
			end
		end
		if(cntDev>0)then
			filecontent = filecontent:sub(1,-2)	--remove last ","
		end
		filecontent = filecontent..");\n"
	end
	if(labels~=nil and addLabel ==1) then
		cntDev=0
		filecontent = filecontent.."labels= ("
		labelsTable = split(labels,",")
		for i in pairs(labelsTable) do
			filecontent = filecontent..tonumber(labelsTable[i])..","
			cntDev = cntDev+1
		end
		if(cntDev>0)then
			filecontent = filecontent:sub(1,-2)	--remove last comma
		end
		filecontent = filecontent..");\n"
	end
	
	--local featureNames = {"TcpDLpckSz","TcpDLpldSz","TcpULpckSz","TcpULpldSz",
	--"TcpPckSz","TcpPldSz","UdpDLpckSz","UdpDLpldSz","UdpULpckSz","UdpULpldSz",
	--"UdpPckSz","UdpPldSz","TotDLpcks","TotDLpld","TotULpcks","TotULpld","TotPcks",
	--"TotPld","TcpDLInter","TcpULInter","TcpInter","UdpDLInter","UdpULInter","UdpInter",
	--"TotDLInter","TotULInter","TotInter","NumTcpDL","NumTcpUL","NumTcp","NumUdpDL","NumUdpUL","NumUdp","NumTotDL","NumTotUL","NumTot","IpPorts"}
	
	local featureNames = {"TcpDLpckSz","TcpULpckSz","TcpPckSz",
	"UdpDLpckSz","UdpULpckSz","UdpPckSz","TotDLpcks","TotULpcks","TotPcks",
	"TcpDLpldSz","TcpULpldSz","TcpPldSz","UdpDLpldSz","UdpULpldSz","UdpPldSz",
	"TotDLpld","TotULpld","TotPld","TcpDLInter","TcpULInter","TcpInter","UdpDLInter",
	"UdpULInter","UdpInter","TotDLInter","TotULInter","TotInter","NumTcpDL","NumTcpUL",
	"NumTcp","NumUdpDL","NumUdpUL","NumUdp","NumTotDL","NumTotUL","NumTot","IpPorts"}
	
	filecontent = filecontent.."featuresList= ("
	featureTable = split(features,",")
	for i in pairs(featureTable) do
		filecontent = filecontent.."{name = \""..featureNames[i].."\";\nselect = "..tonumber(featureTable[i])..";\n},\n"
	end
	filecontent = filecontent:sub(1,-3)	--remove last ",\n"
	filecontent = filecontent..");\n"

	local fp = io.open(filepath, "w")
    fp:write(filecontent)
    fp:close()
	
	if(description~=nil) then
		local descriptionFile = io.open(filesDirectory.."/features/configs/"..configName.."/description.txt", "w")
		descriptionFile:write(description)
		descriptionFile:close()
	end
	
	luci.sys.call("rm "..filesDirectory.."/features/configs/"..configName.."/config.json")
	
	luci.http.prepare_content("application/json")	--prepare the Http response
	luci.http.write_json("Config saved correctly.")
	--luci.http.write_json("mkdir: "..mkdirRes.." windowTime: "..winTime.." features: "..features.." addLabel "..addLabel.." printHeaders "..printHeaders.." splitByMac "..splitByMac.." configName "..configName)


end

--status 0: Running, Status 1: Stopped, status 2: Terminated
local function checkConfigStatus(conf)
	local pid = tonumber(luci.sys.call("test -f "..filesDirectory.."/features/configs/"..conf.."/pid"))
	if(pid ~=0) then 	--pid does not exist
		 return 1
	else			--pid exists
		local running = tonumber(luci.sys.call("kill -0 $(cat "..filesDirectory.."/features/configs/"..conf.."/pid)"))
		if(running~=0) then
			return 2
		end
	end
	return 0
end

local function get_all_configs()
	--get all the configs
	local confDir = filesDirectory.."/features/configs"
	allConf = split(luci.sys.exec("ls -lst "..confDir.."/ | awk '{print $10\",\"$7,$8,$9}'"),"\n")
	local out = ""
	local status = ""
	for i in pairs(allConf) do
		out = out.."{"
		local conf = split(allConf[i],",")
		local statusInt = tonumber(checkConfigStatus(conf[1]))
		if(statusInt == 0) then 
			status = "Running"
		elseif(statusInt == 1)then
			status = "Stopped"
		elseif(statusInt == 2)then
			status = "Terminated"
		end
		out = out.."'name':'"..conf[1].."', 'date':'"..conf[2].."', 'status':'"..status.."'}\n"
	end
	out = out:sub(1,-2)
	return out
	--luci.http.write_json(""..out)
end

function handle_get_features_configs()
	out = get_all_configs()	
	luci.http.write_json(out)
end


--delete the config (if running kill the process first)
function handle_delete_existing_config()
	--input from HTTP
	local configName = luci.http.formvalue("configName")
	--remove spaces, dots and /
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end
	
	--kill the process if running
	luci.sys.call("kill -1 $(cat "..filesDirectory.."/features/configs/"..configName.."/pid)")
	--remove and return res
	local res = tonumber(luci.sys.call("rm -r "..filesDirectory.."/features/configs/"..configName))
	if(res~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Error deleting the configuration. Reload the page and try again")
		return
	end
	luci.http.write_json("Deleted")

end


function handle_start_existing_config()
	local configName = luci.http.formvalue("configName")
	--remove dots and /
	configName = configName:gsub("%.", "")
	configName = configName:gsub(" ", "")
	configName = configName:gsub("\/", "")
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end

	local status = checkConfigStatus(configName)
	if(status==0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Capture is already running")
		return
	end
	
	--remove old output files
	luci.sys.call("rm "..filesDirectory.."/features/configs/"..configName.."/output/*")
	
	--move the old output if exists (output.tar.gz to output1.tar.gz)
	local res = tonumber(luci.sys.exec("test -f "..filesDirectory.."/features/configs/"..configName.."/"..configName..".tar.gz && echo 1"))
	if(res==1)then
		local outputList = tostring(luci.sys.exec("ls "..filesDirectory.."/features/configs/"..configName.."/*.tar.gz"))
		local count =  select(2, string.gsub(outputList, "%\n", "")) --count \n so to know how many files in the folder
		luci.sys.exec("mv "..filesDirectory.."/features/configs/"..configName.."/"..configName..".tar.gz "..filesDirectory.."/features/configs/"..configName.."/"..configName..tostring(count)..".tar.gz")
	end
	
	-- and start the config
	luci.sys.call(homeDirectory.."/features/features-script "..filesDirectory.." "..configName)
	luci.http.write_json("Feature capture started correctly")
	
end

--start the config using python (be sure to generate the json first)
function handle_start_existing_config_python()
	local configName = luci.http.formvalue("configName")
	--remove dots and /
	configName = configName:gsub("%.", "")
	configName = configName:gsub(" ", "")
	configName = configName:gsub("\/", "")
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end

	local status = checkConfigStatus(configName)
	if(status==0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Capture is already running")
		return
	end
	
	--remove old output files
	luci.sys.call("rm "..filesDirectory.."/features/configs/"..configName.."/output/*")
	
	--move the old output if exists (output.tar.gz to output1.tar.gz)
	local res = tonumber(luci.sys.exec("test -f "..filesDirectory.."/features/configs/"..configName.."/"..configName..".tar.gz && echo 1"))
	if(res==1)then
		local outputList = tostring(luci.sys.exec("ls "..filesDirectory.."/features/configs/"..configName.."/*.tar.gz"))
		local count =  select(2, string.gsub(outputList, "%\n", "")) --count \n so to know how many files in the folder
		luci.sys.exec("mv "..filesDirectory.."/features/configs/"..configName.."/"..configName..".tar.gz "..filesDirectory.."/features/configs/"..configName.."/"..configName..tostring(count)..".tar.gz")
	end
	
	--check if the conf.json exists
	local checkExistsJson = tonumber(luci.sys.exec("test -f "..filesDirectory.."/features/configs/"..configName.."/config.json && echo 1"))
	if(checkExistsJson~=1)then
		luci.sys.call("config-translator -i "..filesDirectory.."/features/configs/"..configName.."/settings.cfg -o "..filesDirectory.."/features/configs/"..configName.."/config.json")
	end
	
	
	-- and start the config
	luci.sys.call(homeDirectory.."/features/features-script-python "..filesDirectory.." "..configName)
	luci.http.write_json("Feature capture started correctly")
	
end


function handle_stop_existing_config()
	local configName = luci.http.formvalue("configName")
	--remove dots and /
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end

	local res = luci.sys.call("kill -s SIGINT $(cat "..filesDirectory.."/features/configs/"..configName.."/pid)")
	if(res~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Error stopping the capture. Try again")
		return
	end
	os.execute("sleep 1")
	luci.sys.call("rm "..filesDirectory.."/features/configs/"..configName.."/pid")
	luci.sys.call("(tar -czf "..filesDirectory.."/features/configs/"..configName.."/"..configName..".tar.gz -C "..filesDirectory.."/features/configs/"..configName.."/output/ . && rm "..filesDirectory.."/features/configs/"..configName.."/output/*)&")
	luci.http.write_json("Feature capture stopped correctly")
end

--READ CONFIG FILE (opened in fp) and return the out string
local function load_config_file(fp)
	local fileContent = ""
	for line in fp:lines() do
		line = line:gsub("\n","")
		line = line:gsub("\t","")
		--line = line:gsub("%s","")
		--line = line:gsub(" ","")

		line = line:gsub("\"","'")
		fileContent = fileContent..line
	end
	
	fileContent = fileContent:gsub(";}","}")
	fileContent = fileContent:gsub(";select",",select")
	fileContent = fileContent:gsub("name","'name'")
	fileContent = fileContent:gsub("select","'select'")
	
	fileContent = fileContent:sub(1,-2)
	conf = fileContent.split(fileContent,";")
	local out=""
	
	for i in pairs(conf) do
		out = out..conf[i].."\n"
	end
	
	out = out:sub(1,-2)
	return out
end




function handle_open_existing_config()
	local configName = luci.http.formvalue("configName")
	--remove spaces, dots and /
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end
	
	local checkExists = tonumber(luci.sys.call("test -d "..filesDirectory.."/features/configs/"..configName))	
	if(checkExists~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Configuration does not exist.")
		return
	end
	
	local fp = io.open(filesDirectory.."/features/configs/"..configName.."/settings.cfg", "r" )

	out = load_config_file(fp)
	

	luci.http.write_json(out)
	
end

function handle_prepare_config_output()
	local configName = luci.http.formvalue("configName")
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	local checkExists = tonumber(luci.sys.exec("test -f "..filesDirectory.."/features/configs/"..configName.."/"..configName..".tar.gz && echo 1"))
	
	local status = checkConfigStatus(configName)
	--if the file exists and capture is in status Stopped you can directly download, otherwise you need to compress
	if(checkExists==1 and status==1)then
		luci.http.status(202,"Accepted")
		luci.http.write_json("Request accepted, output becoming ready")
		return
	--if config is in terminated: remove the pid so it is in status stopped and recreate the archive (being terminated it might be changes)
	elseif(status==2)then
		luci.sys.call("rm "..filesDirectory.."/features/configs/"..configName.."/pid")
	end
	res = luci.sys.call("tar -czf "..filesDirectory.."/features/configs/"..configName.."/"..configName..".tar.gz -C "..filesDirectory.."/features/configs/"..configName.."/output/ .")
	if(res~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Error downloading the output. Try again")
		return
	end

end

function handle_download_config_output()
	local io = require "io"
	local configName = luci.http.formvalue("configName")
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	--local filename = tostring(luci.sys.exec("cd "..filesDirectory.."/features/ && ls *.tar.gz && cd /"))
	--filename = filename:sub(1,-2)	--remove the "\n" from the file 
	local filename = configName..".tar.gz"
	local file = filesDirectory.."/features/configs/"..configName.."/"..filename
	if(filename=="1" or filename=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Error downloading file, try again later")
		return
	end
	local download_fpi = io.open(file, "r")
	luci.http.header('Content-Disposition', 'inline; filename="'..filename..'"' )
	luci.http.prepare_content("application/gzip")
	luci.ltn12.pump.all(luci.ltn12.source.file(download_fpi), luci.http.write)
	
	--remove the uncompressed output since it is compressed now (if the capture is not still running)
	local checkRunning = tonumber(luci.sys.exec("kill -0 $(cat "..filesDirectory.."/features/configs/".."/"..configName.."/pid) && echo 1"))
	if(checkRunning~=1)then
		luci.sys.call("rm "..filesDirectory.."/features/configs/"..configName.."/output/*")
	end
end

function handle_check_output_readiness()
	local io = require "io"
	local configName = luci.http.formvalue("configName")
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	local filename = configName..".tar.gz"
	local file = filesDirectory.."/features/configs/"..configName.."/"..filename
	--local size = luci.sys.exec("ls -la "..file.." | awk '{print $5}'")
	local filestats = nixio.fs.stat(file)
	if filestats == nil then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Requested file does not exist, try again...")
		return 
	end
	
	local size = filestats.size
	luci.sys.call("echo '"..size.."' > /mnt/sda1/testDirectory/features/test")
	
	if size <= 1 then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Requested file does not exist, try again...")
		return 
	end
	os.execute("sleep 0.1")
	filestats = nixio.fs.stat(file)
	--local size2 = luci.sys.exec("ls -la "..file.." | awk '{print $5}'")
	if filestats.size~=size then 
		luci.http.status(202,"Accepted")
		luci.http.write_json("Output not ready yet")
		return 
	else
		luci.http.status(200,"OK")
		luci.http.write_json("Output ready")
		return
	end
	
end


function handle_get_predefined_configs()
	local predefined = luci.sys.exec("cd "..filesDirectory.."/features/predefined && ls -d */ && cd");
	local existing = luci.sys.exec("cd "..filesDirectory.."/features/configs && ls -d */ && cd");
	--remove last \n and the /
	existing = existing:gsub("\/", "")
	existing = existing:sub(1,-2)
	--remove last \n and the /
	predefined = predefined:gsub("\/", "")
	predefined = predefined:sub(1,-2)
	luci.http.write_json(predefined.."\t"..existing)

end

function handle_load_predefined_config()
	local configName = luci.http.formvalue("configName")
	local cathegory = tonumber(luci.http.formvalue("cath"))
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	if(configName=="" or (cathegory ~= 1 and cathegory~=2))then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name or cathegory")
		return
	end
	
	local subDir = ""
	if(cathegory==1)then 
		subDir="predefined/"..configName 
	else 
		subDir="configs/"..configName
	end
	local io = require "io"
	local fp = io.open(filesDirectory.."/features/"..subDir.."/settings.cfg", "r" )
	out = load_config_file(fp)
	luci.http.write_json(out)
	
end

function handle_get_config_description()
	local configName = luci.http.formvalue("configName")
	local cathegory = tonumber(luci.http.formvalue("cath"))
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	if(configName=="" or (cathegory ~= 1 and cathegory~=2))then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name or cathegory")
		return
	end
	
	local subDir = ""
	if(cathegory==1)then 
		subDir="predefined/"..configName 
	else 
		subDir="configs/"..configName
	end
	
	local chkDesc = tonumber(luci.sys.call("test -f "..filesDirectory.."/features/"..subDir.."/description.txt"))
	if(chkDesc ~=0) then
		return
	end
	
	local io = require "io"
	local open_file = io.open(filesDirectory.."/features/"..subDir.."/description.txt","r")	--open the file to send it as response
	luci.http.prepare_content("text/javascript")
	luci.ltn12.pump.all(luci.ltn12.source.file(open_file), luci.http.write)
end

function handle_get_base_directory()
	luci.http.write_json(filesDirectory)
end

function handle_change_base_directory()
	local baseDir = luci.http.formvalue("baseDirectory")
	baseDir = baseDir:gsub("\'", "")	--remove eventual apices
	local chkDir = tonumber(luci.sys.exec("test -d '"..baseDir.."' && echo 1"))
	if(chkDir ~=1) then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid directory")
		return
	end
	luci.sys.call("echo '"..baseDir.."' > "..homeDirectory.."/init/baseDirectory");
	filesDirectory = baseDir
	local out = get_all_configs()
	luci.http.write_json(out)
end
