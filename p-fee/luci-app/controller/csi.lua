
module("luci.controller.admin.csi",package.seeall)
rootDirectory = "/home/forensics"
broker_address = "192.168.2.157"

--filesDirectory = "/mnt/sda1/testDirectory"
filesDirectory = tostring(luci.sys.exec("cat "..rootDirectory.."/init/baseDirectory")):gsub("\n", "")

function index()
	entry({"admin", "forensics", "forensics","csi"}, template("forensics/csi"), ("CSI-Sniffer")).leaf = true
	entry({"admin", "forensics", "forensics","csi_start"},call("handle_start_csi"),nil)
	entry({"admin", "forensics", "forensics","csi_stop"},call("handle_stop_csi"),nil)
	entry({"admin", "forensics", "forensics","csi_save_config"},call("handle_save_config"),nil)
	entry({"admin", "forensics", "forensics","csi_delete_config"},call("handle_delete_config"),nil)
	entry({"admin", "forensics", "forensics","csi_open_existing_config"},call("handle_open_existing_config"),nil)
	entry({"admin", "forensics", "forensics","csi_get_predefined_configs"},call("handle_get_predefined_configs"),nil)
	entry({"admin", "forensics", "forensics","csi_load_predefined_config"},call("handle_load_predefined_config"),nil)
	entry({"admin", "forensics", "forensics","csi_transfer_csv"},call("handle_transfer_csv"),nil)
	entry({"admin", "forensics", "forensics","csi_check_output_readiness"},call("handle_check_output_readiness"),nil)
	entry({"admin", "forensics", "forensics","csi_download_config_output"},call("handle_download_config_output"),nil)
	entry({"admin", "forensics", "forensics","csi_get_config_description"},call("handle_get_config_description"),nil)
	entry({"admin", "forensics", "forensics","csi_get_features_configs"},call("handle_get_features_configs"),nil)
	entry({"admin", "forensics", "forensics","csi_get_base_directory"},call("handle_get_base_directory"),nil)	
	entry({"admin", "forensics", "forensics","csi_change_base_directory"},call("handle_change_base_directory"),nil)	
	
end


-- function to start the capture 
function handle_start_csi()
	local configName = luci.http.formvalue("configName")
	local filepath = filesDirectory.."/features/csi_configs/"..configName.."/settings.cfg"
	
	-- when starting the capture, remove the .csv file in the output folder
	luci.sys.call("rm "..filesDirectory.."/features/csi_configs/"..configName.."/output/"..configName..".csv")
	-- publish on topic prepare to retrieve the saved settings for the capture
	luci.sys.call("mosquitto_pub -h "..broker_address.." -t prepare -f "..filepath)
	-- publish on topic start to start the capture with the chosen configuration
	luci.sys.call("mosquitto_pub -h "..broker_address.." -t start -m "..configName)
	
	luci.http.prepare_content("application/json")	--prepare the Http response
	luci.http.write_json("Capture started")

end


--function to stop the capture 
function handle_stop_csi()
	local configName = luci.http.formvalue("configName")
	
	-- publish on topic stop to stop the capture
	luci.sys.call("mosquitto_pub -h "..broker_address.." -t stop -m "..configName)

	luci.http.prepare_content("application/json")	--prepare the Http response
	luci.http.write_json("Capture stopped")
	
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


-- function to save the configuration
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
		local checkExists = tonumber(luci.sys.call("test -d "..filesDirectory.."/features/csi_configs/"..configName))
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
		local checkExists = tonumber(luci.sys.call("test -d "..filesDirectory.."/features/csi_configs/"..oldName))
		if(checkExists~=0)then
			luci.http.status(400,"Bad Request")
			luci.http.write_json("Error in saving the configuration")
			return
		end
		--change name of the config name if oldName and configName are different
		if(oldName~= configName)then
			luci.sys.call("mv "..filesDirectory.."/features/csi_configs/"..oldName.." "..filesDirectory.."/features/csi_configs/"..configName)
		end
		--stop the config and remove pidfile -> ATTENZIONE
		local pidfile = filesDirectory.."/features/csi_configs/"..configName.."/pid"
		luci.sys.call("kill -s SIGINT $(cat "..pidfile..")")
		--luci.sys.call("rm "..pidfile)	--uncomment here if you want to go to stopped state (at the moment go to terminated state)
	end
	
	--get input parameters
	local devices = luci.http.formvalue("devices")
	local channel = tonumber(luci.http.formvalue("channel"))
	local description = luci.http.formvalue("description")
	local checkParameters = true
	local errorString = ""
	------------------------------
	--start check of parameters
	checkParameters = checkParameters and (configName~="")	
	checkParameters = checkParameters and (type(channel) == "number") and channel>=1 and channel<14
	
	if(not checkParameters) then
		luci.http.status(400,"Bad Request")
		luci.http.write_json(errorString)
		return
	end
	
	-----------------------------------
	----- end check of parameters -----
	-----------------------------------
	
	--create directory for new config and check the result (if error)
	local mkdirRes = tonumber(luci.sys.call("mkdir -p "..filesDirectory.."/features/csi_configs/"..configName.."/output"))
	if(mkdirRes~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Config name already exists or is invalid, please choose another one.")
		return
	end
	local filepath = filesDirectory.."/features/csi_configs/"..configName.."/settings.cfg"

	--take the router address from the interface (if interface not specified use the br-lan)
	interface = "br-lan"

	local filecontent = "channel="..channel..";\n"
	
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
	
	local fp = io.open(filepath, "w")
    fp:write(filecontent)
    fp:close()
	
	if(description~=nil) then
		local descriptionFile = io.open(filesDirectory.."/features/csi_configs/"..configName.."/description.txt", "w")
		descriptionFile:write(description)
		descriptionFile:close()
	end
	
	luci.http.prepare_content("application/json")	--prepare the Http response
	luci.http.write_json("Config saved correctly.")
	
	
end

--status 0: Running, Status 1: Stopped, status 2: Terminated
local function checkConfigStatus(conf)
	local pid = tonumber(luci.sys.call("test -f "..filesDirectory.."/features/csi_configs/"..conf.."/pid"))
	if(pid ~=0) then 	--pid does not exist
		 return 1
	else			--pid exists
		local running = tonumber(luci.sys.call("kill -0 $(cat "..filesDirectory.."/features/csi_configs/"..conf.."/pid)"))
		if(running~=0) then
			return 2
		end
	end
	return 0
end


-- function to get all the configs
local function get_all_configs()
	local confDir = filesDirectory.."/features/csi_configs"
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


--delete the config (if running kill the process first -> SISTEMARE)
function handle_delete_config()
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
	-- luci.sys.call("kill -1 $(cat "..filesDirectory.."/features/configs/"..configName.."/pid)")
	
	--remove and return res
	local res = tonumber(luci.sys.call("rm -r "..filesDirectory.."/features/csi_configs/"..configName))
	if(res~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Error deleting the configuration. Reload the page and try again")
		return
	end
	luci.http.write_json("Deleted")
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


-- function to read config settings
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
	
	local checkExists = tonumber(luci.sys.call("test -d "..filesDirectory.."/features/csi_configs/"..configName))	
	if(checkExists~=0)then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Configuration does not exist.")
		return
	end
	
	local fp = io.open(filesDirectory.."/features/csi_configs/"..configName.."/settings.cfg", "r" )

	out = load_config_file(fp)
	

	luci.http.write_json(out)
end


-- function to effectively download the file
function handle_download_config_output()
	local io = require "io"
	local configName = luci.http.formvalue("configName")
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	--local filename = tostring(luci.sys.exec("cd "..filesDirectory.."/features/ && ls *.tar.gz && cd /"))
	--filename = filename:sub(1,-2)	--remove the "\n" from the file 
	local filename = configName..".csv"
	local file = filesDirectory.."/features/csi_configs/"..configName.."/output/"..filename
	if(filename=="1" or filename=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Error downloading file, try again later")
		return
	end
	
	--luci.sys.call("echo '"..filename.."' > /mnt/sda1/testDirectory/features/res")
	local download_fpi = io.open(file, "r")
	luci.http.header('Content-Disposition', 'inline; filename="'..filename..'"' )
	luci.http.prepare_content("application/gzip")
	luci.ltn12.pump.all(luci.ltn12.source.file(download_fpi), luci.http.write)
	
	--remove the uncompressed output since it is compressed now (if the capture is not still running)
	--[[
	local checkRunning = tonumber(luci.sys.exec("kill -0 $(cat "..filesDirectory.."/features/configs/".."/"..configName.."/pid) && echo 1"))
	if(checkRunning~=1)then
		luci.sys.call("rm "..filesDirectory.."/features/configs/"..configName.."/output/*")
	end
	]]
end


-- function to check if the output is ready to download or not (in this case re-check after a timeout)
function handle_check_output_readiness()
	local io = require "io"
	local configName = luci.http.formvalue("configName")
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	local filename = configName..".csv"
	local file = filesDirectory.."/features/csi_configs/"..configName.."/output/"..filename
	--local size = luci.sys.exec("ls -la "..file.." | awk '{print $5}'")
	local filestats = nixio.fs.stat(file)
	if filestats == nil then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Requested file does not exist, try again...")
		return 
	end
	
	local size = filestats.size
	luci.sys.call("echo '"..size.."' > "..filesDirectory.."/features/test")
	if size <= 1 then
		luci.http.status(202,"Accepted")
		luci.http.write_json("Output not ready yet")
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


-- function to prepare the download 
function handle_transfer_csv()
	local configName = luci.http.formvalue("configName")
	
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end
	
	
	local checkExists = tonumber(luci.sys.exec("test -f "..filesDirectory.."/features/csi_configs/"..configName.."/output/"..configName..".csv && echo 1"))
	local status = checkConfigStatus(configName)
	--if the file exists and capture is in status Stopped you can directly go to check_readiness (output may be in compress phase)
	if(checkExists==1 and status==1)then
		luci.http.status(202,"Accepted")
		luci.http.write_json("Request accepted, output becoming ready")
		return
	elseif (status==2)then
		luci.sys.call("rm "..filesDirectory.."/features/csi_configs/"..configName.."/pid")
	elseif (checkExists ~=1) then
		-- delete the retained messages on topic output (otherwise it may download old .csv)
		luci.sys.call("mosquitto_pub -h "..broker_address.." -t output -n -r ")
		-- publish on topic download to start the download process 
		luci.sys.call("mosquitto_pub -h "..broker_address.." -t download -m "..configName)
		-- subscribe on topic output to save data in a .csv file
		luci.sys.call("mosquitto_sub -h "..broker_address.." -t output -C 1 > "..filesDirectory.."/features/csi_configs/"..configName.."/output/"..configName..".csv")
	
		local checkExists = tonumber(luci.sys.exec("test -f "..filesDirectory.."/features/csi_configs/"..configName.."/output/"..configName..".csv && echo 1"))
		local status = checkConfigStatus(configName)
		--if the file exists and capture is in status Stopped you can directly go to check_readiness (output may be in compress phase)
		if(checkExists==1 and status==1)then
			luci.http.status(202,"Accepted")
			luci.http.write_json("Request accepted, output becoming ready")
			return
		--if config is in terminated: remove the pid so it is in status stopped and recreate the archive (being terminated it might be changed)
		elseif(status==2)then
			luci.sys.call("rm "..filesDirectory.."/features/csi_configs/"..configName.."/pid")
		end
	end


--[[	-- delete the retained messages on topic output (otherwise it may download old .csv)
	luci.sys.call("mosquitto_pub -h 192.168.2.117 -t output -n -r ")
	-- publish on topic download to start the download process 
	luci.sys.call("mosquitto_pub -h 192.168.2.117 -t download -m "..configName)
	-- subscribe on topic output to save data in a .csv file
	luci.sys.call("mosquitto_sub -h 192.168.2.117 -t output -C 1 > "..filesDirectory.."/features/csi_configs/"..configName.."/output/"..configName..".csv")
	
	local checkExists = tonumber(luci.sys.exec("test -f "..filesDirectory.."/features/csi_configs/"..configName.."/output/"..configName..".csv && echo 1"))
	local status = checkConfigStatus(configName)
	--if the file exists and capture is in status Stopped you can directly go to check_readiness (output may be in compress phase)
	if(checkExists==1 and status==1)then
		luci.http.status(202,"Accepted")
		luci.http.write_json("Request accepted, output becoming ready")
		return
	--if config is in terminated: remove the pid so it is in status stopped and recreate the archive (being terminated it might be changed)
	elseif(status==2)then
		luci.sys.call("rm "..filesDirectory.."/features/csi_configs/"..configName.."/pid")
	end
	]]

	luci.http.prepare_content("application/json")
	luci.http.write_json("Downloading")

end


-- function to retrieve predefined configs
function handle_load_predefined_config()
	local configName = luci.http.formvalue("configName")
	-- local cathegory = tonumber(luci.http.formvalue("cath"))
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end
	
	local subDir = "csi_configs/"..configName
	--[[ if(cathegory==1)then 
		subDir="csi_predefined/"..configName 
	else 
		subDir="csi_configs/"..configName
	end ]]
	local io = require "io"
	local fp = io.open(filesDirectory.."/features/"..subDir.."/settings.cfg", "r" )
	out = load_config_file(fp)
	luci.http.write_json(out)
	
end 


-- function to check if prefedefined configs exists
function handle_get_predefined_configs()
	-- local predefined = luci.sys.exec("cd "..filesDirectory.."/features/csi_predefined && ls -d */ && cd");
	local existing = luci.sys.exec("cd "..filesDirectory.."/features/csi_configs && ls -d */ && cd");
	--remove last \n and the /
	existing = existing:gsub("\/", "")
	existing = existing:sub(1,-2)
	
	luci.http.write_json(existing)
	
end 


-- function to retrieve the config description
function handle_get_config_description()
	local configName = luci.http.formvalue("configName")
	-- local cathegory = tonumber(luci.http.formvalue("cath"))
	configName = configName:gsub("%.", "")
	configName = configName:gsub("\/", "")
	configName = configName:gsub(" ", "")
	if(configName=="")then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid config name")
		return
	end
	
	local subDir = "csi_configs/"..configName
	
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


-- function to change base directory
function handle_change_base_directory()
	local baseDir = luci.http.formvalue("baseDirectory")
	baseDir = baseDir:gsub("\'", "")	--remove eventual apices
	local chkDir = tonumber(luci.sys.exec("test -d '"..baseDir.."' && echo 1"))
	if(chkDir ~=1) then
		luci.http.status(400,"Bad Request")
		luci.http.write_json("Invalid directory")
		return
	end
	luci.sys.call("echo '"..baseDir.."' > "..rootDirectory.."/init/baseDirectory");
	filesDirectory = baseDir
	local out = get_all_configs()
	luci.http.write_json(out)
end
