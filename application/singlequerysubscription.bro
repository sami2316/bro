
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

export {
	redef enum Log::ID += { LOG };
	type Process: record {
	host: string &log;
	user: string &log;
	ev_type: string &log;
	pid: int &log;
	name: string &log;
	cwd: string &log;
	};
}

global acpi_tables: event(host: string, user: string, ev_type: string, name: string, size: int, md5: string);

###################################################################################
global arp_cache: event(host: string, user: string, ev_type: string, address: string, mac: string, interface: string);

###################################################################################
global block_devices: event(host: string, user: string, ev_type: string,name: string,vendor: string, model: string);

###################################################################################
global chrome_extensions: event(host: string, user: string, ev_type: string, name: string,author: string, path:string);

###################################################################################
global cpuid: event(host: string, user: string, ev_type: string,  feature: string, value: string);

###################################################################################
global crontab: event(host: string, user: string, ev_type: string,  hour: int, command: string, path: string);

###################################################################################
global disk_encryption: event(host: string, user: string, ev_type: string, name: string, uuid: string, encrypted: int);

###################################################################################
global etc_hosts: event(host: string, user: string, ev_type: string,  address: string, hostnames: string);

###################################################################################
global etc_protocols: event(host: string, user: string, ev_type: string,  name: string, number: int);

###################################################################################
global etc_services: event(host: string, user: string, ev_type: string,  name: string, prt: int, protocol: string);

###################################################################################
global file_events: event(host: string, user: string, ev_type: string,  target_path: string, action: string, t: int);

###################################################################################
global firefox_addons: event(host: string, user: string, ev_type: string,  name: string, source_url: string, location: string);

###################################################################################
global groups: event(host: string, user: string, ev_type: string,  gid: int, groupname: string);

###################################################################################
global hardware_events: event(host: string, user: string, ev_type: string, action: string, model: string, vendor: string);

###################################################################################
global interface_address: event(host: string, user: string, ev_type: string, interface: string, address: string);

###################################################################################
global interface_details: event(host: string, user: string, ev_type: string, interface: string, mac: string, mtu: int);

###################################################################################
global kernel_info: event(host: string, user: string, ev_type: string, version: string, path: string, device: string);

###################################################################################
global last: event(host: string, user: string, ev_type: string, username: string, pid: int, h: string);

###################################################################################
global listening_ports: event(host: string, user: string, ev_type: string, pid: int, prt: int, protocol: int);

###################################################################################
global logged_in_users: event(host: string, user: string, ev_type: string, username: string, h: string, t: int);

###################################################################################
global mounts: event(host: string, user: string, ev_type: string, device: string, path: string);

###################################################################################
global opera_extensions: event(host: string, user: string, ev_type: string, name: string, description: string, author: string);

###################################################################################
global os_version: event(host: string, user: string, ev_type: string, name: string, patch: int, build: string);

###################################################################################
global passwd_changes: event(host: string, user: string, ev_type: string, target_path: string, action: string);

###################################################################################
global pci_devices: event(host: string, user: string, ev_type: string, pci_slot: string, driver: string, vendor: string, model: string);

###################################################################################
global process_envs: event(host: string, user: string, ev_type: string, pid: int, key: string, value: string);

###################################################################################
global process_memory_map: event(host: string, user: string, ev_type: string, pid: int, permissions: string, device: string);

###################################################################################
global process_open_files: event(host: string, user: string, ev_type: string, pid: int, fd: string, path: string);

###################################################################################
global process_open_sockets: event(host: string, user: string, ev_type: string, pid: int, socket: int, protocol: int);

###################################################################################
global processes: event(host: string, user: string, ev_type: string, pid: int, name: string, cwd: string,on_disk: int);

###################################################################################
global routes: event(host: string, user: string, ev_type: string, destination: string, source: string, interface: string);

###################################################################################
global shell_history: event(host: string, user: string, ev_type: string, username: string, command: string);

###################################################################################
global smbios_tables: event(host: string, user: string, ev_type: string, number: int, description: string, size: int);

###################################################################################
global system_controls: event(host: string, user: string, ev_type: string, name: string, oid: string, subsystem: string);

###################################################################################
global uptime: event(host: string, user: string, ev_type: string, days: int, hours: int);

###################################################################################
global usb_devices: event(host: string, user: string, ev_type: string, usb_address: int, vendor: string, model: string);

###################################################################################
global user_groups: event(host: string, user: string, ev_type: string, uid: int, gid: int);

###################################################################################
global users: event(host: string, user: string, ev_type: string, username: string, uid: int, gid: int);

###################################################################################
global warning: event(warning_msg: string);

###################################################################################
global error: event(error_msg: string);

###################################################################################

event bro_init()
{
	osquery::enable();
	osquery::subscribe_to_events("/bro/event/");
	osquery::listen(broker_port,"192.168.0.120"); 
	Log::create_stream(LOG, [$columns=Process, $path="process"]);
}

event BrokerComm::incoming_connection_established(peer_name: string)
{
	print "BrokerComm::incoming_connection_establisted",  peer_name;
	
	#osquery::subscribe(acpi_tables,"SELECT name,size,md5 FROM acpi_tables","ADD",T);

	#######################################################################################
	#osquery::subscribe(arp_cache,"SELECT address,mac,interface FROM arp_cache","REMOVED",T);

	#######################################################################################
	#osquery::subscribe(block_devices,"SELECT name,vendor,model FROM block_devices");

	#######################################################################################
	#osquery::subscribe(chrome_extensions,"SELECT name,author,path FROM chrome_extensions");

	########################################################################################
	#osquery::subscribe(cpuid,"SELECT feature,value FROM cpuid");

	#######################################################################################
	#osquery::subscribe(crontab,"SELECT hour,command,path FROM crontab");

	#######################################################################################
	#osquery::subscribe(disk_encryption,"SELECT name,uuid,encrypted FROM disk_encryption");

	########################################################################################
	#osquery::subscribe(etc_hosts,"SELECT address,hostnames FROM etc_hosts");

	########################################################################################
	#osquery::subscribe(etc_protocols,"SELECT name,number FROM etc_protocols");

	#######################################################################################
	#osquery::subscribe(etc_services,"SELECT name,port,protocol FROM etc_services");

	#######################################################################################
	#osquery::subscribe(file_events,"SELECT target_path,action,time FROM file_events");

	#######################################################################################
	#osquery::subscribe(firefox_addons,"SELECT name,source_url,location FROM firefox_addons");

	#######################################################################################
	#osquery::subscribe(groups,"SELECT gid,groupname FROM groups");

	#######################################################################################
	#osquery::subscribe(hardware_events,"SELECT action,model,vendor FROM hardware_events");

	#######################################################################################
	#osquery::subscribe(interface_address,"SELECT interface,address FROM interface_address");

	#######################################################################################
	#osquery::subscribe(interface_details,"SELECT interface,mac,mtu FROM interface_details");

	#######################################################################################
	#osquery::subscribe(kernel_info,"SELECT version,path,device FROM kernel_info");

	#######################################################################################
	#osquery::subscribe(last,"SELECT username,pid,host FROM last");

	#######################################################################################
	#osquery::subscribe(listening_ports,"SELECT pid,port,protocol FROM listening_ports");

	#######################################################################################
	#osquery::subscribe(logged_in_users,"SELECT user,host, user,time FROM logged_in_users");

	########################################################################################
	#osquery::subscribe(mounts,"SELECT device,path FROM mounts");

	########################################################################################
	#osquery::subscribe(opera_extensions,"SELECT name,description,author FROM opera_extensions");

	#######################################################################################
	#osquery::subscribe(os_version,"SELECT name,patch,build FROM os_version","Add",T);

	#######################################################################################
	#osquery::subscribe(passwd_changes,"SELECT target_path,action FROM passwd_changes");

	#######################################################################################
	#osquery::subscribe(pci_devices,"SELECT pci_slot,driver,vendor,model FROM pci_devices");

	#######################################################################################
	#osquery::subscribe(process_envs,"SELECT pid,key,value FROM process_envs");

	#######################################################################################
	#osquery::subscribe(process_memory_map,"SELECT pid,permissions,device FROM process_memory_map");

	#######################################################################################
	#osquery::subscribe(process_open_files,"SELECT pid,fd,path FROM process_open_files");

	######################################################################################
	#osquery::subscribe(process_open_sockets,"SELECT pid,socket,protocol FROM process_open_sockets");

	#######################################################################################
	#osquery::subscribe(processes,"SELECT pid,name,cwd,on_disk FROM processes","ADD",T);

	#######################################################################################
	#osquery::subscribe(routes,"SELECT destination,source,interface FROM routes");

	#######################################################################################
	#osquery::subscribe(shell_history,"SELECT username,command FROM shell_history");

	#######################################################################################
	#osquery::subscribe(smbios_tables,"SELECT number,description,size FROM smbios_tables");

	#######################################################################################
	osquery::subscribe(system_controls,"SELECT name,oid,subsystem FROM system_controls");

	#######################################################################################
	#osquery::subscribe(uptime,"SELECT days,hours FROM uptime");

	#######################################################################################
	#osquery::subscribe(usb_devices,"SELECT usb_address,vendor,model FROM usb_devices","Removed");

	########################################################################################
	#osquery::subscribe(user_groups,"SELECT uid,gid FROM user_groups");

	########################################################################################
	#osquery::subscribe(users,"SELECT username,uid,gid FROM users");

	#######################################################################################
	
}


event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;

}

########################### ACPI TABLES ################################################

event acpi_tables(host: string, user: string, ev_type: string, name: string, size: int, md5: string)
{
	print "acpi_table Entry";
	print fmt("Host = %s user=%s Event_type= %s Table_name = %s size = %d md5 = %s",host, user, ev_type, name, size, md5);
}

############################## ARP CACHE ##############################################
event arp_cache(host: string, user: string, ev_type: string, address: string, mac: string, interface: string)
{
	print "arp_cache Entry";
	print fmt("Host = %s user=%s Event_type= %s Address = %s mac = %s Interface = %s",host, user, ev_type, address, mac, interface);
}

############################## BLOCK DEVICES ###########################################
event block_devices(host: string, user: string, ev_type: string, name: string,vendor: string, model: string)
{
	print "block_devices Entry";
	print fmt("Host = %s user=%s Event_type= %s Name = %s Vendor = %s Model = %s",host, user, ev_type, name, vendor, model);
}

############################## CHROME EXTENSIONS ##########################################
event chrome_extensions(host: string, user: string, ev_type: string, name: string,author: string, path:string)
{
	print fmt("chrome_extensions Entry");
	print fmt("Host = %s user=%s Event_type= %s Name = %s Author = %s Path = %s",host, user, ev_type, name, author, path);
}

############################# CPUID #####################################################
event cpuid(host: string, user: string, ev_type: string, feature: string, value: string)
{
	print fmt("cpuid Entry");
	print fmt("Host = %s user=%s Event_type= %s Feature = %s Value = %s",host, user, ev_type, feature,value);
}

############################ CRONTAB ####################################################
event crontab(host: string, user: string, ev_type: string, hour: int, command: string, path: string)
{
	print fmt("crontab Entry");
	print fmt("Host = %s user=%s Event_type= %s Hour = %d Command = %s Path=%s",host, user, ev_type, hour, command, path);
}

########################### DISK ENCRYPTION ###############################################
event disk_encryption(host: string, user: string, ev_type: string, name: string, uuid: string, encrypted: int)
{
	print fmt("disk_encryption Entry");
	print fmt("Host = %s user=%s Event_type= %s Name = %s uuid = %s encrypted=%d",host, user, ev_type, name, uuid, encrypted);
}

########################### ETC HOSTS ########################################################
event etc_hosts(host: string, user: string, ev_type: string, address: string, hostnames: string)
{
	print fmt("etc_hosts Entry");
	print fmt("Host = %s user=%s Event_type= %s Address = %s hostnames = %s ",host, user, ev_type, address, hostnames);
}

########################### ETC PROTOCOLS #################################################
event etc_protocols(host: string, user: string, ev_type: string, name: string, number: int)
{
	print fmt("New entry added");
	print fmt("Host = %s user=%s Event_type= %s Name = %s number = %d ",host, user, ev_type, name, number);
}

########################### ETC SERVICES ##################################################
event etc_services(host: string, user: string, ev_type: string, name: string, prt: int, protocol: string)
{
	print fmt("etc_services Entry");
	print fmt("Host = %s user=%s Event_type= %s Name = %s prt = %d Protocol = %s ",host, user, ev_type, name, prt, protocol);
}

########################### FILE EVENTS ####################################################
event file_events(host: string, user: string, ev_type: string, target_path: string, action: string, t: int)
{
	print fmt("file_events Entry");
	print fmt("Host = %s user=%s Event_type= %s target_path = %s Action = %s Time = %d",host, user, ev_type, target_path,action,t);
}

############################ FIREFOX ADDONS #################################################
event firefox_addons(host: string, user: string, ev_type: string, name: string, source_url: string, location: string)
{
	print fmt("firefox_extensions Entry");
	print fmt("Host = %s user=%s Event_type= %s Name = %s source_url = %s Locatoin= %s ",host, user, ev_type, name, source_url, location);
}

############################ ADDED GROUPS ###################################################
event groups(host: string, user: string, ev_type: string, gid: int, groupname: string)
{
	print fmt("groups Entry");
	print fmt("Host = %s user=%s Event_type= %s gid = %d groupnumber = %s ",host, user, ev_type, gid, groupname);
}

############################ HARDWARE EVENTS ##################################################
event hardware_events(host: string, user: string, ev_type: string, action: string, model: string, vendor: string)
{
	print fmt("New entry added");
	print fmt("Host = %s user=%s Event_type= %s action = %s model = %s  Vendor =%s",host, user, ev_type, action, model,vendor);
}

########################### INTERFACE ADDRESS ##################################################
event interface_address(host: string, user: string, ev_type: string, interface: string, address: string)
{
	print fmt("interface_address Entry");
	print fmt("Host = %s user=%s Event_type= %s Interface = %s Address = %s ",host, user, ev_type, interface,address);
}

############################ INTERFACE DETAILS ##################################################
event interface_details(host: string, user: string, ev_type: string, interface: string, mac: string, mtu: int)
{
	print fmt("New entry added");
	print fmt("Host = %s user=%s Event_type= %s interface= %s mac = %s Mtu =%d ",host, user, ev_type, interface,mac,mtu);
}

############################ KERNEL INFO ####################################################
event kernel_info(host: string, user: string, ev_type: string, version: string, path: string, device: string)
{
	print fmt("kernel_info Entry");
	print fmt("Host = %s user=%s Event_type= %s version = %s path = %s Device =%s",host, user, ev_type, version,path,device);
}

############################# LAST ##########################################################
event last(host: string, user: string, ev_type: string, username: string, pid: int, h: string)
{
	print fmt("last Entry");
	print fmt("Host = %s user=%s Event_type= %s username = %s pid = %d Host=%s",host, user, ev_type, username, pid,h);
}

############################# LISTENING PORTS ################################################
event listening_ports(host: string, user: string, ev_type: string, pid: int, prt: int, protocol: int)
{
	print fmt("listening_ports Entry");
	print fmt("Host = %s user=%s Event_type= %s pid = %d prt = %d Protocol =%d ",host, user, ev_type, pid,prt,protocol);
}

############################# LOGGED IN USERS #################################################
event logged_in_users(host: string, user: string, ev_type: string, username: string, h: string, t: int)
{
	print fmt("New entry added");
	print fmt("Host = %s user=%s Event_type= %s User = %s Host = %s Time =%d ",host, username, ev_type, user,h,t);
}

############################ MOUNTS ##########################################################
event mounts(host: string, user: string, ev_type: string, device: string, path: string)
{
	print fmt("mounts Entry");
	print fmt("Host = %s user=%s Event_type= %s Device = %s Path = %s ",host, user, ev_type, device,path);
}

############################ OPERA EXTENSIONS #################################################
event opera_extensions(host: string, user: string, ev_type: string, name: string, description: string, author: string)
{
	print fmt("New entry added");
	print fmt("Host = %s user=%s Event_type= %s Name = %s description = %s Author=%s ",host, user, ev_type, name,description,author);
}

############################ OS VERSION ######################################################
event os_version(host: string, user: string, ev_type: string, name: string, patch: int, build: string)
{
	print fmt("os_version Entry");
	print fmt("Host = %s user=%s Event_type= %s Name = %s Patch = %d Build = %s ",host, user, ev_type, name, patch,build);
}

############################ PASSWORD CHANGES ##################################################
event passwd_changes(host: string, user: string, ev_type: string, target_path: string, action: string)
{
	print fmt("passwd_changes Entry");
	print fmt("Host = %s user=%s Event_type= %s Target_Path = %s Action = %s ",host, user, ev_type, target_path,action);
}

############################ PCI DEVICES #####################################################
event pci_devices(host: string, user: string, ev_type: string, pci_slot: string, driver: string, vendor: string, model: string)
{
	print fmt("New entry added");
	print fmt("Host = %s user=%s Event_type= %s PCI_Slot = %s Driver = %s Vendor =%s Model= %s",host, user, ev_type, pci_slot,driver,vendor,model);
}

########################### PROCESS EVENTS #####################################################
event process_envs(host: string, user: string, ev_type: string, pid: int, key: string, value: string)
{
	print fmt("process_envs Entry");
	print fmt("Host = %s user=%s Event_type= %s PID = %d Key = %s Value = %s ",host, user, ev_type, pid,key,value);
}

########################### PROCESS MOMORY ######################################################
event process_memory_map(host: string, user: string, ev_type: string, pid: int, permissions: string, device: string)
{
	print fmt("process_memory Entry");
	print fmt("Host = %s user=%s Event_type= %s PID = %d Permissions = %s Device = %s ",host, user, ev_type, pid,permissions,device);
}

########################## PROCESS OPEN FILES ###################################################
event process_open_files(host: string, user: string, ev_type: string, pid: int, fd: string, path: string)
{
	print fmt("process_open_files Entry");
	print fmt("Host = %s user=%s Event_type= %s PID = %d FD = %s Path = %s",host, user, ev_type, pid,fd,path);
}

########################## PROCESS OPEN SOCKETS ####################################################
event process_open_sockets(host: string, user: string, ev_type: string, pid: int, socket: int, protocol: int)
{
	print fmt("process_open_sockets Entry");
	print fmt("Host = %s user=%s Event_type= %s PID = %d Socket = %d Protocol =%d",host, user, ev_type, pid,socket,protocol);
}

########################## PROCESSES #########################################################
event processes(host: string, user: string, ev_type: string, pid: int, name: string, cwd: string, on_disk: int)
{
	print fmt("processes Entry");
	print fmt("Host = %s user=%s Event_type= %s PID = %d Name = %s cwd = %s on_disk=%d",host, user, ev_type, pid,name,cwd,on_disk);
	Log::write(osquery::LOG, [$host=host ,$user=user, $ev_type= ev_type, $pid= pid, $name= name, $cwd = cwd]);
}

########################### ROUTES ########################################################
event routes(host: string, user: string, ev_type: string, destination: string, source: string, interface: string)
{
	print fmt("routes Entry");
	print fmt("Host = %s user=%s Event_type= %s Destination = %s Source = %s Interface = %s ",host, user, ev_type, destination,source,interface);
}

########################### SHELL HISTORY ####################################################
event shell_history(host: string, user: string, ev_type: string, username: string, command: string)
{
	print fmt("shell_history");
	print fmt("Host = %s user=%s Event_type= %s UserNmae = %s Command = %s ",host, user, ev_type, username, command);
}

############################ SMBIOS TABLES ###################################################
event smbios_tables(host: string, user: string, ev_type: string, number: int, description: string, size: int)
{
	print fmt("smbios_tables Entry");
	print fmt("Host = %s user=%s Event_type= %s Number = %d Description = %s Size=%d ",host, user, ev_type, number, description,size);
}

############################# SYSTEM CONTROLS ###################################################
event system_controls(host: string, user: string, ev_type: string, name: string, oid: string, subsystem: string)
{
	print fmt("system_controls Entry");
	print fmt("Host = %s user=%s Event_type= %s Name = %s OID = %s Subsystem =%s ",host, user, ev_type, name, oid, subsystem);
}

############################## UPTIME ###################################################
event uptime(host: string, user: string, ev_type: string, days: int, hours: int)
{
	print fmt("uptime Entry");
	print fmt("Host = %s user=%s Event_type= %s Days = %d Hours = %d ",host, user, ev_type, days,hours);
}

############################# USB DEVICES ###################################################
event usb_devices(host: string, user: string, ev_type: string, usb_address: int, vendor: string, model: string)
{
	print "usb_devices Entry";
 	print fmt("Host = %s user=%s Event_type= %s Usb_address = %d Vendor = %s Model = %s",host, user, ev_type, usb_address, vendor, model);
}

############################# USER GROUPS ###################################################
event user_groups(host: string, user: string, ev_type: string, uid: int, gid: int)
{
	print fmt("user_groups Entry");
	print fmt("Host = %s user=%s Event_type= %s UID = %d GID = %d ",host, user, ev_type, uid, gid);
}

############################# USERS ######################################################
event users(host: string, user: string, ev_type: string, username: string, uid: int, gid: int)
{
	print "users Entry";
 	print fmt("Host = %s user=%s Event_type= %s UserName = %s UID = %d GID = %d",host, user, ev_type, username, uid, gid);
}

event warning(warning_msg: string)
{
	print fmt("Warning:    %s ", warning_msg);
}

event error(error_msg: string)
{
	print fmt(" %s ", error_msg);
}

