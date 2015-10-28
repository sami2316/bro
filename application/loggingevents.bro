module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

export {
	redef enum Log::ID += { PLOG };
	redef enum Log::ID += { FLOG };
	redef enum Log::ID += { SLOG };

	type Process: record {
	Time: string &log;
	host: string &log;
	user: string &log;
	ev_type: string &log;
	pid: int &log;
	name: string &log;
	cwd: string &log;
	};

	type POpen_Files: record {
	Time: string &log;
	host: string &log;
	user: string &log;
	ev_type: string &log;
	pid: int &log;
	fd: int &log;
	path: string &log;
	};

	type POpen_Socket: record {
	Time: string &log;
	host: string &log;
	user: string &log;
	ev_type: string &log;
	pid: int &log;
	socket: int &log;
	protocol: int &log;
	remote_address: string &log;
	};
}

###################################################################################
global process_open_files: event(host: string, user: string, ev_type: string,  pid: int, fd: int, path: string);

###################################################################################
global processes: event(host: string, user: string, ev_type: string, pid: int, name: string, cwd: string,on_disk: int);

###################################################################################
global process_open_sockets: event(host: string, user: string, ev_type: string, pid: int, socket: int, protocol: int, remote_address: string);

###################################################################################
global warning: event(warning_msg: string);

###################################################################################
global error: event(error_msg: string);

###################################################################################

global gtable: table[string] of string;

###################################################################################
global ready: event(peer_name: string);

event bro_init()
{
	osquery::enable();
	osquery::subscribe_to_events("/bro/event/");
	osquery::listen(broker_port,"192.168.0.120"); 

	gtable["192.168.1.211"] = "/bro/event/group1";
	gtable["192.168.1.33"] = "/bro/event/group2"; 

	Log::create_stream(PLOG, [$columns=Process, $path="process"]);
	Log::create_stream(FLOG, [$columns=POpen_Files, $path="file_events"]);
	Log::create_stream(SLOG, [$columns=POpen_Socket, $path="socket_events"]);
}


event BrokerComm::incoming_connection_established(peer_name: string)
{
	print "BrokerComm::incoming_connection_establisted",  peer_name;

	if (peer_name in gtable)
		osquery::print("/bro/event/",gtable[peer_name]);
	else
		osquery::print("/bro/event/", "/bro/event/default");

}

event ready(peer_name: string)
{
	print fmt("Sending queries at Peer =  %s ", peer_name);

	#######################################################################################
	osquery::subscribe(process_open_files,"SELECT pid,fd,path FROM process_open_files","/bro/event/group1");
 	
	#######################################################################################
	osquery::subscribe(processes,"SELECT pid,name,cwd,on_disk FROM processes","/bro/event/group1");

	#######################################################################################
	osquery::subscribe(process_open_sockets,"SELECT pid,socket,protocol,remote_address FROM process_open_sockets",
		"/bro/event/group1","ADD",T);

}

event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;

}

########################### FILE EVENTS ####################################################
event process_open_files(host: string, user: string, ev_type: string,  pid: int, fd: int, path: string)
{
	print fmt("file_events Entry");
	print fmt("Time = %s  Host = %s user=%s Event_type= %s pid = %d fd = %d path = %s",strftime("%Y/%M/%d %H:%m:%S",current_time()),host, user, ev_type, pid,fd,path);
	Log::write(osquery::FLOG, [$Time= strftime("%Y/%M/%d %H:%m:%S",network_time()), $host=host ,
	$user=user, $ev_type= ev_type, $pid= pid, $fd= fd, $path = path]);
}

########################## PROCESSES #########################################################
event processes(host: string, user: string, ev_type: string, pid: int, name: string, cwd: string, on_disk: int)
{
	print fmt("processes Entry");
	print fmt("Time = %s Host = %s user=%s Event_type= %s PID = %d Name = %s cwd = %s on_disk=%d",strftime("%Y/%M/%d %H:%m:%S",current_time()),
		host, user, ev_type, pid,name,cwd,on_disk);
	Log::write(osquery::PLOG, [$Time= strftime("%Y/%M/%d %H:%m:%S",network_time()), $host=host ,$user=user,
	 	$ev_type= ev_type, $pid= pid, $name= name, $cwd = cwd]);
}

########################## open_sockets #########################################################
event process_open_sockets(host: string, user: string, ev_type: string, pid: int, socket: int, protocol: int, remote_address: string)
{
	print fmt("processes Entry");
	print fmt("Time = %s Host = %s user=%s Event_type= %s PID = %d socket = %d protocol = %d path= %s",strftime("%Y/%M/%d %H:%m:%S",current_time()),
		host, user, ev_type, pid,socket,protocol,remote_address);
	Log::write(osquery::SLOG, [$Time= strftime("%Y/%M/%d %H:%m:%S",network_time()), $host=host ,$user=user, $ev_type= ev_type, $pid= pid,
	 $socket= socket, $protocol = protocol, $remote_address = remote_address]);
}

############################# Warning and Errors #########################################
event warning(warning_msg: string)
{
	print fmt("Warning:    %s ", warning_msg);
}

event error(error_msg: string)
{
	print fmt(" %s ", error_msg);
}
###################################################################################

