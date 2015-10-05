/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef BRO_COMM_QUERY_MANAGER_H
#define BRO_COMM_QUERY_MANAGER_H

#include "Manager.h"

namespace bro_broker {

	/*
	 * QueryManager class is responsible for point to point peer connection
	 * (single master to a single host) and point to multipoint connection 
         * (single master
	 * to multiple hosts). The class also enables a master to subscribe 
         * either to a single query or to multiple queries at the monitoring 
         * hosts. 
	 * This class publically inherits Manager class and adds additoinal 
         * functionality
	 * 
	 * To establish point to point peer connection, this class also uses 
         * the base class Connect().
	 */

class OsqueryManager : public Manager {
friend class StoreHandleVal;
public:
	/**
	 * Constructor.
	 */
	OsqueryManager();

	/**
	 * Destructor.  Any still-pending data store queries are aborted.
	 */
	~OsqueryManager();

	/**
	 * Initiate a remote connection to all hosts of a subgroup.
	 *
	 * @param addr_port A bro table (string of string) which contains
	 * the IP address as a key and the port as a value.
	 * @param retry_interval an interval at which the master host retries 
         * establishing a broken connection with the remote hosts of a group.
	 *
	 * @return true if the connections are successfully established.  
	 */
	bool GroupConnect(RecordVal* addr_port,
	             std::chrono::duration<double> retry_interval);

	/**
	 * Send a subscription message as an event to interested peers
	 * (a single query subscription message to remote host or hosts that 
         * have the interest in the same broker topic).
	 *
	 * @param topic A topic string associated with the print message.
	 * Peers advertise interest by registering to a subscription query 
         * related to a topic name.
	 * @param args the event and SQL query as "EventArgs record values" sent
         *  to a host or group of hosts.
	 * @param inidump set it to true if Master is interested in initial 
         * dump.
	 * @param flags tune the behavior of how the message is sent.
	 *
	 * @return true if the message is sent successfully.
	 */	
	bool Event(std::string topic, RecordVal* args,  bool inidump, 
        Val* flags);

	/**
	 * Send multiple subscripiton messages (multiple queries) as events to 
         * interested peers.
	 * (multiple queries subscription to remote host or hosts).
	 *
	 * @param topic A topic string associated with the print message.
	 * Peers advertise interest by registering to a subscription query 
         * related to a topic name.
	 * @param args a group of events and corresponding SQL queries are sent
         *  to a host or group of hosts.  
	 * @param inidump set it to true if Master is interested in initial 
         * dump.
	 * @param flags tune the behavior of how the message is send.
	 * 
	 * @return true if the messages are sent successfully.
	 */	
	bool GroupEvent(std::string topic, RecordVal* args, bool inidump, 
        Val* flags);

	/**
	 * Creates an EventArgs record value for subscription to a single query.
	 * @param args the event and SQL query. The event is always the first
	 * element in the list.
	 *
	 * @return an EventArgs record value.
	 */
	RecordVal* MakeSubscriptionArgs(val_list* args);

	/**
	 * Creates an EventArgs record value for a subscription to multiple 
         * queries.
	 * @param args Bro table (string of string). The event is always the 
         * first element in the row of bro table.
	 *
	 * @return an EventArgs record value.
	 */
	RecordVal* MakeTableArguments(TableVal* tbl);
	
};
} //end of namespace

extern bro_broker::OsqueryManager* osquery_mgr;
#endif
