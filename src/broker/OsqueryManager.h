/* 
 *  Copyright (c) 2015, nexGIN, RC.
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
	 * (single master to single host), group of peers connection (signle master
	 * to multiple hosts), single query subscription at osquery side and multiple
	 * queries subscription at osquery side. 
	 * 
	 * This class publically inherits Manager class and adds additoinal functionality
	 * (group of connections single query subscription and group of queries of 
	 * subscription).
	 * 
	 * To establish sigle host connection, this class provides base class Connect().
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
	 * @param addr_port A bro table (string of string) which contains
	 * IP address as key and port as value.
	 * 
	 * @param retry_interval an interval at which to retry establishing the
	 * connection with the remote peer.
	 * @return true if it's possible to try connecting with the peers and
	 * they're new peers.  
	 */
	bool GroupConnect(RecordVal* addr_port,
	             std::chrono::duration<double> retry_interval);
	/**
	 * Send a subscription message as event to any interested peers
	 * (single query subscription to remote host/hosts of same interest).
	 * @param topic a topic string associated with the print message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param args the event and SQL query as EventArgs record value to send to peers.
	 * @param flags tune the behavior of how the message is sent.
	 *
	 * @return true if the message is sent successfully.
	 */	
	bool Event(std::string topic, RecordVal* args, int flags);

	/**
	 * Send multiple subscripiton messages(multiple queries) as events to any interested peers.
	 * (multiple queries subscription to remote host/hosts).
	 * @param topic A topic string associated with the print message.
	 * Peers advertise interest by registering a subscription to some prefix
	 * of this topic name.
	 * @param args group of events and SQL query pairs to send to peers.  
	 * @param flags tune the behavior of how the message is send.
	 * 
	 * @return true if the messages are sent successfully.
	 */	
	bool GroupEvent(std::string topic, RecordVal* args, Val* flags);

	/**
	 * Create an EventArgs record value for single query subscription.
	 * @param args the event and SQL query.  The event is always the first
	 * elements in the list.
	 *
	 * @return an EventArgs record value.
	 */
	RecordVal* MakeSubscriptionArgs(val_list* args);

	/**
	 * Create an EventArgs record value for group of queries subscription.
	 * @param args Bro table (string of string).  The event is always the first
	 * elements in the table row.
	 *
	 * @return an EventArgs record value.
	 */
	RecordVal* MakeTableArguments(TableVal* tbl);
	
};
} //end of namespace

extern bro_broker::OsqueryManager* osquery_mgr;
#endif
