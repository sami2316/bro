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

#include "OsqueryManager.h"
#include "Data.h"
#include "Store.h"
#include <broker/broker.hh>
#include <broker/report.hh>
#include <cstdio>
#include <unistd.h>
#include "util.h"
#include "Var.h"
#include "Reporter.h"
#include "broker/comm.bif.h"
#include "broker/data.bif.h"
#include "broker/messaging.bif.h"
#include "broker/store.bif.h"
#include "logging/Manager.h"
#include "DebugLogger.h"
#include "iosource/Manager.h"


using namespace std;

bro_broker::OsqueryManager::OsqueryManager()
	:Manager()
	{
	}

bro_broker::OsqueryManager::~OsqueryManager()
	{
	}

bool bro_broker::OsqueryManager::GroupConnect(RecordVal* addr_port,
	             std::chrono::duration<double> retry_interval)
{
	if ( ! Manager::Enabled() )
		return false;

	if ( ! addr_port->Lookup(0) )
		return false;
	//Extracting vector (containing IPs and Ports) from EventArgs 
	auto vv = addr_port->Lookup(0)->AsVectorVal();
	for ( auto i = 0u; i < vv->Size(); i+=2 )
	{
		auto addr = vv->Lookup(i)->AsRecordVal()->Lookup(0);
		auto addr_val = static_cast<DataVal*>(addr);

		
		auto port = vv->Lookup(i+1)->AsRecordVal()->Lookup(0);
		auto port_val = static_cast<DataVal*>(port);

		Manager::Connect(broker::to_string(addr_val->data),
			std::stoul(broker::to_string(port_val->data)),
                        retry_interval);
	}
	return true;
}

bool bro_broker::OsqueryManager::Event(std::string topic, RecordVal* args,
        bool inidump, Val* flags)
	{
	if ( ! Manager::Enabled() )
		return false;

	if ( ! args->Lookup(0) )
		return false;
	// first argument is the event name
	auto event_name = args->Lookup(0)->AsString()->CheckString();
	// second argument is SQL query
	auto query = args->Lookup(1)->AsString()->CheckString();
	// make broker message
	broker::message msg;
	msg.emplace_back(event_name);
	msg.emplace_back(query);
	msg.emplace_back(inidump);

	// send broker::message to interested peer.
	endpoint->send(move(topic), move(msg), send_flags_to_int(flags));
	return true;
	}

bool bro_broker::OsqueryManager::GroupEvent(std::string topic, RecordVal* args, 
        bool inidump, Val* flags)
	{
	if ( ! Manager::Enabled() )
		return false;

	if ( ! args->Lookup(0) )
		return false;
	// Query Table is returned as a vector. Odd index contains an event's 
        //name and an even index contains a SQL query. 
	auto vv = args->Lookup(0)->AsVectorVal();
	broker::message msg;
	// iterate over vector and formulate broker messages for each query.
	for ( auto i = 0u; i < vv->Size(); i+=2 )
	{
		msg.reserve(2);
		auto event_name = vv->Lookup(i)->AsRecordVal()->Lookup(0);
		auto event_val = static_cast<DataVal*>(event_name);
		msg.emplace_back(event_val->data);

		auto query = vv->Lookup(i+1)->AsRecordVal()->Lookup(0);
		auto query_val = static_cast<DataVal*>(query);
		msg.emplace_back(query_val->data);
		msg.emplace_back(inidump);
	
		endpoint->send(topic, msg, send_flags_to_int(flags));
		msg.clear();
	}
		
		
	return true;
	}


RecordVal* bro_broker::OsqueryManager::MakeSubscriptionArgs(val_list* args)
	{
	if ( ! Manager::Enabled() )
		return nullptr;

	auto rval = new RecordVal(BifType::Record::BrokerComm::EventArgs);

	//extract event_name and SQL string form arguments
	for ( auto i = 0; i < 2; i++ )
		{
		//make record value
		auto data_val = (*args)[i];
		rval->Assign(i, data_val);
			
		}

	return rval;
	}



RecordVal* bro_broker::OsqueryManager::MakeTableArguments(TableVal* tbl)
	{
	if ( ! Manager::Enabled() )
		return nullptr;
	//Convert table argument to a pure list
	ListVal* idxs = tbl->ConvertToPureList();

	auto rval = new RecordVal(BifType::Record::BrokerComm::EventArgs);
	auto arg_vec = new VectorVal(vector_of_data_type);
	rval->Assign(0, arg_vec);
	//place an event's name at the odd indices and SQL query at the even
        //indices
	for (int i = 0; i < idxs->Length(); i++ )
		{

		auto key_val = make_data_val(idxs->Index(i));
		arg_vec->Assign(i*2, key_val );
		auto val_val = make_data_val(tbl->Lookup(idxs->Index(i), 
                        false));
		arg_vec->Assign((i*2)+1, val_val);
		}

	return rval;
	}



