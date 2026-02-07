/*
    This file is part of pcapsipdump

    pcapsipdump is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    pcapsipdump is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    ---

    Project's home: http://pcapsipdump.sf.net/
*/

#include <unistd.h>
#include "trigger.h"
#include "calltable.h"

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

using namespace std;
bool operator <(addr_addr_id const& a, addr_addr_id const& b)
{
	return a.saddr < b.saddr ||
		(a.saddr == b.saddr && a.daddr < b.daddr) ||
		(a.saddr == b.saddr && a.daddr == b.daddr && a.id < b.id);
}

bool operator <(addr_port const& a, addr_port const& b)
{
    return a.addr < b.addr || (a.addr == b.addr && a.port < b.port );
}

calltable::calltable()
{
    erase_non_t38 = 0;
    opt_absolute_timeout = INT32_MAX;
}

calltable_element_ptr calltable::add(
	const std::string & call_id,
	const std::string & caller,
	const std::string & callee,
	time_t time)
{
	calltable_element_ptr ce(new calltable_element());
	callid_table[call_id] = ce;
	
	ce->rtpmap_event = 101;
	ce->had_t38 = 0;
	ce->had_bye = 0;
	ce->call_id = call_id;
	ce->caller = caller;
	ce->callee = callee;
	ce->f_pcap = NULL;
	ce->first_packet_time = time;
	ce->last_packet_time = time;
	trigger.trigger(&trigger.open,
		ce->fn_pcap,
		ce->caller,
		ce->callee,
		ce->call_id,
		ce->first_packet_time);
	return ce;
}

calltable_element_ptr calltable::find_by_call_id(
	const std::string & call_id, const std::string& as_call_id)
{
	auto ce = callid_table.find(call_id);
	if (ce != callid_table.end()){
		return ce->second;
	}

	if (as_call_id.empty()) {
		return nullptr;
	}

	ce = callid_table.find(as_call_id);
	if (ce != callid_table.end())
	{
		callid_table[call_id] = ce->second;
		return ce->second;
	}

	return nullptr;
}

bool calltable::add_ip_port(
	    calltable_element_ptr ce,
	    in_addr_t addr,
	    unsigned short port)
{
	struct addr_port addr_port{ addr, port };
	addr_port_table[addr_port] = ce->call_id;
	ce->ip_port.insert(addr_port);
	return true;
}

calltable_element_ptr calltable::find_ip_port(in_addr_t addr, unsigned short port)
{
	struct addr_port addr_port { addr, port };
	const auto it_addr_port = addr_port_table.find(addr_port);
	if (it_addr_port != addr_port_table.end())
	{
		return find_by_call_id(it_addr_port->second);
	}
	return nullptr;
}


int calltable::do_cleanup(time_t currtime) {

	for (auto ce = callid_table.begin(); ce != callid_table.end();)
	{
		if ((currtime - ce->second->last_packet_time > 300) ||
			(ce->second->had_bye && currtime - ce->second->last_packet_time > opt_absolute_timeout))
		{
			for (auto aai : ce->second->ipfrags) {

				auto it_frags = ipfrags_table.find(aai);
				if (it_frags != ipfrags_table.end() && it_frags->second == ce->second->call_id) {
					this->ipfrags_table.erase(aai);
				}
			}

			if (ce->second->f_pcap != NULL) {
				pcap_dump_close(ce->second->f_pcap);
				ce->second->f_pcap = NULL;
				if (erase_non_t38 && !ce->second->had_t38) {
					unlink(ce->second->fn_pcap.c_str());
				}
				else {
					trigger.trigger(&trigger.close,
						ce->second->fn_pcap,
						ce->second->caller,
						ce->second->callee,
						ce->second->call_id,
						ce->second->first_packet_time);
				}
			}
			for (const auto & addr_port : ce->second->ip_port)
			{
				const auto & it_callid = addr_port_table.find(addr_port);
				if (it_callid != addr_port_table.end() && it_callid->second == ce->second->call_id){
					addr_port_table.erase(it_callid);
				}
			}

			ce = callid_table.erase(ce);
		}
		else {
			ce++;
		}
	}
	return 0;
}

void calltable::add_ipfrag(struct addr_addr_id aai, calltable_element_ptr ce) {
	ipfrags_table[aai] = ce->call_id;
	ce->ipfrags.insert(aai);
}

void calltable::delete_ipfrag(struct addr_addr_id aai) {
	const auto it_frags = ipfrags_table.find(aai);
	if (it_frags != ipfrags_table.end()) {
		auto it_ce = callid_table.find(it_frags->second);
		if (it_ce != callid_table.end()) {
			it_ce->second->ipfrags.erase(aai);
		}
		ipfrags_table.erase(it_frags);
	}
}

calltable_element_ptr calltable::find_by_ipfrag(struct addr_addr_id aai) {
	const auto & it = ipfrags_table.find(aai);
	if(it != ipfrags_table.end()){
		auto it_ce = callid_table.find(it->second);
		if (it_ce != callid_table.end()) {
			return it_ce->second;
		}
	}
	return nullptr;
}
