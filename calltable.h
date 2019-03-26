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


#include <vector>
#include <set>
#include <string>
#include <map>
#include <memory>
#include <time.h>

#include <pcap.h>
#include <arpa/inet.h>

#ifndef INT32_MAX
#define INT32_MAX                (2147483647)
#endif

struct addr_port {
	//in_addr_t addr;
	uint16_t  port;
};

struct calltable_element {
	unsigned char had_bye;
	unsigned char had_t38;
	unsigned char rtpmap_event;
	std::string caller;
	std::string callee;
	std::string call_id;
	std::set<struct addr_port> ip_port;
	std::vector<uint32_t>  ssrc;
	time_t first_packet_time;
	time_t last_packet_time;
	pcap_dumper_t *f_pcap;
	std::string fn_pcap;
};

typedef std::shared_ptr<calltable_element> calltable_element_ptr;

struct addr_addr_id {
    in_addr_t saddr;
    in_addr_t daddr;
    uint16_t  id;
};

class calltable
{
public:
	calltable();
	calltable_element_ptr add(
		const std::string & call_id,
		const std::string & caller,
		const std::string & callee,
		time_t time);
	calltable_element_ptr find_by_call_id(
		const std::string & call_id);
	bool add_ip_port(
		calltable_element_ptr ce,
		in_addr_t addr,
		unsigned short port);
	calltable_element_ptr find_ip_port(
		in_addr_t addr,
		unsigned short port);
	void add_ipfrag(
		struct addr_addr_id aai,
		pcap_dumper_t *f);
	void delete_ipfrag(
		struct addr_addr_id aai);
	pcap_dumper_t *get_ipfrag(
		struct addr_addr_id aai);
	int do_cleanup(time_t currtime);
	bool erase_non_t38;
	int opt_absolute_timeout;
private:
	std::map <addr_addr_id, pcap_dumper_t *> ipfrags;
	std::map <std::string, calltable_element_ptr> callid_table;
	std::map <struct addr_port,std::string> addr_port_table;
};
