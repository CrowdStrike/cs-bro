# Creates a vector from a DNS query
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com
# @jshlbrd

@load base/protocols/dns
@load base/protocols/http

module DNS;

redef record DNS::Info += {
	query_vec:        vector of string  &log &optional;
	query_vec_size:   count             &log &optional;
};

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
	if( c?$dns ) {
		c$dns$query_vec = HTTP::extract_keys(query,/\./);
		c$dns$query_vec_size = |c$dns$query_vec|;
	}
}
