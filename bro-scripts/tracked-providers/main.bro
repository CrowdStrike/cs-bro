# Log connections to VPS and VPN providers that are important to track
# CrowdStrike 2016
# josh.liburdi@crowdstrike.com
# @jshlbrd

module TrackedProviders;

export {
	redef enum Log::ID += { TrackedProviders::LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:		time &log;
		## Unique ID for the connection.
		uid:		string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:		conn_id &log;
		## Provider IP address.
		provider_h:	addr &log;
		## The name of the provider.
		provider_name:	string &log &optional;
		## The type of provider.
		provider_type:	string	&log &optional;
		};

	## Event that can be handled to access the TrackedProvider 
	## record as it is sent to the logging framework.
	global log_providers: event(rec: Info);
}

redef record connection += {
	provider: Info &optional;
};

type provider_subnet_idx: record {
	provider_subnet:	subnet;
};

type provider_addr_idx: record {
	provider_addr:	addr;
};

type provider_table: record {
	provider_name:	string;
	provider_type:	string;
};

global provider_subnet: table[subnet] of provider_table;
global provider_addr: table[addr] of provider_table;
const provider_subnet_location = "/path/to/tracked-provider-subnet.txt" &redef;
const provider_addr_location = "/path/to/tracked-provider-addr.txt" &redef;

# Create the provider log stream and load the provider list
event bro_init()
{
Log::create_stream(TrackedProviders::LOG, [$columns=Info, $ev=log_providers]);
Input::add_table([$source=provider_subnet_location, $name="provider_subnet_list", $idx=provider_subnet_idx, $val=provider_table, $destination=provider_subnet, $mode=Input::REREAD]);
Input::add_table([$source=provider_addr_location, $name="provider_addr_list", $idx=provider_addr_idx, $val=provider_table, $destination=provider_addr, $mode=Input::REREAD]);
}

# Function to establish a provider info record
function set_session(c: connection, provider_addr: addr)
{
if ( ! c?$provider )
	{
	c$provider = [$ts=network_time(),$id=c$id,$uid=c$uid,$provider_h=provider_addr];
	}
}

# Function to check originator and responder for provider subnets and addrs
function get_provider(c: connection)
{
if ( c?$provider )
	return;

if ( c$id$orig_h in provider_subnet )
	{
	set_session(c,c$id$orig_h);
	c$provider$provider_name = provider_subnet[c$id$orig_h]$provider_name;
	c$provider$provider_type = provider_subnet[c$id$orig_h]$provider_type;
	}

else if ( c$id$orig_h in provider_addr )
	{
	set_session(c,c$id$orig_h);
	c$provider$provider_name = provider_addr[c$id$orig_h]$provider_name;
	c$provider$provider_type = provider_addr[c$id$orig_h]$provider_type;
	}

else if ( c$id$resp_h in provider_subnet )
	{
	set_session(c,c$id$resp_h);
	c$provider$provider_name = provider_subnet[c$id$resp_h]$provider_name;
	c$provider$provider_type = provider_subnet[c$id$resp_h]$provider_type;
	}

else if ( c$id$resp_h in provider_addr )
	{
	set_session(c,c$id$resp_h);
	c$provider$provider_name = provider_addr[c$id$resp_h]$provider_name;
	c$provider$provider_type = provider_addr[c$id$resp_h]$provider_type;
	}
}

# Check each new connection for an IP address in both provider lists
event new_connection(c: connection )
{
get_provider(c);
}

# Generate the tracked_providers.log for each provider connection
event connection_state_remove(c: connection)
{
if ( c?$provider )
	Log::write(TrackedProviders::LOG, c$provider);
}
