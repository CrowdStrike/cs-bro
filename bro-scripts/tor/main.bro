# Log Tor connections based on IP addresses along with Tor node metadata
# Based on data collected from torstatus.blutmagie.de
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com
# @jshlbrd

module Tor;

export {
	redef enum Log::ID += { TOR::LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:               time 	  &log;
		## Unique ID for the connection.
		uid:              string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id &log;
		## Tor node IP address.
		tor_ip:           addr    &log &optional;
		## Tor node router name.
		router_name:      string  &log &optional;
		## Tor node host name.
		host_name:        string  &log &optional;
		## Tor node platform / version number.
		platform:         string  &log &optional;
		## Tor node country code location.
		country_code:     string  &log &optional;
		## Tor node bandwidth (in KB/s).
		bandwidth:        count	  &log &optional;
		## Tor node estimated uptime.
		uptime:           time	  &log &optional;
		## Tor node router port.
		router_port:      count	  &log &optional;
		## Tor node directory port.
		directory_port:   count	  &log &optional;
		## Tor node auth flag.
		auth_flag:        bool	  &log &optional;
		## Tor node exit flag.
		exit_flag:        bool	  &log &optional;
		## Tor node fast flag.
		fast_flag:        bool	  &log &optional;
		## Tor node guard flag.
		guard_flag:       bool	  &log &optional;
		## Tor node named flag.
		named_flag:       bool	  &log &optional;
		## Tor node stable flag.
		stable_flag:      bool	  &log &optional;
		## Tor node running flag.
		running_flag:     bool	  &log &optional;
		## Tor node valid flag.
		valid_flag:       bool	  &log &optional;
		## Tor node v2dir flag.
		v2dir_flag:       bool	  &log &optional;
		## Tor node hibernating flag.
		hibernating_flag: bool	  &log &optional;
		## Tor node bad exit flag.
		bad_exit_flag:    bool	  &log &optional;
	};

	## Event that can be handled to access the Tor record as it is sent on
	## to the logging framework.
	global log_tor: event(rec: Info);
}

redef record connection += {
	tor: Info &optional;
};

type tor_idx: record {
	tor_ip:	addr;
};

type tor_table: record {
	router_name:      string;
	country_code:     string;
	bandwidth:        count;
	uptime:           double;
	host_name:        string;
	router_port:      count;
	directory_port:   string;
	auth_flag:        count;
	exit_flag:        count;
	fast_flag:        count;
	guard_flag:       count;
	named_flag:       count;
	stable_flag:      count;
	running_flag:     count;
	valid_flag:       count;
	v2dir_flag:       count;
	platform:         string;
	hibernating_flag: count;
	bad_exit_flag:    count;
};

global torlist: table[addr] of tor_table = table();
const torlist_location = "bro-tor.txt" &redef;

# Create the Tor log stream and load the Tor list
event bro_init()
{
Log::create_stream(TOR::LOG, [$columns=Info, $ev=log_tor]);
Input::add_table([$source=torlist_location, $name="torlist", $idx=tor_idx, $val=tor_table, $destination=torlist, $mode=Input::REREAD]);
}

# Function to establish a Tor info record
function set_session(c: connection)
{
if ( ! c?$tor )
	{
	add c$service["tor"];
	c$tor = [$ts=network_time(),$id=c$id,$uid=c$uid];
	}
}

# Function to convert blutmagie Tor flags from count to bool
function convert_flag(flag: count): bool
{
if ( flag == 1 )
	return T;
else return F;
}

# Function to set data in the Tor info record
function set_data(c: connection, tor_ip: addr)
{
c$tor$tor_ip = tor_ip;
if ( torlist[tor_ip]?$router_name )
	c$tor$router_name = torlist[tor_ip]$router_name;
if ( torlist[tor_ip]?$host_name )
	c$tor$host_name = torlist[tor_ip]$host_name;
if ( torlist[tor_ip]?$platform )
	c$tor$platform = torlist[tor_ip]$platform;
if ( torlist[tor_ip]?$country_code )
	c$tor$country_code = torlist[tor_ip]$country_code;
if ( torlist[tor_ip]?$bandwidth )
	c$tor$bandwidth = torlist[tor_ip]$bandwidth;

if ( torlist[tor_ip]?$uptime )
	{
	# Uptime is recorded by hour, so we need to convert it to seconds
	local uptime_hr = torlist[tor_ip]$uptime;
	local uptime_time = ( uptime_hr * 3600 );
	c$tor$uptime = double_to_time(uptime_time);
	}

if ( torlist[tor_ip]?$router_port )
	c$tor$router_port = torlist[tor_ip]$router_port;
if ( torlist[tor_ip]?$directory_port )
	if ( torlist[tor_ip]$directory_port != "None" )
		c$tor$directory_port = to_count(torlist[tor_ip]$directory_port);
if ( torlist[tor_ip]?$auth_flag )
	c$tor$auth_flag = convert_flag(torlist[tor_ip]$auth_flag);
if ( torlist[tor_ip]?$exit_flag )
	c$tor$exit_flag = convert_flag(torlist[tor_ip]$exit_flag);
if ( torlist[tor_ip]?$fast_flag )
	c$tor$fast_flag = convert_flag(torlist[tor_ip]$fast_flag);
if ( torlist[tor_ip]?$guard_flag )
	c$tor$guard_flag = convert_flag(torlist[tor_ip]$guard_flag);
if ( torlist[tor_ip]?$named_flag )
	c$tor$named_flag = convert_flag(torlist[tor_ip]$named_flag);
if ( torlist[tor_ip]?$stable_flag )
	c$tor$stable_flag = convert_flag(torlist[tor_ip]$stable_flag);
if ( torlist[tor_ip]?$running_flag )
	c$tor$running_flag = convert_flag(torlist[tor_ip]$running_flag);
if ( torlist[tor_ip]?$valid_flag )
	c$tor$valid_flag = convert_flag(torlist[tor_ip]$valid_flag);
if ( torlist[tor_ip]?$v2dir_flag )
	c$tor$v2dir_flag = convert_flag(torlist[tor_ip]$v2dir_flag);
if ( torlist[tor_ip]?$hibernating_flag )
	c$tor$hibernating_flag = convert_flag(torlist[tor_ip]$hibernating_flag);
if ( torlist[tor_ip]?$bad_exit_flag )
	c$tor$bad_exit_flag = convert_flag(torlist[tor_ip]$bad_exit_flag);
}

# Generate reporter message when the Tor list is updated
event Input::end_of_data(name: string, source: string)
{
if ( strcmp(name, "torlist") == 0 )
	{
	local msg = fmt("Tor list updated at %s",network_time());
	Log::write(Reporter::LOG, [$ts=network_time(), $level=Reporter::INFO, $message=msg]);
	}
}

# Check each new connection for an IP address in the Tor list
event new_connection(c: connection )
{
if ( c$id$orig_h in torlist )
	{
	set_session(c);
	set_data(c,c$id$orig_h);
	}
else if ( c$id$resp_h in torlist )
	{
	set_session(c);
	set_data(c,c$id$resp_h);
	}
}

# Generate the tor.log for each Tor connection
event connection_state_remove(c: connection)
{
if ( c?$tor )
	{
	Log::write(TOR::LOG, c$tor);
	}
}
