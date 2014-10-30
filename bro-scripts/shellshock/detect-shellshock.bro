# Monitors traffic for Shellshock exploit attempts
# When exploits are seen containing IP addresses and domain values, monitors traffic for 60 minutes watching for endpoints to connect to IP addresses and domains seen in exploit attempts
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/dhcp
@load base/protocols/smtp

module CrowdStrike;

export {
  redef enum Notice::Type += {
    Shellshock_DHCP,
    Shellshock_HTTP,
    Shellshock_SMTP,
    Shellshock_Successful_Conn
  };
}

const shellshock_pattern = /((\(|%28)(\)|%29)( |%20)(\{|%7B)|(\{|%7B)(\:|%3A)(\;|%3B))/ &redef;

const shellshock_commands = /wget/ | /curl/;

global shellshock_servers: set[addr] &create_expire=60min;
global shellshock_hosts: set[string] &create_expire=60min;

# function to locate and extract domains seen in shellshock exploit attempts
function find_domain(ss: string)
{
local parts1 = split_all(ss,/[[:space:]]/);
for ( p in parts1 )
  if ( "http" in parts1[p] )
    {
    local parts2 = split_all(parts1[p],/\//);
    local output = parts2[5];
    }

if ( output !in shellshock_hosts )
  add shellshock_hosts[output];
}

# function to locate and extract IP addresses seen in shellshock exploit attempts
function find_ip(ss: string): bool
{
local b = F;
local remote_servers = find_ip_addresses(ss);

if ( |remote_servers| > 0 )
  {
  b = T;
  for ( rs in remote_servers )
    {
    local s = to_addr(remote_servers[rs]);
    if ( s !in shellshock_servers )
      add shellshock_servers[s];
    }
  }

return b;
}

# event to identify shellshock HTTP exploit attempts
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
{
if ( ! is_orig ) return;
if ( shellshock_pattern !in value ) return;

# generate a notice of the HTTP exploit attempt
NOTICE([$note=Shellshock_HTTP,
        $conn=c,
        $msg=fmt("Host %s may have attempted a shellshock HTTP exploit against %s", c$id$orig_h, c$id$resp_h),
        $sub=fmt("Command: %s",value),
        $identifier=cat(c$id$orig_h,c$id$resp_h,value)]);

# check the exploit attempt for IP addresses
# if an IP address is found, then do not look for domains
if ( find_ip(value) == T ) return;

# check the exploit attempt for domains
if ( shellshock_commands in value )
  find_domain(value);
}

# event to identify shellshock DHCP exploit attempts
event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
if ( shellshock_pattern !in host_name ) return;

# generate a notice of the DHCP exploit attempt
NOTICE([$note=Shellshock_DHCP,
        $conn=c,
        $msg=fmt("Host %s may have attempted a shellshock DHCP exploit against %s", c$id$orig_h, c$id$resp_h),
        $sub=fmt("Command: %s",host_name),
        $identifier=cat(c$id$orig_h,c$id$resp_h,host_name)]);

# check the exploit attempt for IP addresses
# if an IP address is found, then do not look for domains
if ( find_ip(host_name) == T ) return;

# check the exploit attempt for domains
if ( shellshock_commands in host_name )
  find_domain(host_name);
}

# event to identify endpoints connecting to domains seen in shellshock exploit attempts
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
{
if ( name != "HOST" ) return;
if ( value in shellshock_hosts )
  # generate a notice of HTTP connection to domain seen in exploit attempts
  NOTICE([$note=Shellshock_Successful_Conn,
          $conn=c,
          $msg=fmt("Host %s connected to a domain seen in a shellshock exploit", c$id$orig_h),
          $sub=fmt("Domain: %s",value),
          $identifier=cat(c$id$orig_h,value)]);
}

# event to identify shellshock SMTP exploit attempts
event mime_one_header(c: connection, h: mime_header_rec)
{
if ( ! c?$smtp || ! h?$value ) return;
if (  shellshock_pattern !in h$value ) return;

# generate a notice of the SMTP exploit attempt
NOTICE([$note=Shellshock_SMTP,
        $conn=c,
        $msg=fmt("Host %s may have attempted a shellshock SMTP exploit against %s", c$id$orig_h, c$id$resp_h),
        $sub=fmt("Command: %s",h$value),
        $identifier=cat(c$id$orig_h,c$id$resp_h,h$value)]);

# check the exploit attempt for IP addresses
# if an IP address is found, then do not look for domains
if ( find_ip(h$value) == T ) return;

# check the exploit attempt for domains
if ( shellshock_commands in h$value )
  find_domain(h$value);
}

# event to identify endpoints connecting to IP addresses seen in shellshock exploit attempts
event connection_state_remove(c: connection)
{
if ( c$id$resp_h in shellshock_servers )
  # generate a notice of connection to IP address seen in exploit attempts
  NOTICE([$note=Shellshock_Successful_Conn,
          $conn=c,
          $msg=fmt("Host %s connected to an IP address seen in a shellshock exploit", c$id$orig_h),
          $sub=fmt("IP address: %s",c$id$resp_h),
          $identifier=cat(c$id$orig_h,c$id$resp_h)]);
}
