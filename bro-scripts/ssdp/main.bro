# A simple parser for SSDP traffic. 
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com

module SSDP;

export {
  redef enum Log::ID += { ssdp::LOG };

  type Info: record {
    ## Timestamp for when the event happened.
    ts:				time    &log;
    ## Unique ID for the connection.
    uid:			string  &log;
    ## The connection's 4-tuple of endpoint addresses/ports.
    id:				conn_id &log;
    ## Request search target. 
    ## This value is derived from search requests.
    request_search_target:	string	&log &optional;
    ## Response search target.
    ## This value is derived from advertisements or responses.
    response_search_target:	string	&log &optional;
    ## Device data.
    ## This value should contain a comma-separated list containing 
    ## the OS name, OS version, the string "UPnP/1.0," product name,
    ## and product version. This is specified by the UPnP vendor.
    server:			string	&log &optional;
    ## Advertisement UUID of device.
    usn:			string	&log &optional;
    ## URL for UPnP description of device.
    location:			string	&log &optional;
    ## Vector of all request header fields.
    request_headers:		vector of string &log &optional;
    ## Vector of all response header fields.
    response_headers:		vector of string &log &optional;
    ## Flag the connection if it contains a request.
    seen_request:		bool	&log &default=F;
    ## Flag the connection if it contains a response.
    seen_response:		bool	&log &default=F;
  };

  ## Event that can be handled to access the rdp record as it is sent on
  ## to the logging framework.
  global log_ssdp: event(rec: Info);
}

redef record connection += {
  ssdp: Info &optional;
};

# Function to parse the SSDP data.
function ssdp_headers(s: string): table[string] of string
  {
  local split_data = split_string_all(s,/\x0d\x0a/);
  local trimmed_ssdp: table[string] of string;

  for ( sd in split_data )
    if ( sd % 2 == 0 )
    {
    local split_ssdp = split_string1(split_data[sd],/: ?/);

    if ( |split_ssdp| == 2 )
      trimmed_ssdp[split_ssdp[0]] = split_ssdp[1];
    }

  return trimmed_ssdp;
  }

# Function to initialize the ssdp record.
function set_session(c: connection)
  {
  if ( ! c?$ssdp )
    {
    c$ssdp = [$ts=network_time(),$id=c$id,$uid=c$uid];
    add c$service["ssdp"];
    }
  }

event bro_init()&priority=5
  {
  Log::create_stream(ssdp::LOG, [$columns=Info, $ev=log_ssdp]);
  }

# Function to process SSDP requests.
function ssdp::ssdp_request(state: signature_state, data: string): bool
  {
  local c = state$conn;
  set_session(c);

  local info = c$ssdp;
  info$seen_request = T;

  local ssdp_table = ssdp_headers(data);

  if ( ! info?$request_headers )
    info$request_headers = vector();

  for ( header in ssdp_table )
    {
    info$request_headers[|info$request_headers|] = header;

    if ( header == /[Ss][Tt]/ )
      info$request_search_target = ssdp_table[header];
    }

  return F;
  }

# Function to process SSDP responses.
function ssdp::ssdp_response(state: signature_state, data: string): bool
  {
  local c = state$conn;
  set_session(c);

  local info = c$ssdp;
  info$seen_response = T;

  local ssdp_table = ssdp_headers(data);

  if ( ! info?$response_headers )
    info$response_headers = vector();

  for ( header in ssdp_table )
    {
    info$response_headers[|info$response_headers|] = header;

    if ( header == /([Ss]|[Nn])[Tt]/ )
      info$response_search_target = ssdp_table[header];
    else if ( header == /[Ss][Ee][Rr][Vv][Ee][Rr]/ )
      info$server = ssdp_table[header];
    else if ( header == /[Uu][Ss][Nn]/ )
      info$usn = ssdp_table[header];
    else if ( header == /[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]/ )
      info$location = ssdp_table[header];
    }

  return F;
  }

# Event to write the SSDP log.
event connection_state_remove(c: connection) &priority=-5
  {
  if ( c?$ssdp )
    Log::write(ssdp::LOG, c$ssdp);
  }
