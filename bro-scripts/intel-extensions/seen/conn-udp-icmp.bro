# Support for UDP, ICMP, and non-established TCP connections
# This will only generate Intel matches when a connection is removed from Bro
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com
#
# Update by: Brian Kellogg 8/7/2015
#  - updated to run in Bro 2.4

@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event Conn::log_conn(rec: Conn::Info)
{
if ( rec?$proto && ( rec$proto != tcp || ( rec?$history && rec$proto == tcp && "h" !in rec$history ) ) )
  {
  # duration, start_time, addl, and hot are required fields although they are not used by Intel framework
  # for Bro 2.4 we also need to setup $orig and $resp for the connection record being sent to Intel::seen
  # we also need to add the start_time and service for the conn record for Bro 2.4
  local dur: interval;
  local history: string;
  local orig_ep: endpoint;
  local resp_ep: endpoint;
  local start: time;
  local service: set[string];
  local c: connection;

  start = rec$ts;

  orig_ep = [$size = 0,$state = 0,$flow_label = 0];
  resp_ep = [$size = 0,$state = 0,$flow_label = 0];

  if ( rec?$service )
    add service[rec$service];
  else add service[""];

  if ( rec?$duration )
    dur = rec$duration;
  else dur = 0secs;

  if ( rec?$history )
    history = rec$history;
  else history = "";

  c = [$id = rec$id,$orig = orig_ep,$resp = resp_ep,$start_time = start,$duration = dur,$service = service,$history = history,$uid = rec$uid];

  Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
  Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
  }
}
