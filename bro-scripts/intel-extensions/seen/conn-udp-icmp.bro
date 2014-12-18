# Support for UDP, ICMP, and non-established TCP connections
# This will only generate Intel matches when a connection is removed from Bro
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event Conn::log_conn(rec: Conn::Info)
{
if ( rec?$proto && ( rec$proto != tcp || ( rec?$history && rec$proto == tcp && "h" !in rec$history ) ) ) 
  {
  # duration, start_time, addl, and hot are required fields although they are not used by Intel framework
  local dur: interval;
  local history: string;

  if ( rec?$duration )
    dur = rec$duration;
  else dur = 0secs;

  if ( rec?$history )
    history = rec$history;
  else history = "";

  local c = [$uid = rec$uid,$id = rec$id,$history = history,$duration = dur,$start_time = 0,$addl = "",$hot = 0];

  Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
  Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
  }
}
