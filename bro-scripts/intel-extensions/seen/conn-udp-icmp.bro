# Support for UDP, ICMP, and non-established TCP connections
# This will only generate Intel matches when a connection is removed from Bro
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event connection_state_remove(c: connection)
{
if ( c$conn?$proto && ( c$conn$proto != tcp || ( c$conn?$history && c$conn$proto == tcp && "h" !in c$conn$history ) ) )
        {
        Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
        Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
        }
}
