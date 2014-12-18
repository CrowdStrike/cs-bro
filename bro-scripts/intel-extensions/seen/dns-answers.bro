# Intel framework support for DNS answers 
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/protocols/dns
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event dns_end(c: connection, msg: dns_msg)
{
if ( c$dns?$answers )
  {
  local ans = c$dns$answers;
  for ( i in ans )
    {
    if ( ans[i] == ip_addr_regex )
      Intel::seen([$host=to_addr(ans[i]),
                   $conn=c,
                   $where=DNS::IN_RESPONSE]);
    else
      Intel::seen([$indicator=ans[i],
                   $indicator_type=Intel::DOMAIN,
                   $conn=c,
                   $where=DNS::IN_RESPONSE]);
    }
  }
}
