# Intel framework support for RADIUS usernames 
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/protocols/radius
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event RADIUS::log_radius(rec: RADIUS::Info)
{
if ( rec?$username && rec?$result )
  if ( rec$result == "success" )
    Intel::seen([$indicator=rec$username,
                 $indicator_type=Intel::USER_NAME,
                 $where=RADIUS::IN_USER_NAME]);
}
