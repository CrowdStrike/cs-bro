# Intel framework support for SSL certificate subjects
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/protocols/ssl
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event ssl_established(c: connection)
{
if ( c$ssl?$subject )
  Intel::seen([$indicator=c$ssl$subject,
               $indicator_type=Intel::CERT_SUBJECT,
               $conn=c,
               $where=SSL::IN_SERVER_CERT]);

if ( c$ssl?$client_subject )
  Intel::seen([$indicator=c$ssl$client_subject,
               $indicator_type=Intel::CERT_SUBJECT,
               $conn=c,
               $where=SSL::IN_CLIENT_CERT]);
}
