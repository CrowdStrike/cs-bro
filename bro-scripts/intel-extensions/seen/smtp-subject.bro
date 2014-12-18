# Intel framework support for SMTP subjects 
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/protocols/smtp
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) 
{
if ( c$smtp?$subject )
  Intel::seen([$indicator=c$smtp$subject,
               $indicator_type=Intel::EMAIL_SUBJECT,
               $conn=c,
               $where=SMTP::IN_SUBJECT]);
}
