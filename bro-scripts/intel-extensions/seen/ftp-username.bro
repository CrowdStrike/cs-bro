# Intel framework support for FTP usernames 
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/protocols/ftp
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

event ftp_request(c: connection, command: string, arg: string)
{
if ( command == "USER" )
 Intel::seen([$indicator=arg,
              $indicator_type=Intel::USER_NAME,
              $conn=c,
              $where=FTP::IN_USER_NAME]);
}
