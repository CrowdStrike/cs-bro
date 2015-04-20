# Detects MS15-034 vulnerabilities by inspecting inbound HTTP requests and web server responses 
# Any generated notices should have their sub value inspected for the appropriate exploitable RANGE values 
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com

@load base/frameworks/notice
@load base/protocols/http

module CrowdStrike;

export {
        redef enum Notice::Type += {
                MS15034_Vulnerability
        };
}

# RANGE values seen in each connection are stored here
global ranges: table[string] of string;

# RANGE values are extracted from client HTTP headers if the web server has a private IP address or if the web server is within the local network
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
if ( ! is_orig )
        return;

if ( Site::is_local_addr(c$id$resp_h) == T || Site::is_private_addr(c$id$resp_h) == T ) 
        if ( name == "RANGE" )
                ranges[c$uid] = value;
}

# If an HTTP reply is seen for connections in the ranges table, then the web server's response code is checked for a match with the vulnerability
# A notice is generated that contains the client RANGE request
event http_reply(c: connection, version: string, code: count, reason: string)
{
if ( c$uid in ranges ) 
        {
        if ( code == 416 )
                {
                local sub_msg = fmt("Range used: %s",ranges[c$uid]);
                NOTICE([$note=MS15034_Vulnerability,
                        $conn=c,
                        $msg=fmt("%s may be vulnerable to MS15-034",c$id$resp_h),
                        $sub=sub_msg,
                        $identifier=cat(c$id$resp_h,ranges[c$uid])]);
                }
        
        delete ranges[c$uid]; 
        }
}

# The ranges table is cleaned up as connections are dropped from Bro
event connection_state_remove(c: connection)
{
if ( c?$http )
        if ( c$uid in ranges )
                delete ranges[c$uid];
}
