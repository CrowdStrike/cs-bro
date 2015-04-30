# Detects MS15-034 vulnerabilities by inspecting inbound HTTP requests and web server responses
# Any generated notices should have their sub value inspected for the appropriate exploitable RANGE values
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com

@load base/frameworks/notice
@load base/protocols/http

module CrowdStrike;

export {
        redef enum Notice::Type += {
                MS15034_Vulnerability,
                MS15034_Server_Crash
        };
}

# RANGE values seen in each connection are stored here
global ranges: table[string] of string;

# Potentially crashed servers are stored here and are dropped from the table after 10 seconds of being added
global crash_check: table[addr] of string &create_expire=10secs;

event bro_init()
{
# do a bunch of stuff required by sumstats
local r1: SumStats::Reducer = [$stream="http.ms15034.down", $apply=set(SumStats::SUM)];
local r2: SumStats::Reducer = [$stream="http.ms15034.up", $apply=set(SumStats::SUM)];
SumStats::create([$name="detect-ms15034",
                  $epoch=5secs,
                  $reducers=set(r1, r2),
                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        if ( "http.ms15034.up" in result && "http.ms15034.down" in result 
                                && result["http.ms15034.down"]$sum > 1 )
                                {
                                local down = result["http.ms15034.down"];
                                local up = result["http.ms15034.up"];
                                local total_sum = down$sum + up$sum;
                                local down_perc = down$sum / total_sum;
                                
                                if ( down_perc > 90 )
                                        {
                                        local sub_msg = fmt("Range used: %s",crash_check[key$host]);
                                        NOTICE([$note=MS15034_Server_Crash,
                                                $src=key$host,
                                                $msg=fmt("%s may have crashed due to MS15-034",cat(key$host)),
                                                $sub=sub_msg,
                                                $identifier=cat(key$host)]);  
                                        }
                                }

                        delete crash_check[key$host];
                        }
                  ]);
}

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
# If the server response code isn't 416, then the traffic is ignored
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

                delete ranges[c$uid];
                }

        else if ( code != 416 )
                delete ranges[c$uid];
        }
}

# If no server response was seen, then poll the web server to see if it has crashed
# The ranges table is cleaned up as connections are dropped from Bro
event connection_state_remove(c: connection)
{
if ( c?$http )
        {
        if ( c$id$resp_h in crash_check )
                {
                if ( ! c$http?$status_code )
                        {
                        SumStats::observe("http.ms15034.down",
                                SumStats::Key($host=c$id$resp_h), 
                                SumStats::Observation($num=1));
                        }
                else
                        {
                        SumStats::observe("http.ms15034.up",
                                SumStats::Key($host=c$id$resp_h), 
                                SumStats::Observation($num=1));
                        }
                }

        if ( c$uid in ranges )
                {
                if ( ! c$http?$status_code )
                        {
                        crash_check[c$id$resp_h] = ranges[c$uid];
                        delete ranges[c$uid];
                        }
                else
                        delete ranges[c$uid];
                }
        }
}
