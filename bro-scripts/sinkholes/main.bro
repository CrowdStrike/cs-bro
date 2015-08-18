# Flag queries for sinkhole domains
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com
# @jshlbrd

module DNS;

export {
    redef record DNS::Info += {
        sinkhole: bool &log &default=F;
    };
}

type sinkhole_idx: record {
	ip:	string;
};

global sinkhole_list: set[string] = set();
const sinkhole_list_location = "./sinkhole_ip.dat" &redef;

event bro_init()
{
Input::add_table([$source=sinkhole_list_location, $name="sinkhole", $idx=sinkhole_idx, $destination=sinkhole_list, $mode=Input::REREAD]);
}

event Input::end_of_data(name: string, source: string)
{
if ( name == "sinkhole" )
    {
    local msg = fmt("Sinkhole list updated at %s",network_time());
    Log::write(Reporter::LOG, [$ts=network_time(), $level=Reporter::INFO, $message=msg]);
    }
}

event dns_end(c: connection, msg: dns_msg)
{
if ( ! c?$dns ) return;
if ( ! c$dns?$answers ) return;

for ( answer in c$dns$answers )
    {
    local ans = c$dns$answers[answer];
    if ( is_valid_ip(ans) )
        if ( ans in sinkhole_list )
            {
            c$dns$sinkhole = T;
            }
    }
}
