# Creates a count of HTTP User-Agent length and vector of HTTP User-Agent variables
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com
# @jshlbrd

@load base/protocols/http

module HTTP;

redef record HTTP::Info += {
	user_agent_length:	count			&log &optional;
	user_agent_vars:	vector of string	&log &optional;
};

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
if ( is_orig )
	{
	if ( name == "USER-AGENT" )
		{
		c$http$user_agent_length = |value|;
		local cut_value = value;
		if ( value == /.*\)$/ )
			cut_value = cut_tail(value,1);
		c$http$user_agent_vars = extract_keys(cut_value, /\x20?\(|\;\x20?|\)\x20/);
		}
	}
}
