# Detects endpoints searching Reddit for values related to the Mac.BackDoor.iWorm malware
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/protocols/http
@load base/frameworks/notice

module CrowdStrike;

export {
  redef enum Notice::Type += {
    Mac_BackDoor_iWorm,
  };
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
# stop processing the event if an endpoint is not searching Reddit
if ( ! is_orig || ! c$http?$host || ! c$http?$uri ) return;
if ( c$http$host != "www.reddit.com" ) return;
if ( "?q=" !in c$http$uri ) return;

# locate and extract the Reddit search value
local clean_reddit_uri = find_last(c$http$uri,/\?q\=.*/);
local uri_parts = split_all(clean_reddit_uri,/&/);
local extract_reddit_search = split1(uri_parts[1],/\?q\=/);

# confirm that the search value is 8 bytes of an MD5 hash
if ( |extract_reddit_search[2]| == 16 && extract_reddit_search[2] == /^[A-Fa-f0-9]{16}$/ )
  NOTICE([$note=Mac_BackDoor_iWorm,
          $conn=c,
          $msg=fmt("%s connected to a Reddit page that may be related to Mac.BackDoor.iWorm",c$id$orig_h),
          $sub=c$http$uri,
          $identifier=cat(c$id$orig_h,c$http$uri)]);
}

