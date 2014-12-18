# Monitors indicator matches and notice activity to correlate malicious activity per host 
# Must be loaded after Intelligence framework
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/frameworks/notice
@load base/frameworks/intel

module CrowdStrike;

export {
  redef enum Notice::Type += {
    Correlated_Alerts
  };
}

# Amount of time to watch for indicator / notice correlations
const alert_correlation_interval = 2min &redef;

# Number of notices to see before alerting on correlations
const alert_correlation_notice_threshold = 2.0 &redef;

# Number of indicators to see before alerting on correlations
const alert_correlation_indicator_threshold = 2.0 &redef;

# Notices to exclude from correlations
const alert_correlation_notice_whitelist: set[string] = {
  "CrowdStrike::Correlated_Alerts",
  "SSL::Invalid_Server_Cert",
  "Weird::Activity",
  } &redef;

# Proxy servers to exclude from correlations
# Indicators and notices tend to funnel at proxy servers, making them useless for this type of detection
const alert_correlation_proxy_whitelist: set[subnet] = {
  } &redef;

# Function to build notices from seen indicators / notices.
function alerts_out(t: table[addr] of set[string], idx: addr): interval
{
local cnt = |t[idx]|;

# Continue if more than one indicator or notice was seen.
if ( cnt > 1 )
  {
  # Local variable to track indicators seen
  local i = 0;
  # Local variable to track notices seen
  local n = 0;
  # Local variable to store sub-message for alert notice
  local sub_msg = "";

  # Build the notice sub-message that contains all unique indicators / notices seen
  for ( [z] in t[idx] )
    {
    # Split all notices and indicators seen
    local parts = split_all(z,/`/);
    # If parts[1] is a notice, increase the notice count
    # Otherwise, parts[1] is an indicator, increase the indicator count
    if ( parts[1] == "Notice" )
      ++n;
    else
      ++i;

    # Add the notice / indicator to the sub-message
    sub_msg += fmt("%s: %s, ",parts[1],parts[3]);
    }

# Clean the end of the sub-message
sub_msg = cut_tail(sub_msg,2);

# If at least one notice and one indicator are seen, generate a meta-notice
if ( n >= 1 && i >= 1 )
  NOTICE([$note=Correlated_Alerts,
          $src=idx,
          $msg=fmt("Host %s was involved with %s unique notices / indicators", idx, cnt),
          $sub=sub_msg,
          $n=cnt,
          $identifier=cat(idx,sub_msg)]);

# If notice threshold is met and no indicators are seen, generate a meta-notice
if ( n >= alert_correlation_notice_threshold && i == 0 )
  NOTICE([$note=Correlated_Alerts,
          $src=idx,
          $msg=fmt("Host %s was involved with %s unique notices", idx, cnt),
          $sub=sub_msg,
          $n=cnt,
          $identifier=cat(idx,sub_msg)]);

# If indicator threshold is met and no notices are seen, generate a meta-notice
if ( n == 0 && i >= alert_correlation_indicator_threshold )
  NOTICE([$note=Correlated_Alerts,
          $src=idx,
          $msg=fmt("Host %s was involved with %s unique indicators", idx, cnt),
          $sub=sub_msg,
          $n=cnt,
          $identifier=cat(idx,sub_msg)]);
  }
return 0secs;
}

# Table where endpoint and indicator / notice data is dynamically stored
global alert_correlation_state: table[addr] of set[string] &create_expire=alert_correlation_interval &expire_func=alerts_out;

# Function to add host and indicator data to table above
function add_indicator(a: addr, ind: string)
{
if ( a !in alert_correlation_state ) 
  alert_correlation_state[a] = set();
if ( a in alert_correlation_state )
  add alert_correlation_state[a][cat("Indicator`",ind)];
}

# Function to add host and notice data to table above
function add_notice(a: addr, note: string)
{
if ( a !in alert_correlation_state )
  alert_correlation_state[a] = set();
if ( a in alert_correlation_state )
  add alert_correlation_state[a][cat("Notice`",note)];
}

# Function to check if hosts should be added to table above
function correlation_is_local(a: addr): bool
{
if ( Site::is_local_addr(a) == T && a !in alert_correlation_proxy_whitelist )
  return T;
else return F;
}

# Processing for indicators
event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
# If the indicator is file related, extract and save the connection data
if ( s?$f )
  if ( s$f?$conns && |s$f$conns| == 1 )
    for ( cid in s$f$conns )
      s$conn = s$f$conns[cid];

# Stop processing if connection data does not exist
if ( ! s?$conn ) return;

# Check if the orginator or responder is in the local network and not a proxy server
if ( correlation_is_local(s$conn$id$orig_h) == T )
  add_indicator(s$conn$id$orig_h,s$indicator);
if ( correlation_is_local(s$conn$id$resp_h) == T )
  add_indicator(s$conn$id$resp_h,s$indicator);
}

# Processing for notices
hook Notice::policy(n: Notice::Info)
{
local note = cat(n$note);

# Check if the orignator is in the local network and not a proxy server
if ( n?$src && note !in alert_correlation_notice_whitelist )
  if ( correlation_is_local(n$src) == T )
    add_notice(n$src,note);

# Check if the responder is in the local network and not a proxy server
if ( n?$dst && note !in alert_correlation_notice_whitelist )
  if ( correlation_is_local(n$dst) == T )
    add_notice(n$dst,note);
}
