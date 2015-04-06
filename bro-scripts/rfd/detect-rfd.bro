# Detect reflected file download attacks as described in 
# http://packetstorm.foofus.com/papers/presentations/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf
# CrowdStrike 2015
# josh.liburdi@crowdstrike.com

@load base/frameworks/notice
@load base/protocols/http

module CrowdStrike;

export {
  redef enum Notice::Type += {
    Reflected_File_Download
  };

  redef enum HTTP::Tags += {
    RFD
  };
}

const rfd_content_type: set[string] = {
  "application/json",
  "application/x-javascript",
  "application/javascript",
  "application/notexist",
  "text/json",
  "text/x-javascript",
  "text/plain",
  "text/notexist",
  "application/xml",
  "text/xml",
  "text/html"
} &redef;

const rfd_pattern =   /\"\|\|/ |
                      /\"\<\</ |
                      /\"\>\>/ |
                      /[^?]*\.bat(\;|$)/ |
                      /[^?]*\.cmd(\;|$)/ |
                      /[^?]*[Ss][Ee][Tt][Uu][Pp][:alnum:]*?\.[:alpha:]{3,4}(\;|$)/ |
                      /[^?]*[Ii][nn][Ss][Tt][Aa][Ll][Ll][:alnum:]*?\.[:alpha:]{3,4}(\;|$)/ |
                      /[^?]*[Uu][Pp][Dd][Aa][Tt][Ee][:alnum:]*?\.[:alpha:]{3,4}(\;|$)/ |
                      /[^?]*[Uu][Nn][In][Ss][Tt][:alnum:]*?\.[:alpha:]{3,4}(\;|$)/ &redef;


# Perform a pattern match for reflected file downloads.
# If found, add HTTP tag and generate a notice.
function rfd_do_notice(c: connection)
{
if ( rfd_pattern in c$http$uri )
  {
  add c$http$tags[RFD];
  NOTICE([$note=Reflected_File_Download,
          $msg="A reflected file download was attempted",
          $sub=c$http$uri,
          $id=c$id,
          $identifier=cat(c$id$orig_h,c$id$resp_h,c$http$uri)]);
  }
}

# Check for reflected file downloads in HTTP transactions that have a 
# CONTENT-TYPE header. Valid RFD content types are identified anywhere
# in the CONTENT-TYPE header value.
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
if ( is_orig || ! c$http?$uri || c$http$uri == "" ) return;

if ( name == "CONTENT-TYPE" )
  for ( rct in rfd_content_type )
    if ( rct in value )
      rfd_do_notice(c);
}

# Check for reflected file downloads in HTTP transactions that do not have a 
# CONTENT-TYPE header.
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
if ( is_orig || ! c$http?$uri || c$http$uri == "" ) return;

local headers: set[string];

for ( h in hlist )
  {
  local name = hlist[h]$name;
  add headers[name];
  }

if ( "CONTENT-TYPE" !in headers ) 
  rfd_do_notice(c);
else return;
}
