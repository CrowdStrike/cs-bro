# Extends functionality of Intel framework in various ways
# Supports three new indicator types: Email subjects, Usernames, and SSL cert subjects
# CrowdStrike 2014
# josh.liburdi@crowdstrike.com

@load base/frameworks/intel

module Intel;

export {
  redef enum Intel::Type += {
    CERT_SUBJECT,
    EMAIL_SUBJECT
  };

  redef enum Intel::Where += {
    RADIUS::IN_USER_NAME,
    FTP::IN_USER_NAME,
    SMTP::IN_SUBJECT,
    SSL::IN_SERVER_CERT,
    SSL::IN_CLIENT_CERT
  };
}
