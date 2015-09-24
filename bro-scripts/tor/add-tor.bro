module Tor;

export {
    redef record Conn::Info += {
        found_tor: bool &log &default=F;
    };
}

event connection_state_remove (c: connection)
{
if ( c?$tor )
    c$conn$found_tor = T;
}
