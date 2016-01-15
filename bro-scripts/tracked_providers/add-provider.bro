module TrackedProviders;

export {
        redef record Conn::Info += {
                found_tracked_provider: bool &log &default=F;
        };
}

event connection_state_remove (c: connection)
{
if ( c?$provider )
        c$conn$found_tracked_provider = T;
}
