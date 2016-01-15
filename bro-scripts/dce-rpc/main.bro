module DceRpc;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                ## Timestamp for when the event happened.
                ts:             time    &log;
                ## Unique ID for the connection.
                uid:            string  &log;
                ## The connection's 4-tuple of endpoint addresses/ports.
                id:             conn_id &log;
                ## UUID of the binding interface.
                int_uuid:       string  &log &optional;
                ## Description for the UUID of the binding interface.
                int_uuid_desc:  string	&log &optional;
                ## opnum seen in the call.
                opnum:          count   &log &optional;
                ## Call message type.
                ## Either REQUEST or RESPONSE.
                msg_type:       string  &log &optional;
                ## Length of the stub data in the call.
                stub_len:       count   &log &optional;
        };

        ## Event that can be handled to access the dcerpc record as it is sent on
        ## to the logging framework.
        global log_dcerpc: event(rec: Info);

        ## Flag to ignore interface UUID values specified in ignore_int_uuid_set.
        const ignore_int_uuid_bool = T &redef;
        ## Set of interface UUID values to ignore ( if ignore_int_uuid_bool is set to true ).
        const ignore_int_uuid_set = set("e1af8308-5d1f-11c9-91a4-08002b14a0fa") &redef;
}

redef record connection += {
        dcerpc: Info &optional;
};

event bro_init() &priority=5
    {
    Log::create_stream(DceRpc::LOG, [$columns=DceRpc::Info, $ev=log_dcerpc]);
    }

function set_session(c: connection)
    {
    if ( ! c?$dcerpc )
        {
        add c$service["dce-rpc"];
        c$dcerpc = [$ts=network_time(),$id=c$id,$uid=c$uid];
        }
    }

function write_session(c: connection, ts: time, msg_type: string, opnum: count, stub_len: count)
    {
    local rec = c$dcerpc;
    rec$ts = ts;
    rec$msg_type = msg_type;
    rec$opnum = opnum;
    rec$stub_len = stub_len;
    Log::write(DceRpc::LOG, rec);
    }

event dce_rpc_bind(c: connection, uuid: string) &priority=5
    {
    if ( ignore_int_uuid_bool )
        if ( uuid in ignore_int_uuid_set )
            return;

    set_session(c);
    c$dcerpc$int_uuid = uuid;

    if ( uuid in DceRpc::uuid_map )
    	c$dcerpc$int_uuid_desc = DceRpc::uuid_map[uuid];
    }

event dce_rpc_request(c: connection, opnum: count, stub: string) &priority=5
    {
    if ( c?$dcerpc )
        {
        if ( ! c$dcerpc?$int_uuid )
            return;

        write_session(c,network_time(),"REQUEST",opnum,|stub|);
        }
    }

event dce_rpc_response(c: connection, opnum: count, stub: string) &priority=5
    {
    if ( c?$dcerpc )
        {
        if ( ! c$dcerpc?$int_uuid )
            return;

        write_session(c,network_time(),"RESPONSE",opnum,|stub|);
        }
    }
