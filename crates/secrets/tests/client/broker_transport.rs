use secrets::proto::PROTOCOL_VERSION;

fn hello() -> String {
    format!("HELLO\tversion={PROTOCOL_VERSION}")
}

#[path = "broker_transport/basics.rs"]
mod basics;
#[path = "broker_transport/grants_and_control.rs"]
mod grants_and_control;
