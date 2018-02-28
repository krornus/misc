extern crate dbus;

use dbus::{Connection, BusType, Message};
use dbus::arg::Array;

use std::fmt::Write;

fn main() {
    let c = Connection::get_private(BusType::Session).unwrap();
    let m = Message::new_method_call("com.example.dbustest", "/hello", "com.example.dbustest", "Hello").expect("failed to create method")
        .append1::<&str>("the client");

    let r = c.send_with_reply_and_block(m, 2000).expect("no reply");

    let arr: &str  = r.get1().expect("could not get reply arg");

    println!("Greeting response: '{}'", arr);
}
