extern crate dbus;

use std::sync::Arc;
use std::sync::mpsc;
use std::cell::Cell;
use std::thread;

use dbus::{Connection, BusType, tree, Path};
use dbus::tree::{Interface, Signal, MTFn, Access, MethodErr, EmitsChangedSignal};

// Our storage device
#[derive(Debug)]
struct Device {
    description: String,
    path: Path<'static>,
    index: i32,
    online: Cell<bool>,
    checking: Cell<bool>,
}

// Every storage device has its own object path.
// We therefore create a link from the object path to the Device.
#[derive(Copy, Clone, Default, Debug)]
struct TData;
impl tree::DataType for TData {
    type Tree = ();
    type ObjectPath = Arc<Device>;
    type Property = ();
    type Interface = ();
    type Method = ();
    type Signal = ();
}


impl Device {
    // Creates a "test" device (not a real one, since this is an example).
    fn new_bogus(index: i32) -> Device {
        Device {
            description: format!("This is device {}, which is {}.", index,
                ["totally awesome", "really fancy", "still going strong"][(index as usize) % 3]),
            path: format!("/Device{}", index).into(),
            index: index,
            online: Cell::new(index % 2 == 0),
            checking: Cell::new(false),
        }
    }
}

// Here's where we implement the code for our interface.
fn create_iface(check_complete_s: mpsc::Sender<i32>) -> Interface<MTFn<TData>, TData> {
    let f = tree::Factory::new_fn();

    f.interface("com.example.dbus.rs.device", ())
        .add_p(f.property::<bool,_>("playing", ())
            .access(Access::ReadWrite)
            .emits_changed(EmitsChangedSignal::True)
            .on_get(|i, m| {
                let car: &Arc<Carousel> = m.path.get_data();
                i.append(car.playing.get());
                Ok(())
            })
            .on_set(|i, m| {
                let car: &Arc<Carousel> = m.path.get_data();
                let b: bool = try!(i.read());

                dev.online.set(b);
                Ok(())
            })
        )
        .add_p(f.property::<bool,_>("shuffle", ())
            .access(Access::ReadWrite)
            .emits_changed(EmitsChangedSignal::True)
            .on_get(|i, m| {
                let dev: &Arc<Carousel> = m.path.get_data();
                i.append(dev.checking.get());
                Ok(())
            })
            .on_set(|i, m| {
                let dev: &Arc<Carousel> = m.path.get_data();
                let b: bool = try!(i.read());

                dev.online.set(b);
                Ok(())
            })
        )
        .add_m(f.method("next", (), move |m| {
            let dev: &Arc<Carousel> = m.path.get_data();

            Ok(vec!(m.msg.method_return()))
        }))
}

fn create_tree(devices: &[Arc<Device>], iface: &Arc<Interface<MTFn<TData>, TData>>)
    -> tree::Tree<MTFn<TData>, TData> {

    let f = tree::Factory::new_fn();
    let mut tree = f.tree(());
    for dev in devices {
        tree = tree.add(f.object_path(dev.path.clone(), dev.clone())
            .introspectable()
            .add(iface.clone())
        );
    }
    tree
}

fn run() -> Result<(), Box<std::error::Error>> {
    // Create our bogus devices
    let devices: Vec<Arc<Device>> = (0..10).map(|i| Arc::new(Device::new_bogus(i))).collect();

    // Create tree
    let (check_complete_s, check_complete_r) = mpsc::channel::<i32>();
    let (iface, sig) = create_iface(check_complete_s);
    let tree = create_tree(&devices, &Arc::new(iface));

    // Setup DBus connection
    let c = try!(Connection::get_private(BusType::Session));
    try!(c.register_name("com.example.dbus.rs.advancedserverexample", 0));
    try!(tree.set_registered(&c, true));

    // ...and serve incoming requests.
    for _ in tree.run(&c, c.iter(1000)) {

        // This will be run every second, because we block (waiting for DBus requests)
        // one second at a time.
        if let Ok(idx) = check_complete_r.try_recv() {
            let dev = &devices[idx as usize];
            dev.checking.set(false);
            try!(c.send(sig.msg(&dev.path, &"com.example.dbus.rs.device".into())).map_err(|_| "Sending DBus signal failed"));
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        println!("{}", e);
    }
}
