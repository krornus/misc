extern crate dbus;

use dbus::{Message, Connection, BusType, NameFlag};
use dbus::tree::{Factory, MethodInfo, MethodErr, MethodType, DataType};

const BUS_NAME: &str = "com.example.dbustest";

fn main() {

    let c = Connection::get_private(BusType::Session).unwrap();
    c.register_name(BUS_NAME, NameFlag::ReplaceExisting as u32).unwrap();

    let mut carousel = Carousel {
        paths: vec![],
        indices: vec![],
        current_path: 0,
        current_index: 0,
        paused: false,
    };

    let f = Factory::new_fnmut::<()>();

    let tree = f.tree(()).add(f.object_path("/media", ()).introspectable().add(
        {
            let intro = f.interface(BUS_NAME, ());
                .add_m(
                    f.method("TogglePlay", (), move |m| {
                        carousel.TogglePlay(m)
                    })
                    .outarg::<bool,_>("state")
                )
                .add_m(
                    f.method("Next", (), move |m| {
                        carousel.Next(m)
                    })
                    .outarg::<bool,_>("state")
                )
                .add_m(
                    f.method("Previous", (), move |m| {
                        carousel.Previous(m)
                    })
                    .outarg::<bool,_>("state")
                )
                .add_m(
                    f.method("Remove", (), move |m| {
                        carousel.Remove(m)
                    })
                    .outarg::<bool,_>("state")
                )
        }
    ));

    tree.set_registered(&c, true).unwrap();
    c.iter(1000).with(tree).count();
}

struct Carousel<'a> {
    paused: bool,
    paths: Vec<&'a str>,
    indices: Vec<usize>,
    current_path: usize,
    current_index: usize,
}

impl<'a> Carousel<'a> {
    fn toggle_play(&mut self) -> bool {

        self.paused = ! self.paused;
        self.paused
    }

    fn next(&mut self) {
        let index = self.current_index + 1;
        let max = self.paths.len();

        self.set_image(index % max);
    }

    fn previous(&mut self) {
        let index = self.current_index - 1;
        let max = self.paths.len();

        self.set_image(index % max);
    }

    fn remove(&mut self) -> bool {
        if self.paths.len() == 0 {
            false
        } else {
            self.paths.remove(self.current_path);

            let mut indices = Vec::with_capacity(self.indices.len() - 1);
            let current_index = self.current_index;

            for index in self.indices.iter() {
                if *index > current_index {
                    indices.push(index - 1);
                } else if *index < current_index {
                    indices.push(*index);
                }
            }

            self.indices = indices;

            self.set_image(current_index);

            true
        }
    }

    fn set_image(&mut self, index: usize) -> bool {

        /* if it is zero, we could have no paths */
        if (index == 0 && self.paths.len() == 0) ||
            index >= self.paths.len() {

            false
        } else {
            self.current_index = index;
            self.current_path = self.indices[index];

            true
        }
    }
}

impl<'a> Carousel<'a> {
    fn TogglePlay<M: MethodType<D>, D: DataType>(
            &mut self,
            m: &MethodInfo<M, D>
        )
        -> Result<Vec<Message>, MethodErr>
    {
        let mret = m.msg.method_return().append1(self.toggle_play());
        Ok(vec![mret])
    }

    fn Next<M: MethodType<D>, D: DataType>(
            &mut self,
            m: &MethodInfo<M, D>
        )
        -> Result<Vec<Message>, MethodErr>
    {
        self.next();
        let mret = m.msg.method_return();
        Ok(vec![mret])
    }

    fn Previous<M: MethodType<D>, D: DataType>(
            &mut self,
            m: &MethodInfo<M, D>
        )
        -> Result<Vec<Message>, MethodErr>
    {
        self.previous();
        let mret = m.msg.method_return();
        Ok(vec![mret])
    }

    fn Remove<M: MethodType<D>, D: DataType>(
            &mut self,
            m: &MethodInfo<M, D>
        )
        -> Result<Vec<Message>, MethodErr>
    {
        let mret = m.msg.method_return().append1(self.remove());
        Ok(vec![mret])
    }
}
