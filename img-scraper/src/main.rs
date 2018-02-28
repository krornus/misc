extern crate futures;
extern crate hyper;
extern crate tokio_core;
use futures::{future,Future,Stream};
use hyper::{Client, Error, Chunk, Body};
use tokio_core::reactor::Core;

#[derive(Debug)]
enum Meta {
    PNG(u32,u32),
    Unknown,
}

fn main() {

    let url = "http://www.freepngimg.com/download/light/1-2-light-png-file.png";

    let mut core = Core::new().unwrap();
    let client = Client::new(&core.handle());

    let uri = url.parse().unwrap();

    let work = client.get(uri).and_then(|res| {
        res.body().collect()
    });

    let r = core.run(work);

    println!("{:?}",r);
}


struct Image<T: ImageSpecification> {
    metadata: Meta,
    image: T,
}

macro_rules! try_handlers {
    ( $i:expr; $f:ident$(, $($rest:ident),*)* ) => (
        if let Some(x) = $f::parse($i) {
            Some(x)
        }
        $($(
            else if let Some(x) = $rest::parse($i) {
                Some(x)
            }
        )*)*
        else {
            None
        }
    );
}

struct ImagePNG { }

impl<T: ImageSpecification> Image<T> {

    fn new(i: Vec<u8>) -> Option<Image<T>> {
        if let Some(img) = try_handlers![&i; ImagePNG] {
            let meta = img.metadata();

            Some(Image {
                image: img,
                metadata: meta,
            })
        }
    }

    fn metadata(i: Vec<u8>) -> Meta {

    }
}


impl ImageSpecification for ImagePNG {
    #[inline]
    fn magic() -> Vec<u8> {
        vec![137,80,78,71,13,10,26,10]
    }

    fn parse(img: &Vec<u8>) -> Option<ImagePNG> {

        if Self::is_valid(img) {
            Some(ImagePNG { })
        } else {
            None
        }
    }

    fn metadata(&self) -> Meta {
        Meta::PNG(0,0)
    }
}

trait ImageSpecification {

    #[inline]
    fn magic() -> Vec<u8>;
    fn parse(img: &Vec<u8>) -> Option<ImagePNG>;
    fn metadata(&self) -> Meta;
    fn is_valid(img: &Vec<u8>) -> bool {
        &ImagePNG::magic() == img
    }
}
