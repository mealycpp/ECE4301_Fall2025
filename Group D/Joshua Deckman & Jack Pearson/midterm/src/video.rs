use gstreamer::{
    Buffer, Bus, Element, MessageView, Pipeline, State, glib::object::ObjectExt, prelude::{Cast, ElementExt, GstBinExt, GstObjectExt}
};
use gstreamer_app::{AppSink, AppSrc};

pub struct GUI {
    fpsdisplaysink: Element,
    appsrc: AppSrc,
}

pub struct Camera {
    bus: Bus,
    appsink: AppSink,
}

pub fn get_camera() -> Camera {
    let pipeline = Pipeline::default();
    let bus = pipeline.bus().unwrap();
    let bin = gstreamer::parse::bin_from_description(
        "v4l2src device=/dev/video0 ! image/jpeg ! decodebin ! openh264enc ! gdppay ! appsink name=sink",
        false,
    )
    .unwrap();

    pipeline.add(&bin).unwrap();

    let appsink: AppSink = bin.by_name("sink").unwrap().downcast::<AppSink>().unwrap();

    if let Err(_) = pipeline.set_state(State::Playing) {
        while let Some(msg) = bus.pop() {
            let src = msg.src().map(|s| s.path_string()).unwrap_or_default();
            match msg.view() {
                MessageView::Eos(..) => { println!("EOS from {src}"); break; }
                MessageView::Error(err) => {
                    eprintln!("ERROR from {src}: {} ({:?})", err.error(), err.debug());
                    break;
                }
                _ => println!("{:?} from {src}: {msg:?}", msg.type_()),
            }
        }
    }


    Camera { bus, appsink }
}

pub fn get_gui() -> GUI {
    let pipeline = Pipeline::default();
    let bin = gstreamer::parse::bin_from_description(
        "appsrc name=source ! gdpdepay ! openh264dec ! videoconvert ! fpsdisplaysink sync=false name=fps",
        false,
    )
    .unwrap();

    pipeline.add(&bin).unwrap();

    let appsrc: AppSrc = bin.by_name("source").unwrap().downcast::<AppSrc>().unwrap();
    let fpsdisplaysink: Element = bin.by_name("fps").unwrap();

    pipeline.set_state(State::Playing).unwrap();

    GUI {
        fpsdisplaysink,
        appsrc,
    }
}

impl GUI {
    pub fn push(&self, buf: Vec<u8>) {
        let gst_buf = Buffer::from_slice(buf);
        self.appsrc.push_buffer(gst_buf).unwrap();
    }
    pub fn get_fps(&self) -> Option<f32> {
        let res = self
            .fpsdisplaysink
            .property_value("last-message")
            .get::<String>();
        match res {
            Ok(s) => Some(
                s.split_once("current: ")
                    .unwrap()
                    .1
                    .split(',')
                    .next()
                    .unwrap()
                    .trim()
                    .parse::<f32>()
                    .unwrap(),
            ),
            Err(_) => None,
        }
    }
}

impl Camera {
    pub fn pull(&self) -> Vec<u8> {
        let sample_res = self.appsink.pull_sample();
        if sample_res.is_err() {
            while let Some(msg) = self.bus.pop() {
                let src = msg.src().map(|s| s.path_string()).unwrap_or_default();
                match msg.view() {
                    MessageView::Eos(..) => { println!("EOS from {src}"); break; }
                    MessageView::Error(err) => {
                        eprintln!("ERROR from {src}: {} ({:?})", err.error(), err.debug());
                        break;
                    }
                    _ => println!("{:?} from {src}: {msg:?}", msg.type_()),
                }
            }
        }
        let sample = sample_res.unwrap();
        let buffer = sample.buffer().unwrap();
        let map = buffer.map_readable().unwrap();
        map.as_slice().to_vec()
    }
}
