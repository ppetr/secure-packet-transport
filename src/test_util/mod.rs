#[cfg(test)]
pub mod tests {
    use std::fmt::Display;
    use std::io as io;
    use std::io::{Read, Write};
    use std::sync::mpsc::{Receiver, RecvError, SyncSender, sync_channel};

    #[derive(Debug)]
    pub struct Channel {
        writer: SyncSender<Vec<u8>>,
        reader: Receiver<Vec<u8>>,
    }

    impl Channel {
        pub fn create_pair(bound: usize) -> (Channel, Channel) {
            let (sender1, receiver1) = sync_channel(bound);
            let (sender2, receiver2) = sync_channel(bound);
            (Channel { writer: sender1, reader: receiver2 },
             Channel { writer: sender2, reader: receiver1 })
        }

        fn to_io_result<E>(err: E) -> io::Error where E: Display {
            use std::io::{Error, ErrorKind};
            Error::new(ErrorKind::BrokenPipe, err.to_string())
        }
    }

    impl Write for Channel {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writer.send(buf.to_vec()).map_err(Channel::to_io_result)?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for Channel {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::cmp::min;
            let vec = match self.reader.recv() {
                Err(RecvError { }) => return Ok(0),
                Ok(payload) => payload,
            };
            // Silently truncate the value, if the buffer is too small.
            let len = min(vec.len(), buf.len());
            buf[..len].clone_from_slice(&vec[..len]);
            Ok(len)
        }
    }
}
