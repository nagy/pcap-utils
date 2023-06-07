use std::net::SocketAddrV4;

#[derive(Debug, Clone)]
pub struct TcpInfoTuple {
    pub ssocket: SocketAddrV4,
    pub dsocket: SocketAddrV4,
    pub syn: bool,
    pub finrst: bool,
    pub ack: bool,
}

impl TcpInfoTuple {
    fn swap(&self) -> Self {
        Self {
            ssocket: self.dsocket,
            dsocket: self.ssocket,
            syn: self.syn,
            finrst: self.finrst,
            ack: self.ack,
        }
    }
    fn closed(&self) -> Self {
        Self {
            ssocket: self.ssocket,
            dsocket: self.dsocket,
            syn: self.syn,
            finrst: true,
            ack: self.ack,
        }
    }
    #[cfg(test)]
    fn syned(&self) -> Self {
        Self {
            ssocket: self.ssocket,
            dsocket: self.dsocket,
            syn: true,
            finrst: self.finrst,
            ack: self.ack,
        }
    }
}
impl PartialEq for TcpInfoTuple {
    fn eq(&self, other: &Self) -> bool {
        self.ssocket == other.ssocket && self.dsocket == other.dsocket
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct TcpSegmenter {
    state: Vec<TcpInfoTuple>,
}

impl TcpSegmenter {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.state.len()
    }
    #[cfg(test)]
    pub fn num_open(&self) -> usize {
        let mut count = 0;
        for v in &self.state {
            if !v.finrst {
                count += 1;
            }
        }
        count
    }
    pub fn find(&self, other: &TcpInfoTuple) -> Option<usize> {
        let mut ret = None;
        for (index, v) in self.state.iter().enumerate() {
            if v == other {
                ret = Some(index);
            }
            if v == &other.swap() {
                ret = Some(index);
            }
        }
        ret
    }
    pub fn add(&mut self, other: &TcpInfoTuple) {
        if other.finrst {
            // find and close
            if let Some(found) = self.find(other) {
                let vmut = self.state.get_mut(found).unwrap();
                *vmut = vmut.closed()
            } else {
                // closing an already closed stream should be okay
            }
            return;
        }
        if other.syn && !other.ack {
            self.state.push(other.clone());
        }
    }
}

impl std::ops::AddAssign<TcpInfoTuple> for TcpSegmenter {
    fn add_assign(&mut self, other: TcpInfoTuple) {
        self.add(&other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap() {
        let tcpinfo = TcpInfoTuple {
            ssocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            dsocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            syn: true,
            finrst: false,
            ack: true,
        };
        assert_eq!(
            tcpinfo.swap(),
            TcpInfoTuple {
                ssocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
                dsocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
                syn: true,
                finrst: false,
                ack: true,
            }
        );
    }

    #[test]
    fn stack() {
        let mut segmenter = TcpSegmenter::default();
        segmenter += TcpInfoTuple {
            ssocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            dsocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            syn: true,
            finrst: false,
            ack: true,
        };
        segmenter += TcpInfoTuple {
            ssocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            dsocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            syn: false,
            finrst: false,
            ack: false,
        };
        segmenter += TcpInfoTuple {
            ssocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            dsocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            syn: false,
            finrst: false,
            ack: false,
        };
        segmenter += TcpInfoTuple {
            ssocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            dsocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            syn: false,
            finrst: false,
            ack: false,
        };
        assert_eq!(segmenter.len(), 1)
    }

    #[test]
    fn stack_multi() {
        let mut segmenter = TcpSegmenter::default();
        let first = TcpInfoTuple {
            ssocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            dsocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            syn: true,
            finrst: false,
            ack: true,
        };
        let second = TcpInfoTuple {
            ssocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            dsocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            syn: false,
            finrst: false,
            ack: false,
        };
        assert_eq!(segmenter.num_open(), 0);
        segmenter += first.clone();
        segmenter += second.clone();
        assert_eq!(segmenter.find(&first), Some(0));
        assert_eq!(segmenter.find(&second), Some(0));
        assert_eq!(segmenter.len(), 1);
        assert_eq!(segmenter.num_open(), 1);
        segmenter += first.closed();
        assert_eq!(segmenter.len(), 1);
        assert_eq!(segmenter.num_open(), 0);
        // new stream
        segmenter += first.clone();
        assert_eq!(segmenter.find(&first), Some(1));
    }

    #[test]
    fn numbering() {
        let mut segmenter = TcpSegmenter::default();
        let first = TcpInfoTuple {
            ssocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            dsocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            syn: false,
            finrst: false,
            ack: false,
        };
        let closed = first.closed();
        segmenter += first.syned();
        segmenter += first.swap().clone();
        segmenter += first.clone();
        segmenter += first.swap().clone();
        segmenter += first.clone();
        segmenter += first.swap().clone();
        segmenter += closed.clone();
        assert_eq!(segmenter.find(&closed), Some(0));
        let second = TcpInfoTuple {
            ssocket: SocketAddrV4::new([10, 0, 0, 1].into(), 52000),
            dsocket: SocketAddrV4::new([192, 168, 1, 1].into(), 4000),
            syn: false,
            finrst: false,
            ack: false,
        };
        segmenter += second.syned();
        // new stream
        assert_eq!(segmenter.find(&second), Some(1));
    }
}
