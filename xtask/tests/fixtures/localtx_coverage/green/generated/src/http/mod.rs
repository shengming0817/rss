pub mod demo_v1;

pub struct LocalTxSpec {}

pub struct HttpSpec {
    pub local_tx: Option<LocalTxSpec>,
}

pub const LOCAL_TX_SPECS: &[HttpSpec] = &[demo_v1::write::SPEC];
