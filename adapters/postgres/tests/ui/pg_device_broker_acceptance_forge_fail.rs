//! INVARIANT: MQTT-BROKER-ACCEPTANCE-MINT-01 { level = "Medium", exec = "test", source = "trybuild" }

fn forge_receipt() -> diport::BrokerAccepted {
    diport::BrokerAccepted(())
}

fn forge_mint() -> diport::BrokerAcceptanceMint {
    diport::BrokerAcceptanceMint(())
}

fn main() {}
