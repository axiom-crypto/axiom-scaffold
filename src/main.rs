use std::env::var;

use axiom_eth::{
    providers::{GOERLI_PROVIDER_URL, MAINNET_PROVIDER_URL},
    Network,
};
use axiom_scaffold::scaffold::AxiomChip;
use ethers_providers::{Http, Provider};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

fn main() {
    env_logger::init();

    let infura_id = var("INFURA_ID").expect("Infura ID not found: set INFURA_ID env var");
    let network = Network::Mainnet;
    let provider_url = match network {
        Network::Mainnet => MAINNET_PROVIDER_URL,
        Network::Goerli => GOERLI_PROVIDER_URL,
    };
    let provider = Provider::<Http>::try_from(format!("{provider_url}{infura_id}").as_str())
        .expect("could not instantiate HTTP Provider");

    let axiom = AxiomChip::<Fr>::default();

    let block = axiom.eth_getBlockByNumber(&provider, 16_000_000);
    // Debug display of a block header field:
    // dbg!(block.number);
    // Note that block.number.bytes has fixed length 4, but the variable string length is specified by block.number.len
    // E.g., 16_000_000 = 0xf42400, so block.number.bytes = [0xf4, 0x24, 0x00, 0x00] and block.number.len = 3

    // `AxiomChip` also has access to all functions in other chips like `GateChip` and `RangeChip`.
    // For example,
    let number = block.number.evaluate(&mut axiom.ctx(), axiom.gate());
    assert_eq!(number.value(), &Fr::from(16_000_000u64));

    // All variables are private by default. You can expose an `AssignedValue` to be public by calling `expose_public`:
    axiom.expose_public(number);

    axiom.mock();

    // Uncomment to run the real prover; can be slow / memory intensive depending on your machine
    // axiom.prove();
}
