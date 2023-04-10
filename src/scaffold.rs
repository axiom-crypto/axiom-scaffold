#![allow(non_snake_case)]
use ark_std::{end_timer, start_timer};
use axiom_eth::{
    block_header::{
        EthBlockHeaderChip, EthBlockHeaderTraceWitness, GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
        MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
    },
    keccak::{FnSynthesize, KeccakChip},
    providers::{get_block_rlp, get_block_storage_input},
    rlp::{
        builder::{RlcThreadBreakPoints, RlcThreadBuilder},
        rlc::{RlcFixedTrace, RlcTrace},
        RlpChip,
    },
    storage::{EIP1186ResponseDigest, EthBlockAccountStorageTraceWitness, EthStorageChip},
    EthChip, EthCircuitBuilder, Field, Network,
};
use ethers_core::types::{Address, H256, U256};
use ethers_providers::{Http, Middleware, Provider};
use halo2_base::{
    gates::{GateChip, RangeChip, RangeInstructions},
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    utils::fs::gen_srs,
    AssignedValue, Context,
};
use rand_core::OsRng;
use std::{
    cell::{RefCell, RefMut},
    env::var,
};
use tokio::runtime::Runtime;

use super::containers::EthBlock;

type KeccakRlcs<F> =
    (Vec<(RlcFixedTrace<F>, RlcFixedTrace<F>)>, Vec<(RlcTrace<F>, RlcFixedTrace<F>)>);

pub const ACCOUNT_PROOF_MAX_DEPTH: usize = 10;
pub const STORAGE_PROOF_MAX_DEPTH: usize = 10;

#[derive(Debug)]
pub struct AxiomChip<F: Field> {
    pub range: RangeChip<F>,
    pub keccak: RefCell<KeccakChip<F>>,
    pub builder: RefCell<RlcThreadBuilder<F>>,

    instances: Vec<AssignedValue<F>>,
    header_witness: Vec<EthBlockHeaderTraceWitness<F>>,
    storage_witness: Vec<EthBlockAccountStorageTraceWitness<F>>,
}

impl<F: Field> Default for AxiomChip<F> {
    fn default() -> Self {
        Self::new(RlcThreadBuilder::mock())
    }
}

impl<F: Field> Clone for AxiomChip<F> {
    // deep clone
    fn clone(&self) -> Self {
        Self {
            range: self.range.clone(),
            keccak: RefCell::new(self.keccak.borrow().clone()),
            builder: RefCell::new(self.builder.borrow().clone()),
            instances: self.instances.clone(),
            header_witness: self.header_witness.clone(),
            storage_witness: self.storage_witness.clone(),
        }
    }
}

impl<F: Field> AxiomChip<F> {
    pub fn new(builder: RlcThreadBuilder<F>) -> Self {
        let lookup_bits = var("LOOKUP_BITS").map(|l| l.parse().unwrap_or(8)).unwrap_or(8);
        Self {
            range: RangeChip::default(lookup_bits),
            keccak: RefCell::new(KeccakChip::default()),
            builder: RefCell::new(builder),
            instances: Default::default(),
            header_witness: Default::default(),
            storage_witness: Default::default(),
        }
    }

    pub fn ctx(&self) -> RefMut<Context<F>> {
        RefMut::map(self.builder.borrow_mut(), |b| b.gate_builder.main(0))
    }

    pub fn gate(&self) -> &GateChip<F> {
        self.range.gate()
    }

    pub fn range(&self) -> &RangeChip<F> {
        &self.range
    }

    pub fn rlp_chip(&self) -> RlpChip<F> {
        RlpChip::new(&self.range, None)
    }

    pub fn eth_chip(&self) -> EthChip<'_, F> {
        EthChip::new(RlpChip::new(&self.range, None), None)
    }

    pub fn expose_public(&mut self, value: AssignedValue<F>) {
        self.instances.push(value);
    }

    pub fn instances(&self) -> &[AssignedValue<F>] {
        &self.instances
    }

    pub fn header_witness(&self) -> &[EthBlockHeaderTraceWitness<F>] {
        &self.header_witness
    }

    pub fn storage_witness(&self) -> &[EthBlockAccountStorageTraceWitness<F>] {
        &self.storage_witness
    }

    /// Get block header from provider by number. The provider provides the chain ID. Currently Ethereum mainnet and Goerli are supported.
    /// Returns the parsed block header where each field is a variable-length bytestring.
    pub fn eth_getBlockByNumber(
        &mut self,
        provider: &Provider<Http>,
        block_number: u32,
    ) -> EthBlock<F> {
        let rt = Runtime::new().unwrap();
        let chain_id = rt.block_on(provider.get_chainid()).unwrap();
        let network = match chain_id {
            U256([1, 0, 0, 0]) => Network::Mainnet,
            U256([5, 0, 0, 0]) => Network::Goerli,
            _ => panic!("Unsupported chain id"),
        };
        let block = rt.block_on(provider.get_block(block_number as u64)).unwrap().unwrap();
        let mut block_header = get_block_rlp(&block);
        let max_len = match network {
            Network::Mainnet => MAINNET_BLOCK_HEADER_RLP_MAX_BYTES,
            Network::Goerli => GOERLI_BLOCK_HEADER_RLP_MAX_BYTES,
        };
        block_header.resize(max_len, 0u8);

        let witness = self.eth_chip().decompose_block_header_phase0(
            &mut self.ctx(),
            &mut self.keccak.borrow_mut(),
            &block_header,
            network,
        );
        let block = (&witness).into();
        self.header_witness.push(witness);
        block
    }

    /// Matches the `eth_getProof` JSON-RPC call. Note that this will return a result matching the JSON-RPC call, even if account or storage slot is empty.
    ///
    /// This function assigns `address`, `slots`, and `block_number` as *private* witnesses. You must separately constrain them or make them public as needed.
    pub fn eth_getProof(
        &mut self,
        provider: &Provider<Http>,
        address: Address,
        slots: Vec<H256>,
        block_number: u32,
    ) -> EIP1186ResponseDigest<F> {
        let rt = Runtime::new().unwrap();
        let chain_id = rt.block_on(provider.get_chainid()).unwrap();
        let network = match chain_id {
            U256([1, 0, 0, 0]) => Network::Mainnet,
            U256([5, 0, 0, 0]) => Network::Goerli,
            _ => panic!("Unsupported chain id"),
        };
        let input = get_block_storage_input(
            provider,
            block_number,
            address,
            slots,
            ACCOUNT_PROOF_MAX_DEPTH,
            STORAGE_PROOF_MAX_DEPTH,
        );
        let input = input.assign(&mut self.ctx());
        let (witness, digest) = self.eth_chip().parse_eip1186_proofs_from_block_phase0(
            &mut self.builder.borrow_mut().gate_builder,
            &mut self.keccak.borrow_mut(),
            input,
            network,
        );
        self.storage_witness.push(witness);
        digest
    }

    pub fn create(
        self,
        break_points: Option<RlcThreadBreakPoints>,
    ) -> EthCircuitBuilder<F, impl FnSynthesize<F>> {
        let prover = self.builder.borrow().witness_gen_only();
        let circuit = EthCircuitBuilder::new(
            self.instances,
            self.builder.take(),
            self.keccak,
            self.range,
            break_points,
            move |builder: &mut RlcThreadBuilder<F>,
                  rlp: RlpChip<F>,
                  keccak_rlcs: KeccakRlcs<F>| {
                let eth_chip = EthChip::new(rlp, Some(keccak_rlcs));
                let (ctx_gate, ctx_rlc) = builder.rlc_ctx_pair();

                for witness in self.header_witness.into_iter() {
                    eth_chip.decompose_block_header_phase1((ctx_gate, ctx_rlc), witness);
                }

                for witness in self.storage_witness.into_iter() {
                    eth_chip.parse_eip1186_proofs_from_block_phase1(builder, witness);
                }
            },
        );
        if !prover {
            let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
            let minimum_rows =
                var("UNUSABLE_ROWS").unwrap_or_else(|_| "109".to_string()).parse().unwrap();
            circuit.config(k, Some(minimum_rows));
        }
        circuit
    }
}

impl AxiomChip<Fr> {
    /// Creates a circuit and runs the Halo2 `MockProver` on it. Will print out errors if the circuit does not pass.
    ///
    /// This requires an environment variable `DEGREE` to be set, which limits the number of rows of the circuit to 2<sup>DEGREE</sup>.
    pub fn mock(self) {
        assert!(!self.builder.borrow().witness_gen_only());
        let circuit = self.create(None);
        let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
        let time = start_timer!(|| "Mock prover");
        MockProver::run(k, &circuit, vec![circuit.instance()]).unwrap().assert_satisfied();
        end_timer!(time);
        println!("Mock prover passed!");
    }

    /// Creates a circuit and runs the full Halo2 proving process on it.
    /// Will time the generation of verify key & proving key. It will then run the prover on the given circuit.
    /// Finally the verifier will verify the proof. The verifier will panic if the proof is invalid.
    ///
    /// Warning: This may be memory and compute intensive.
    pub fn prove(self) {
        assert!(!self.builder.borrow().witness_gen_only());
        let circuit = self.create(None);
        let k = var("DEGREE").unwrap_or_else(|_| "18".to_string()).parse().unwrap();
        let minimum_rows =
            var("UNUSABLE_ROWS").unwrap_or_else(|_| "109".to_string()).parse().unwrap();
        circuit.config(k, Some(minimum_rows));

        let params = gen_srs(k as u32);
        let vk_time = start_timer!(|| "Generating verifying key");
        let vk = keygen_vk(&params, &circuit).expect("vk generation failed");
        end_timer!(vk_time);
        let pk_time = start_timer!(|| "Generating proving key");
        let pk = keygen_pk(&params, vk, &circuit).expect("pk generation failed");
        end_timer!(pk_time);

        // For those learning: you should technically create a separate circuit for the
        // proof (vs keygen) but for memory efficiency we just use the same one
        let pf_time = start_timer!(|| "Creating KZG proof using SHPLONK multi-open scheme");
        let instance = circuit.instance();
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[&instance]], OsRng, &mut transcript)
        .expect("proof generation failed");
        let proof = transcript.finalize();
        end_timer!(pf_time);

        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verify_time = start_timer!(|| "verify");
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(&params, pk.get_vk(), strategy, &[&[&instance]], &mut transcript)
        .unwrap();
        end_timer!(verify_time);

        println!("Congratulations! Your ZK proof is valid!");
    }
}
