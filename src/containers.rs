use axiom_eth::{
    block_header::EthBlockHeaderTraceWitness,
    rlp::{evaluate_byte_array, RlpFieldWitness},
    Field,
};
use halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue, Context};

#[derive(Clone, Debug)]
pub struct ByteString<F: ScalarField> {
    /// the possibly variable length of the bytestring
    pub len: AssignedValue<F>,
    /// the bytes of the bytestring, padded to a known fixed maximum length (depends on the context)
    pub bytes: Vec<AssignedValue<F>>,
}

impl<'a, F: ScalarField> From<&'a RlpFieldWitness<F>> for ByteString<F> {
    fn from(value: &'a RlpFieldWitness<F>) -> Self {
        Self { len: value.field_len, bytes: value.field_cells.clone() }
    }
}

impl<F: ScalarField> ByteString<F> {
    /// Evaluates a variable-length byte string to a big endian number.
    ///
    /// If the resulting number is larger than the size of the scalar field `F`, then the result
    /// is modulo the prime of the scalar field. (We do not recommend using it in this setting.)
    pub fn evaluate(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> AssignedValue<F> {
        evaluate_byte_array(ctx, gate, &self.bytes, self.len)
    }
}

/// The max bytes per bytestring field are, for reference:
/// ```
/// const MAINNET_HEADER_FIELDS_MAX_BYTES: [usize; _] =
/// [32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, 32, 32, 8, 6];
/// const GOERLI_HEADER_FIELDS_MAX_BYTES: [usize; _] =
/// [32, 32, 20, 32, 32, 32, 256, 7, 4, 4, 4, 4, 97, 32, 8, 6];
/// ```
#[derive(Clone, Debug)]
pub struct EthBlock<F: Field> {
    pub parent_hash: ByteString<F>,
    pub ommers_hash: ByteString<F>,
    pub beneficiary: ByteString<F>,
    pub state_root: ByteString<F>,
    pub transactions_root: ByteString<F>,
    pub receipts_root: ByteString<F>,
    pub logs_bloom: ByteString<F>,
    pub difficulty: ByteString<F>,
    pub number: ByteString<F>,
    pub gas_limit: ByteString<F>,
    pub gas_used: ByteString<F>,
    pub timestamp: ByteString<F>,
    pub extra_data: ByteString<F>,
    pub mix_hash: ByteString<F>,
    pub nonce: ByteString<F>,
    pub basefee: ByteString<F>, // this will be 0 (or undefined) if before London

    pub block_hash: [AssignedValue<F>; 32],
}

impl<'a, F: Field> From<&'a EthBlockHeaderTraceWitness<F>> for EthBlock<F> {
    fn from(value: &'a EthBlockHeaderTraceWitness<F>) -> Self {
        Self {
            parent_hash: value.get("parent_hash").into(),
            ommers_hash: value.get("ommers_hash").into(),
            beneficiary: value.get("beneficiary").into(),
            state_root: value.get("state_root").into(),
            transactions_root: value.get("transactions_root").into(),
            receipts_root: value.get("receipts_root").into(),
            logs_bloom: value.get("logs_bloom").into(),
            difficulty: value.get("difficulty").into(),
            number: value.get("number").into(),
            gas_limit: value.get("gas_limit").into(),
            gas_used: value.get("gas_used").into(),
            timestamp: value.get("timestamp").into(),
            extra_data: value.get("extra_data").into(),
            mix_hash: value.get("mix_hash").into(),
            nonce: value.get("nonce").into(),
            basefee: value.get("basefee").into(),
            block_hash: value.block_hash.clone().try_into().unwrap(),
        }
    }
}
