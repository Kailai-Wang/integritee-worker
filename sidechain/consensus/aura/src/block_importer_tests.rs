/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use crate::{block_importer::BlockImporter, mock::validateer, ShardIdentifierFor};
use codec::Encode;
use itc_parentchain_block_import_dispatcher::trigger_parentchain_block_import_mock::TriggerParentchainBlockImportMock;
use itp_sgx_crypto::{aes::Aes, StateCrypto};
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::{
	builders::{
		parentchain_block_builder::ParentchainBlockBuilder,
		parentchain_header_builder::ParentchainHeaderBuilder,
	},
	mock::{handle_state_mock::HandleStateMock, onchain_mock::OnchainMock},
};
use itp_time_utils::duration_now;
use itp_types::{Block as ParentchainBlock, Header as ParentchainHeader, H256};
use its_consensus_common::BlockImport;
use its_primitives::{
	traits::{SignBlock, SignedBlock},
	types::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock},
};
use its_state::{SidechainDB, SidechainState, StateUpdate};
use its_test::sidechain_block_builder::SidechainBlockBuilder;
use its_top_pool_executor::call_operator_mock::TopPoolCallOperatorMock;
use sgx_externalities::{SgxExternalities, SgxExternalitiesDiffType};
use sp_core::{blake2_256, ed25519::Pair};
use sp_keyring::ed25519::Keyring;
use sp_runtime::generic::SignedBlock as SignedParentchainBlock;
use std::sync::Arc;

type TestSidechainState = SidechainDB<SidechainBlock, SgxExternalities>;
type TestTopPoolCallOperator = TopPoolCallOperatorMock<ParentchainBlock, SignedSidechainBlock>;
type TestParentchainBlockImportTrigger =
	TriggerParentchainBlockImportMock<SignedParentchainBlock<ParentchainBlock>>;
type TestBlockImporter = BlockImporter<
	Pair,
	ParentchainBlock,
	SignedSidechainBlock,
	OnchainMock,
	TestSidechainState,
	HandleStateMock,
	Aes,
	TestTopPoolCallOperator,
	TestParentchainBlockImportTrigger,
>;

fn state_key() -> Aes {
	Aes::new([3u8; 16], [0u8; 16])
}

fn shard() -> ShardIdentifierFor<SignedSidechainBlock> {
	blake2_256(&[1, 2, 3, 4, 5, 6]).into()
}

fn default_authority() -> Pair {
	Keyring::Alice.pair()
}

fn test_fixtures(
	parentchain_block_import_trigger: Arc<TestParentchainBlockImportTrigger>,
) -> (TestBlockImporter, Arc<HandleStateMock>, Arc<TestTopPoolCallOperator>) {
	let state_handler = Arc::new(HandleStateMock::default());
	let top_pool_call_operator = Arc::new(TestTopPoolCallOperator::default());
	let ocall_api = Arc::new(
		OnchainMock::default()
			.with_validateer_set(Some(vec![validateer(Keyring::Alice.public().into())])),
	);

	let block_importer = TestBlockImporter::new(
		state_handler.clone(),
		state_key(),
		default_authority(),
		top_pool_call_operator.clone(),
		parentchain_block_import_trigger,
		ocall_api,
	);

	(block_importer, state_handler, top_pool_call_operator)
}

fn test_fixtures_with_default_import_trigger(
) -> (TestBlockImporter, Arc<HandleStateMock>, Arc<TestTopPoolCallOperator>) {
	test_fixtures(Arc::new(TestParentchainBlockImportTrigger::default()))
}

fn empty_encrypted_state_update(state_handler: &HandleStateMock) -> Vec<u8> {
	let apriori_state_hash =
		TestSidechainState::new(state_handler.load_initialized(&shard()).unwrap()).state_hash();
	let empty_state_diff = SgxExternalitiesDiffType::default();
	let mut state_update =
		StateUpdate::new(apriori_state_hash, apriori_state_hash, empty_state_diff).encode();
	state_key().encrypt(&mut state_update).unwrap();
	state_update
}

fn signed_block(
	parentchain_header: &ParentchainHeader,
	state_handler: &HandleStateMock,
	signer: Pair,
) -> SignedSidechainBlock {
	let state_update = empty_encrypted_state_update(state_handler);

	SidechainBlockBuilder::default()
		.with_timestamp(duration_now().as_millis() as u64)
		.with_parentchain_block_hash(parentchain_header.hash())
		.with_parent_hash(H256::default())
		.with_shard(shard())
		.with_payload(state_update)
		.with_signer(signer)
		.build_signed()
}

fn default_authority_signed_block(
	parentchain_header: &ParentchainHeader,
	state_handler: &HandleStateMock,
) -> SignedSidechainBlock {
	signed_block(parentchain_header, state_handler, default_authority())
}

#[test]
fn simple_block_import_works() {
	let (block_importer, state_handler, _) = test_fixtures_with_default_import_trigger();
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let signed_sidechain_block =
		default_authority_signed_block(&parentchain_header, state_handler.as_ref());

	block_importer
		.import_block(signed_sidechain_block, &parentchain_header)
		.unwrap();
}

#[test]
fn block_import_with_invalid_signature_fails() {
	let (block_importer, state_handler, _) = test_fixtures_with_default_import_trigger();

	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let state_update = empty_encrypted_state_update(state_handler.as_ref());

	let block = SidechainBlockBuilder::default()
		.with_timestamp(duration_now().as_millis() as u64)
		.with_parentchain_block_hash(parentchain_header.hash())
		.with_signer(Keyring::Charlie.pair())
		.with_parent_hash(H256::default())
		.with_shard(shard())
		.with_payload(state_update)
		.build();

	// Bob signs the block, but Charlie is set as the author -> invalid signature.
	let invalid_signature_block: SignedSidechainBlock = block.sign_block(&Keyring::Bob.pair());

	assert!(!invalid_signature_block.verify_signature());
	assert!(block_importer
		.import_block(invalid_signature_block, &parentchain_header)
		.is_err());
}

#[test]
fn if_block_author_is_self_remove_tops_from_pool() {
	let (block_importer, state_handler, top_pool_call_operator) =
		test_fixtures_with_default_import_trigger();
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let signed_sidechain_block =
		default_authority_signed_block(&parentchain_header, state_handler.as_ref());

	block_importer.cleanup(&signed_sidechain_block).unwrap();

	assert_eq!(1, top_pool_call_operator.remove_calls_invoked().len());
}

#[test]
fn if_block_author_is_not_self_do_not_remove_tops() {
	let (block_importer, state_handler, top_pool_call_operator) =
		test_fixtures_with_default_import_trigger();
	let parentchain_header = ParentchainHeaderBuilder::default().build();
	let signed_sidechain_block =
		signed_block(&parentchain_header, state_handler.as_ref(), Keyring::Bob.pair());

	block_importer.cleanup(&signed_sidechain_block).unwrap();

	assert!(top_pool_call_operator.remove_calls_invoked().is_empty());
}

#[test]
fn sidechain_block_import_triggers_parentchain_block_import() {
	let previous_parentchain_header = ParentchainHeaderBuilder::default().with_number(4).build();
	let latest_parentchain_header = ParentchainHeaderBuilder::default()
		.with_number(5)
		.with_parent_hash(previous_parentchain_header.hash())
		.build();

	let latest_parentchain_block = ParentchainBlockBuilder::default()
		.with_header(latest_parentchain_header.clone())
		.build_signed();

	let parentchain_block_import_trigger = Arc::new(
		TestParentchainBlockImportTrigger::default()
			.with_latest_imported(Some(latest_parentchain_block)),
	);
	let (block_importer, state_handler, _) =
		test_fixtures(parentchain_block_import_trigger.clone());

	let signed_sidechain_block =
		default_authority_signed_block(&latest_parentchain_header, state_handler.as_ref());

	block_importer
		.import_block(signed_sidechain_block, &previous_parentchain_header)
		.unwrap();

	assert!(parentchain_block_import_trigger.has_import_been_called());
}
