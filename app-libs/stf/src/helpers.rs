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
use crate::{AccountId, StfError, StfResult, ENCLAVE_ACCOUNT_KEY};
use codec::{Decode, Encode};
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use ita_sgx_runtime::System;
use itp_storage::{storage_double_map_key, storage_map_key, storage_value_key, StorageHasher};
use itp_utils::stringify::account_id_to_string;
use log::*;
use std::prelude::v1::*;

pub fn get_storage_value<V: Decode>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
) -> Option<V> {
	let key = storage_value_key(storage_prefix, storage_key_name);
	get_storage_by_key_hash(key)
}

pub fn get_storage_map<K: Encode, V: Decode + Clone>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
	map_key: &K,
	hasher: &StorageHasher,
) -> Option<V> {
	let key = storage_map_key::<K>(storage_prefix, storage_key_name, map_key, hasher);
	get_storage_by_key_hash(key)
}

pub fn get_storage_double_map<K: Encode, Q: Encode, V: Decode + Clone>(
	storage_prefix: &'static str,
	storage_key_name: &'static str,
	first: &K,
	first_hasher: &StorageHasher,
	second: &Q,
	second_hasher: &StorageHasher,
) -> Option<V> {
	let key = storage_double_map_key::<K, Q>(
		storage_prefix,
		storage_key_name,
		first,
		first_hasher,
		second,
		second_hasher,
	);
	get_storage_by_key_hash(key)
}

/// Get value in storage.
pub fn get_storage_by_key_hash<V: Decode>(key: Vec<u8>) -> Option<V> {
	if let Some(value_encoded) = sp_io::storage::get(&key) {
		if let Ok(value) = Decode::decode(&mut value_encoded.as_slice()) {
			Some(value)
		} else {
			error!("could not decode state for key {:x?}", key);
			None
		}
	} else {
		info!("key not found in state {:x?}", key);
		None
	}
}

/// Get the AccountInfo key where the account is stored.
pub fn account_key_hash(account: &AccountId) -> Vec<u8> {
	storage_map_key("System", "Account", account, &StorageHasher::Blake2_128Concat)
}

pub fn get_events() -> Option<Vec<Box<EventRecord>>> {
	get_storage_value("System", "Events")
}

pub fn get_event_count() -> Option<EventIndex> {
	get_storage_value("System", "EventCount")
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub fn reset_events() {
	System::reset_events()
}

pub fn set_event_topic(topic: &H256, value: Vec<(BlockNumber, EventIndex)>) {
	sp_io::storage::set(
		&storage_map_key("System", "EventTopics", topic, &StorageHasher::Blake2_128Concat),
		&value.encode(),
	);
}

pub fn get_account_info(who: &AccountId) -> Option<AccountInfo> {
	let maybe_storage_map =
		get_storage_map("System", "Account", who, &StorageHasher::Blake2_128Concat);
	if maybe_storage_map.is_none() {
		info!("Failed to get account info for account {}", account_id_to_string(who));
	}
	maybe_storage_map
}

pub fn get_events() -> Option<Vec<Box<EventRecord>>> {
	get_storage_value("System", "Events")
}

pub fn get_event_count() -> Option<EventIndex> {
	get_storage_value("System", "EventCount")
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub fn reset_events() {
	System::reset_events()
}

pub fn set_event_topic(topic: &H256, value: Vec<(BlockNumber, EventIndex)>) {
	sp_io::storage::set(
		&storage_map_key("System", "EventTopics", topic, &StorageHasher::Blake2_128Concat),
		&value.encode(),
	);
}

pub fn get_event_topics(topic: &H256) -> Option<Vec<(BlockNumber, EventIndex)>> {
	get_storage_map("System", "EventTopics", topic, &StorageHasher::Blake2_128Concat)
}

// FIXME: Unbound storage call
/// Read the events from runtime. This has a potentially very large return value,
/// as the event storage size is not limited and depends on the number and types of executed calls.
/// However, substrate will change the event handling soon, so this should be acceptable for now.
pub fn get_events_unbounded() -> Vec<EventRecord> {
	get_events().unwrap_or_default().into_iter().map(|e| *e).collect()
}

pub fn get_event_topics(topic: &H256) -> Option<Vec<(BlockNumber, EventIndex)>> {
	get_storage_map("System", "EventTopics", topic, &StorageHasher::Blake2_128Concat)
}

/// FIXME: Unbound storage call
/// Read the events from runtime. This has a potentially very large return value,
/// as the event storage size is not limited and depends on the number and types of executed calls.
/// However, substrate will change the event handling soon, so this should be acceptable for now.
pub fn get_events_unbounded() -> Vec<EventRecord> {
	get_events().unwrap_or_default().into_iter().map(|e| *e).collect()
}

pub fn validate_nonce(who: &AccountId, nonce: Index) -> StfResult<()> {
	let expected_nonce = match get_account_info(who) {
		None => {
			info!(
				"Attempted to validate account nonce of non-existent account: {}",
				account_id_to_string(who)
			);
			0
		},
		Some(account_info) => account_info.nonce,
	};
	if expected_nonce == nonce {
		return Ok(())
	}
	Err(StfError::InvalidNonce(nonce))
}

/// increment nonce after a successful call execution
pub fn increment_nonce(account: &AccountId) {
	//FIXME: Proper error handling - should be taken into
	// consideration after implementing pay fee check
	if let Some(mut acc_info) = get_account_info(account) {
		debug!("incrementing account nonce");
		acc_info.nonce += 1;
		sp_io::storage::set(&account_key_hash(account), &acc_info.encode());
		debug!(
			"updated account {} nonce: {:?}",
			account_id_to_string(account),
			get_account_info(account).unwrap().nonce
		);
	} else {
		error!(
			"tried to increment nonce of a non-existent account: {}",
			account_id_to_string(account)
		)
	}
}

pub fn account_nonce(account: &AccountId) -> Index {
	if let Some(info) = get_account_info(account) {
		info.nonce
	} else {
		info!("Attempted to get nonce of non-existent account: {}", account_id_to_string(account));
		0_u32
	}
}

pub fn account_data(account: &AccountId) -> Option<AccountData> {
	if let Some(info) = get_account_info(account) {
		Some(info.data)
	} else {
		info!(
			"Attempted to get account data of non-existent account: {}",
			account_id_to_string(account)
		);
		None
	}
}

pub fn root() -> AccountId {
	get_storage_value("Sudo", "Key").expect("No root account")
}

pub fn enclave_signer_account() -> AccountId {
	get_storage_value("Sudo", ENCLAVE_ACCOUNT_KEY).expect("No enclave account")
}

/// Ensures an account is a registered enclave account.
pub fn ensure_enclave_signer_account(account: &AccountId) -> StfResult<()> {
	let expected_enclave_account = enclave_signer_account();
	if &expected_enclave_account == account {
		Ok(())
	} else {
		error!(
			"Expected enclave account {}, but found {}",
			account_id_to_string(&expected_enclave_account),
			account_id_to_string(account)
		);
		Err(StfError::RequireEnclaveSignerAccount)
	}
}
