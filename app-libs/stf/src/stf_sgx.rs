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

#[cfg(feature = "test")]
use crate::test_genesis::test_genesis_setup;

use crate::{
	helpers::{
		account_data, account_nonce, enclave_signer_account, ensure_enclave_signer_account,
		ensure_root, get_account_info, increment_nonce, root, validate_nonce,
	},
	AccountData, AccountId, Getter, Index, ParentchainHeader, PublicGetter, ShardIdentifier, State,
	StateTypeDiff, Stf, StfError, StfResult, TrustedCall, TrustedCallSigned, TrustedGetter,
	ENCLAVE_ACCOUNT_KEY,
};
use codec::Encode;
use itp_storage::StorageKeyProvider;
use itp_types::OpaqueCall;
use itp_utils::stringify::account_id_to_string;
use its_state::SidechainSystemExt;
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sgx_runtime::Runtime;
use sidechain_primitives::types::{BlockHash, BlockNumber as SidechainBlockNumber, Timestamp};
use sp_io::hashing::blake2_256;
use sp_runtime::MultiAddress;
use std::{format, prelude::v1::*, vec};
use support::traits::UnfilteredDispatchable;
impl Stf {
	pub fn init_state(
		enclave_account: AccountId,
		storage_key_provider: &impl StorageKeyProvider,
	) -> StfResult<State> {
		debug!("initializing stf state, account id {}", account_id_to_string(&enclave_account));
		let mut ext = State::new();

		ext.execute_with(|| -> StfResult<()> {
			// do not set genesis for pallets that are meant to be on-chain
			// use get_storage_hashes_to_update instead

			sp_io::storage::set(
				&storage_key_provider.storage_value_key("Balances", "TotalIssuance")?.0,
				&11u128.encode(),
			);
			sp_io::storage::set(
				&storage_key_provider.storage_value_key("Balances", "CreationFee")?.0,
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_key_provider.storage_value_key("Balances", "TransferFee")?.0,
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_key_provider.storage_value_key("Balances", "TransactionBaseFee")?.0,
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_key_provider.storage_value_key("Balances", "TransactionByteFee")?.0,
				&1u128.encode(),
			);
			sp_io::storage::set(
				&storage_key_provider.storage_value_key("Balances", "ExistentialDeposit")?.0,
				&1u128.encode(),
			);
			Ok(())
		})?;

		#[cfg(feature = "test")]
		test_genesis_setup(&mut ext, storage_key_provider)?;

		ext.execute_with(|| -> StfResult<()> {
			sp_io::storage::set(
				&storage_key_provider.storage_value_key("Sudo", ENCLAVE_ACCOUNT_KEY)?.0,
				&enclave_account.encode(),
			);

			if let Err(e) = Self::create_enclave_self_account(&enclave_account) {
				error!("Failed to initialize the enclave signer account: {:?}", e);
			}
			Ok(())
		})?;

		trace!("Returning updated state: {:?}", ext);
		Ok(ext)
	}

	pub fn get_state(
		ext: &mut impl SgxExternalitiesTrait,
		getter: Getter,
		storage_key_provider: &impl StorageKeyProvider,
	) -> Option<Vec<u8>> {
		ext.execute_with(|| match getter {
			Getter::trusted(g) => match g.getter {
				TrustedGetter::free_balance(who) =>
					if let Some(info) = get_account_info(&who, storage_key_provider) {
						debug!("TrustedGetter free_balance");
						debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
						debug!("Account free balance is {}", info.data.free);
						Some(info.data.free.encode())
					} else {
						None
					},
				TrustedGetter::reserved_balance(who) =>
					if let Some(info) = get_account_info(&who, storage_key_provider) {
						debug!("TrustedGetter reserved_balance");
						debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
						debug!("Account reserved balance is {}", info.data.reserved);
						Some(info.data.reserved.encode())
					} else {
						None
					},
				TrustedGetter::nonce(who) =>
					if let Some(info) = get_account_info(&who, storage_key_provider) {
						debug!("TrustedGetter nonce");
						debug!("AccountInfo for {} is {:?}", account_id_to_string(&who), info);
						debug!("Account nonce is {}", info.nonce);
						Some(info.nonce.encode())
					} else {
						None
					},
			},
			Getter::public(g) => match g {
				PublicGetter::some_value => Some(42u32.encode()),
			},
		})
	}

	pub fn execute(
		ext: &mut impl SgxExternalitiesTrait,
		call: TrustedCallSigned,
		calls: &mut Vec<OpaqueCall>,
		unshield_funds_fn: [u8; 2],
		storage_key_provider: &impl StorageKeyProvider,
	) -> StfResult<()> {
		let call_hash = blake2_256(&call.encode());
		ext.execute_with(|| -> StfResult<()> {
			let sender = call.call.account().clone();
			validate_nonce(&sender, call.nonce, storage_key_provider)?;
			match call.call {
				TrustedCall::balance_set_balance(root, who, free_balance, reserved_balance) => {
					ensure_root(root, storage_key_provider)?;
					debug!(
						"balance_set_balance({}, {}, {})",
						account_id_to_string(&who),
						free_balance,
						reserved_balance
					);
					sgx_runtime::BalancesCall::<Runtime>::set_balance {
						who: MultiAddress::Id(who),
						new_free: free_balance,
						new_reserved: reserved_balance,
					}
					.dispatch_bypass_filter(sgx_runtime::Origin::root())
					.map_err(|e| {
						StfError::Dispatch(format!("Balance Set Balance error: {:?}", e.error))
					})?;
				},
				TrustedCall::balance_transfer(from, to, value) => {
					let origin = sgx_runtime::Origin::signed(from.clone());
					debug!(
						"balance_transfer({}, {}, {})",
						account_id_to_string(&from),
						account_id_to_string(&to),
						value
					);
					if let Some(info) = get_account_info(&from, storage_key_provider) {
						debug!("sender balance is {}", info.data.free);
					} else {
						debug!("sender balance is zero");
					}
					sgx_runtime::BalancesCall::<Runtime>::transfer {
						dest: MultiAddress::Id(to),
						value,
					}
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						StfError::Dispatch(format!("Balance Transfer error: {:?}", e.error))
					})?;
				},
				TrustedCall::balance_unshield(account_incognito, beneficiary, value, shard) => {
					debug!(
						"balance_unshield({}, {}, {}, {})",
						account_id_to_string(&account_incognito),
						account_id_to_string(&beneficiary),
						value,
						shard
					);

					Self::unshield_funds(account_incognito, value, storage_key_provider)?;
					calls.push(OpaqueCall::from_tuple(&(
						unshield_funds_fn,
						beneficiary,
						value,
						shard,
						call_hash,
					)));
				},
				TrustedCall::balance_shield(enclave_account, who, value) => {
					ensure_enclave_signer_account(&enclave_account, storage_key_provider)?;
					debug!("balance_shield({}, {})", account_id_to_string(&who), value);
					Self::shield_funds(who, value, storage_key_provider)?;
				},
			};
			increment_nonce(&sender, storage_key_provider)?;
			Ok(())
		})
	}

	/// Creates valid enclave account with a balance that is above the existential deposit.
	/// !! Requires a root to be set.
	fn create_enclave_self_account(enclave_account: &AccountId) -> StfResult<()> {
		sgx_runtime::BalancesCall::<Runtime>::set_balance {
			who: MultiAddress::Id(enclave_account.clone()),
			new_free: 1000,
			new_reserved: 0,
		}
		.dispatch_bypass_filter(sgx_runtime::Origin::root())
		.map_err(|e| {
			StfError::Dispatch(format!(
				"Set Balance for enclave signer account error: {:?}",
				e.error
			))
		})
		.map(|_| ())
	}

	fn shield_funds(
		account: AccountId,
		amount: u128,
		storage_key_provider: &impl StorageKeyProvider,
	) -> StfResult<()> {
		match get_account_info(&account, storage_key_provider) {
			Some(account_info) => sgx_runtime::BalancesCall::<Runtime>::set_balance {
				who: MultiAddress::Id(account),
				new_free: account_info.data.free + amount,
				new_reserved: account_info.data.reserved,
			}
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?,
			None => {
				debug!(
					"Account {} does not exist yet, initializing by setting free balance to {}",
					account_id_to_string(&account),
					amount
				);
				sgx_runtime::BalancesCall::<Runtime>::set_balance {
					who: MultiAddress::Id(account),
					new_free: amount,
					new_reserved: 0,
				}
				.dispatch_bypass_filter(sgx_runtime::Origin::root())
				.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?
			},
		};
		Ok(())
	}

	fn unshield_funds(
		account: AccountId,
		amount: u128,
		storage_key_provider: &impl StorageKeyProvider,
	) -> StfResult<()> {
		match get_account_info(&account, storage_key_provider) {
			Some(account_info) => {
				if account_info.data.free < amount {
					return Err(StfError::MissingFunds)
				}

				sgx_runtime::BalancesCall::<Runtime>::set_balance {
					who: MultiAddress::Id(account),
					new_free: account_info.data.free - amount,
					new_reserved: account_info.data.reserved,
				}
				.dispatch_bypass_filter(sgx_runtime::Origin::root())
				.map_err(|e| StfError::Dispatch(format!("Unshield funds error: {:?}", e.error)))?;
				Ok(())
			},
			None => Err(StfError::InexistentAccount(account)),
		}
	}

	pub fn update_storage(ext: &mut impl SgxExternalitiesTrait, map_update: &StateTypeDiff) {
		ext.execute_with(|| {
			map_update.iter().for_each(|(k, v)| {
				match v {
					Some(value) => sp_io::storage::set(k, value),
					None => sp_io::storage::clear(k),
				};
			});
		});
	}

	/// Updates the block number, block hash and parent hash of the parentchain block.
	pub fn update_parentchain_block(
		ext: &mut impl SgxExternalitiesTrait,
		header: ParentchainHeader,
	) -> StfResult<()> {
		ext.execute_with(|| {
			sgx_runtime::ParentchainCall::<Runtime>::set_block { header }
				.dispatch_bypass_filter(sgx_runtime::Origin::root())
				.map_err(|e| {
					StfError::Dispatch(format!("Update parentchain block error: {:?}", e.error))
				})
		})?;
		Ok(())
	}

	pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		match call.call {
			TrustedCall::balance_set_balance(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_transfer(_, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_unshield(_, _, _, _) => debug!("No storage updates needed..."),
			TrustedCall::balance_shield(_, _, _) => debug!("No storage updates needed..."),
		};
		key_hashes
	}

	pub fn get_storage_hashes_to_update_for_getter(getter: &Getter) -> Vec<Vec<u8>> {
		debug!(
			"No specific storage updates needed for getter. Returning those for on block: {:?}",
			getter
		);
		Self::storage_hashes_to_update_on_block()
	}

	pub fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
		let mut key_hashes = Vec::new();

		// get all shards that are currently registered
		key_hashes.push(shards_key_hash());
		key_hashes
	}

	pub fn get_root(
		ext: &mut impl SgxExternalitiesTrait,
		storage_key_provider: &impl StorageKeyProvider,
	) -> StfResult<AccountId> {
		ext.execute_with(|| root(storage_key_provider))
	}

	pub fn get_enclave_account(
		ext: &mut impl SgxExternalitiesTrait,
		storage_key_provider: &impl StorageKeyProvider,
	) -> StfResult<AccountId> {
		ext.execute_with(|| enclave_signer_account(storage_key_provider))
	}

	pub fn account_nonce(
		ext: &mut impl SgxExternalitiesTrait,
		account: &AccountId,
		storage_key_provider: &impl StorageKeyProvider,
	) -> Index {
		ext.execute_with(|| {
			let nonce = account_nonce(account, storage_key_provider);
			debug!("Account {} nonce is {}", account_id_to_string(&account), nonce);
			nonce
		})
	}

	pub fn account_data(
		ext: &mut impl SgxExternalitiesTrait,
		account: &AccountId,
		storage_key_provider: &impl StorageKeyProvider,
	) -> Option<AccountData> {
		ext.execute_with(|| account_data(account, storage_key_provider))
	}
}

pub fn storage_hashes_to_update_per_shard(_shard: &ShardIdentifier) -> Vec<Vec<u8>> {
	Vec::new()
}

pub fn shards_key_hash() -> Vec<u8> {
	// here you have to point to a storage value containing a Vec of
	// ShardIdentifiers the enclave uses this to autosubscribe to no shards
	vec![]
}

/// Trait extension to simplify sidechain data access from the STF.
///
/// This should be removed when the refactoring of the STF has been done: #269
pub trait SidechainExt {
	/// get the block number of the sidechain state
	fn get_sidechain_block_number<S: SidechainSystemExt>(
		ext: &S,
	) -> StfResult<Option<SidechainBlockNumber>>;

	/// set the block number of the sidechain state
	fn set_sidechain_block_number<S: SidechainSystemExt>(
		ext: &mut S,
		number: &SidechainBlockNumber,
	) -> StfResult<()>;

	/// get the last block hash of the sidechain state
	fn get_last_block_hash<S: SidechainSystemExt>(ext: &S) -> StfResult<Option<BlockHash>>;

	/// set the last block hash of the sidechain state
	fn set_last_block_hash<S: SidechainSystemExt>(ext: &mut S, hash: &BlockHash) -> StfResult<()>;

	/// get the timestamp of the sidechain state
	fn get_timestamp<S: SidechainSystemExt>(ext: &S) -> StfResult<Option<Timestamp>>;

	/// set the timestamp of the sidechain state
	fn set_timestamp<S: SidechainSystemExt>(ext: &mut S, timestamp: &Timestamp) -> StfResult<()>;
}

impl SidechainExt for Stf {
	fn get_sidechain_block_number<S: SidechainSystemExt>(
		ext: &S,
	) -> StfResult<Option<SidechainBlockNumber>> {
		Ok(ext.get_block_number()?)
	}

	fn set_sidechain_block_number<S: SidechainSystemExt>(
		ext: &mut S,
		number: &SidechainBlockNumber,
	) -> StfResult<()> {
		ext.set_block_number(number)?;
		Ok(())
	}

	fn get_last_block_hash<S: SidechainSystemExt>(ext: &S) -> StfResult<Option<BlockHash>> {
		Ok(ext.get_last_block_hash()?)
	}

	fn set_last_block_hash<S: SidechainSystemExt>(ext: &mut S, hash: &BlockHash) -> StfResult<()> {
		ext.set_last_block_hash(hash)?;
		Ok(())
	}

	fn get_timestamp<S: SidechainSystemExt>(ext: &S) -> StfResult<Option<Timestamp>> {
		Ok(ext.get_timestamp()?)
	}

	fn set_timestamp<S: SidechainSystemExt>(ext: &mut S, timestamp: &Timestamp) -> StfResult<()> {
		ext.set_timestamp(timestamp)?;
		Ok(())
	}
}
