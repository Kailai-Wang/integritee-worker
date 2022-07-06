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

use crate::{helpers::get_account_info, StfError, StfResult};
use itp_storage::StorageKeyProvider;
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sgx_runtime::{Balance, Runtime};
use sgx_tstd as std;
use sp_core::{crypto::AccountId32, ed25519, Pair};
use sp_runtime::MultiAddress;
use std::{format, vec, vec::Vec};
use support::traits::UnfilteredDispatchable;

type Seed = [u8; 32];

const ALICE_ENCODED: Seed = [
	212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
	76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

const ENDOWED_SEED: Seed = *b"12345678901234567890123456789012";
const SECOND_ENDOWED_SEED: Seed = *b"22345678901234567890123456789012";
const UNENDOWED_SEED: Seed = *b"92345678901234567890123456789012";

const ALICE_FUNDS: Balance = 1000000000000000;
pub const ENDOWED_ACC_FUNDS: Balance = 2000;
pub const SECOND_ENDOWED_ACC_FUNDS: Balance = 1000;

pub fn endowed_account() -> ed25519::Pair {
	ed25519::Pair::from_seed(&ENDOWED_SEED)
}
pub fn second_endowed_account() -> ed25519::Pair {
	ed25519::Pair::from_seed(&SECOND_ENDOWED_SEED)
}

pub fn unendowed_account() -> ed25519::Pair {
	ed25519::Pair::from_seed(&UNENDOWED_SEED)
}

pub(crate) fn test_genesis_setup(
	state: &mut impl SgxExternalitiesTrait,
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<()> {
	// set alice sudo account
	set_sudo_account(state, &ALICE_ENCODED, storage_key_provider)?;
	trace!("Set new sudo account: {:?}", &ALICE_ENCODED);

	let endowees: Vec<(AccountId32, Balance, Balance)> = vec![
		(endowed_account().public().into(), ENDOWED_ACC_FUNDS, ENDOWED_ACC_FUNDS),
		(
			second_endowed_account().public().into(),
			SECOND_ENDOWED_ACC_FUNDS,
			SECOND_ENDOWED_ACC_FUNDS,
		),
		(ALICE_ENCODED.into(), ALICE_FUNDS, ALICE_FUNDS),
	];

	endow(state, endowees, storage_key_provider);
	Ok(())
}

fn set_sudo_account(
	state: &mut impl SgxExternalitiesTrait,
	account_encoded: &[u8],
	storage_key_provider: &impl StorageKeyProvider,
) -> StfResult<()> {
	let storage_value_key = storage_key_provider.storage_value_key("Sudo", "Key")?.0;

	state.execute_with(|| {
		sp_io::storage::set(&storage_value_key, account_encoded);
	});
	Ok(())
}

fn endow(
	state: &mut impl SgxExternalitiesTrait,
	endowees: impl IntoIterator<Item = (AccountId32, Balance, Balance)>,
	storage_key_provider: &impl StorageKeyProvider,
) {
	state.execute_with(|| {
		for e in endowees.into_iter() {
			let account = e.0;

			sgx_runtime::BalancesCall::<Runtime>::set_balance {
				who: MultiAddress::Id(account.clone()),
				new_free: e.1,
				new_reserved: e.2,
			}
			.dispatch_bypass_filter(sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("Balance Set Balance error: {:?}", e.error)))
			.unwrap();

			let print_public: [u8; 32] = account.clone().into();
			if let Some(info) = get_account_info(&print_public.into(), storage_key_provider) {
				debug!("{:?} balance is {}", print_public, info.data.free);
			} else {
				debug!("{:?} balance is zero", print_public);
			}
		}
	});
}
