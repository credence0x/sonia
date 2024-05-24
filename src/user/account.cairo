use starknet::{ContractAddress, account::Call};

// SPDX-License-Identifier: MIT

#[starknet::contract(account)]
mod AccountUpgradeable {
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::upgrades::UpgradeableComponent;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use super::AccountComponent;

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    // Account Mixin
    #[abi(embed_v0)]
    impl AccountMixinImpl = AccountComponent::AccountMixinImpl<ContractState>;
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;

    // Upgradeable
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: AccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252, master_account: ContractAddress) {
        self.account.initializer(public_key, master_account);
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.account.assert_only_master();
            self.upgradeable._upgrade(new_class_hash);
        }
    }
}

// Changes fron standard oz account
//
// account key must be changeable by master
// account should have multiple keys

/// # Account Component
///
/// The Account component enables contracts to behave as accounts.
#[starknet::component]
mod AccountComponent {
    use openzeppelin::account::interface;
    use openzeppelin::account::utils::{MIN_TRANSACTION_VERSION, QUERY_VERSION, QUERY_OFFSET};
    use openzeppelin::account::utils::{execute_calls, is_valid_stark_signature};
    use openzeppelin::introspection::src5::SRC5Component::InternalTrait as SRC5InternalTrait;
    use openzeppelin::introspection::src5::SRC5Component::SRC5;
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::ContractAddress;
    use starknet::account::Call;
    use starknet::get_caller_address;
    use starknet::get_contract_address;
    use starknet::get_tx_info;

    const MAX_PUBLIC_KEY_COUNT: u8 = 10;

    #[storage]
    struct Storage {
        Account_master: ContractAddress,
        Account_public_keys: LegacyMap<u8, felt252>,
        Account_public_keys_count: u8
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    enum Event {
        MasterAdded: MasterAdded,
        MasterRemoved: MasterRemoved,
        OwnerAdded: OwnerAdded,
        OwnerRemoved: OwnerRemoved
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct MasterAdded {
        #[key]
        new_master_account: ContractAddress
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct MasterRemoved {
        #[key]
        removed_master_account: ContractAddress
    }


    #[derive(Drop, PartialEq, starknet::Event)]
    struct OwnerAdded {
        #[key]
        count: u8,
        new_owner_guid: felt252
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    struct OwnerRemoved {
        #[key]
        count: u8,
        removed_owner_guid: felt252
    }

    mod Errors {
        const INVALID_CALLER: felt252 = 'Account: invalid caller';
        const INVALID_SIGNATURE: felt252 = 'Account: invalid signature';
        const INVALID_TX_VERSION: felt252 = 'Account: invalid tx version';
        const UNAUTHORIZED: felt252 = 'Account: unauthorized';
    }

    #[embeddable_as(SRC6Impl)]
    impl SRC6<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::ISRC6<ComponentState<TContractState>> {
        /// Executes a list of calls from the account.
        ///
        /// Requirements:
        ///
        /// - The transaction version must be greater than or equal to `MIN_TRANSACTION_VERSION`.
        /// - If the transaction is a simulation (version than `QUERY_OFFSET`), it must be
        /// greater than or equal to `QUERY_OFFSET` + `MIN_TRANSACTION_VERSION`.
        fn __execute__(
            self: @ComponentState<TContractState>, mut calls: Array<Call>
        ) -> Array<Span<felt252>> {
            // Avoid calls from other contracts
            // https://github.com/OpenZeppelin/cairo-contracts/issues/344
            let sender = get_caller_address();
            assert(sender.is_zero(), Errors::INVALID_CALLER);

            // Check tx version
            let tx_info = get_tx_info().unbox();
            let tx_version: u256 = tx_info.version.into();
            // Check if tx is a query
            if (tx_version >= QUERY_OFFSET) {
                assert(
                    QUERY_OFFSET + MIN_TRANSACTION_VERSION <= tx_version, Errors::INVALID_TX_VERSION
                );
            } else {
                assert(MIN_TRANSACTION_VERSION <= tx_version, Errors::INVALID_TX_VERSION);
            }

            execute_calls(calls)
        }

        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `invoke` transactions.
        fn __validate__(self: @ComponentState<TContractState>, mut calls: Array<Call>) -> felt252 {
            self.validate_transaction()
        }

        /// Verifies that the given signature is valid for the given hash.
        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            if self._is_valid_signature(hash, signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }
    }

    #[embeddable_as(DeclarerImpl)]
    impl Declarer<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IDeclarer<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `declare` transactions.
        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252
        ) -> felt252 {
            self.validate_transaction()
        }
    }

    #[embeddable_as(DeployableImpl)]
    impl Deployable<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IDeployable<ComponentState<TContractState>> {
        /// Verifies the validity of the signature for the current transaction.
        /// This function is used by the protocol to verify `deploy_account` transactions.
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252
        ) -> felt252 {
            self.validate_transaction()
        }
    }

    #[embeddable_as(PublicKeyImpl)]
    impl PublicKey<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of super::IPublicKey<ComponentState<TContractState>> {
        /// Returns the current public key of the account.
        fn get_public_key(self: @ComponentState<TContractState>, count: u8) -> felt252 {
            assert!(count > 0 && count <= MAX_PUBLIC_KEY_COUNT, "Account: invalid count");
            self.Account_public_keys.read(count)
        }

        /// Sets the public key of the account to `new_public_key`.
        ///
        /// Requirements:
        ///
        /// - The caller must be the contract itself.
        ///
        /// Emits an `OwnerRemoved` event.
        fn add_public_key(ref self: ComponentState<TContractState>, new_public_key: felt252) {
            self.assert_only_master();

            let new_count = self.Account_public_keys_count.read() + 1;
            assert!(new_count <= MAX_PUBLIC_KEY_COUNT, "max public keys storage reached");
            self._set_public_key(new_count, new_public_key);
        }

        fn change_public_key(
            ref self: ComponentState<TContractState>, count: u8, new_public_key: felt252
        ) {
            self.assert_only_master();

            let previous_key: felt252 = self.Account_public_keys.read(count);
            assert!(previous_key.is_non_zero(), "no previous key to change");

            self.emit(OwnerRemoved { count: count, removed_owner_guid: previous_key });
            self._set_public_key(count, new_public_key);
        }
    }


    #[embeddable_as(MasterAccountImpl)]
    impl MasterAccount<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of super::IMasterAccount<ComponentState<TContractState>> {
        /// Returns the current master account of the account.
        fn get_master_account(self: @ComponentState<TContractState>) -> ContractAddress {
            self.Account_master.read()
        }

        /// Sets the master account of the account to `new_master_account`.
        ///
        /// Requirements:
        ///
        /// - The caller must be the master contract itself.
        ///
        /// Emits a `MasterRemoved` event.
        fn set_master_account(
            ref self: ComponentState<TContractState>, new_master_account: ContractAddress
        ) {
            self.assert_only_master();
            self.emit(MasterRemoved { removed_master_account: self.Account_master.read() });
            self._set_master_account(new_master_account)
        }
    }

    /// Adds camelCase support for `ISRC6`.
    #[embeddable_as(SRC6CamelOnlyImpl)]
    impl SRC6CamelOnly<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::ISRC6CamelOnly<ComponentState<TContractState>> {
        fn isValidSignature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            SRC6::is_valid_signature(self, hash, signature)
        }
    }

    /// Adds camelCase support for `PublicKeyTrait`.
    #[embeddable_as(PublicKeyCamelImpl)]
    impl PublicKeyCamel<
        TContractState,
        +HasComponent<TContractState>,
        +SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of super::IPublicKeyCamel<ComponentState<TContractState>> {
        fn getPublicKey(self: @ComponentState<TContractState>, count: u8) -> felt252 {
            PublicKey::get_public_key(self, count)
        }

        fn addPublicKey(ref self: ComponentState<TContractState>, newPublicKey: felt252) {
            PublicKey::add_public_key(ref self, newPublicKey);
        }

        fn changePublicKey(
            ref self: ComponentState<TContractState>, count: u8, newPublicKey: felt252
        ) {
            PublicKey::change_public_key(ref self, count, newPublicKey);
        }
    }

    #[generate_trait]
    impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of InternalTrait<TContractState> {
        /// Initializes the account by setting the initial public key
        /// and registering the ISRC6 interface Id.
        fn initializer(
            ref self: ComponentState<TContractState>,
            public_key: felt252,
            master_account: ContractAddress
        ) {
            let mut src5_component = get_dep_component_mut!(ref self, SRC5);
            src5_component.register_interface(interface::ISRC6_ID);
            self._set_public_key(1, public_key);
            self._set_master_account(master_account);
        }

        /// Validates that the caller is master account. Otherwise it reverts.
        fn assert_only_master(self: @ComponentState<TContractState>) {
            let caller = get_caller_address();
            assert(caller == self.Account_master.read(), Errors::UNAUTHORIZED);
        }

        /// Validates the signature for the current transaction.
        /// Returns the short string `VALID` if valid, otherwise it reverts.
        fn validate_transaction(self: @ComponentState<TContractState>) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;
            assert(self._is_valid_signature(tx_hash, signature), Errors::INVALID_SIGNATURE);
            starknet::VALIDATED
        }

        /// Sets the public key without validating the caller.
        /// The usage of this method outside the `add_public_key` function is discouraged.
        ///
        /// Emits an `OwnerAdded` event.
        fn _set_public_key(
            ref self: ComponentState<TContractState>, count: u8, new_public_key: felt252
        ) {
            assert!(count <= MAX_PUBLIC_KEY_COUNT, "count value greater than max ");
            self.Account_public_keys.write(count, new_public_key);
            self.emit(OwnerAdded { count: count, new_owner_guid: new_public_key });
        }

        /// Sets the master account without validating the caller.
        /// The usage of this method outside the `set_master_account` function is discouraged.
        ///
        /// Emits an `MasterAdded` event.
        fn _set_master_account(
            ref self: ComponentState<TContractState>, new_master_account: ContractAddress
        ) {
            self.Account_master.write(new_master_account);
            self.emit(MasterAdded { new_master_account: new_master_account });
        }

        /// Returns whether the given signature is valid for the given hash
        /// using the account's current public key.
        fn _is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Span<felt252>
        ) -> bool {
            let mut count = self.Account_public_keys_count.read();
            return loop {
                if count == 0 {
                    break false;
                }
                let public_key = self.Account_public_keys.read(count);
                if is_valid_stark_signature(hash, public_key, signature) {
                    break true;
                } else {
                    count -= 1;
                }
            };
        }
    }

    #[embeddable_as(AccountMixinImpl)]
    impl AccountMixin<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of super::AccountABI<ComponentState<TContractState>> {
        // ISRC6
        fn __execute__(
            self: @ComponentState<TContractState>, calls: Array<Call>
        ) -> Array<Span<felt252>> {
            SRC6::__execute__(self, calls)
        }

        fn __validate__(self: @ComponentState<TContractState>, calls: Array<Call>) -> felt252 {
            SRC6::__validate__(self, calls)
        }

        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            SRC6::is_valid_signature(self, hash, signature)
        }

        // ISRC6CamelOnly
        fn isValidSignature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            SRC6CamelOnly::isValidSignature(self, hash, signature)
        }

        // IDeclarer
        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252
        ) -> felt252 {
            Declarer::__validate_declare__(self, class_hash)
        }

        // IDeployable
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: felt252
        ) -> felt252 {
            Deployable::__validate_deploy__(self, class_hash, contract_address_salt, public_key)
        }

        // IPublicKey
        fn get_public_key(self: @ComponentState<TContractState>, count: u8) -> felt252 {
            PublicKey::get_public_key(self, count)
        }

        fn add_public_key(ref self: ComponentState<TContractState>, new_public_key: felt252) {
            PublicKey::add_public_key(ref self, new_public_key);
        }

        fn change_public_key(
            ref self: ComponentState<TContractState>, count: u8, new_public_key: felt252
        ) {
            PublicKey::change_public_key(ref self, count, new_public_key);
        }


        // IMasterAccount
        fn get_master_account(self: @ComponentState<TContractState>) -> ContractAddress {
            MasterAccount::get_master_account(self)
        }

        fn set_master_account(
            ref self: ComponentState<TContractState>, new_master_account: ContractAddress
        ) {
            MasterAccount::set_master_account(ref self, new_master_account);
        }

        // IPublicKeyCamel
        fn getPublicKey(self: @ComponentState<TContractState>, count: u8) -> felt252 {
            PublicKey::get_public_key(self, count)
        }

        fn addPublicKey(ref self: ComponentState<TContractState>, newPublicKey: felt252) {
            PublicKey::add_public_key(ref self, newPublicKey);
        }

        fn changePublicKey(
            ref self: ComponentState<TContractState>, count: u8, newPublicKey: felt252
        ) {
            PublicKey::change_public_key(ref self, count, newPublicKey);
        }

        // ISRC5
        fn supports_interface(
            self: @ComponentState<TContractState>, interface_id: felt252
        ) -> bool {
            let src5 = get_dep_component!(self, SRC5);
            src5.supports_interface(interface_id)
        }
    }
}

#[starknet::interface]
trait AccountABI<TState> {
    // ISRC6
    fn __execute__(self: @TState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, calls: Array<Call>) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;

    // ISRC5
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;

    // IDeclarer
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;

    // IDeployable
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, public_key: felt252
    ) -> felt252;

    // IPublicKey
    fn get_public_key(self: @TState, count: u8) -> felt252;
    fn add_public_key(ref self: TState, new_public_key: felt252);
    fn change_public_key(ref self: TState, count: u8, new_public_key: felt252);

    // IMasterAccount
    fn get_master_account(self: @TState) -> ContractAddress;
    fn set_master_account(ref self: TState, new_master_account: ContractAddress);


    // ISRC6CamelOnly
    fn isValidSignature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;

    // IPublicKeyCamel
    fn getPublicKey(self: @TState, count: u8) -> felt252;
    fn addPublicKey(ref self: TState, newPublicKey: felt252);
    fn changePublicKey(ref self: TState, count: u8, newPublicKey: felt252);
}


#[starknet::interface]
trait IMasterAccount<TState> {
    fn get_master_account(self: @TState) -> ContractAddress;
    fn set_master_account(ref self: TState, new_master_account: ContractAddress);
}

#[starknet::interface]
trait IPublicKey<TState> {
    fn get_public_key(self: @TState, count: u8) -> felt252;
    fn add_public_key(ref self: TState, new_public_key: felt252);
    fn change_public_key(ref self: TState, count: u8, new_public_key: felt252);
}

#[starknet::interface]
trait IPublicKeyCamel<TState> {
    fn getPublicKey(self: @TState, count: u8) -> felt252;
    fn addPublicKey(ref self: TState, newPublicKey: felt252);
    fn changePublicKey(ref self: TState, count: u8, newPublicKey: felt252);
}
