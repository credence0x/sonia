use starknet::ContractAddress;

#[starknet::interface]
trait IUserRegistry<TContractState> {
    fn get_username(self: @TContractState, id: u128) -> felt252;
    fn get_id(self: @TContractState, username: felt252) -> u128;
    fn get_app_account(self: @TContractState, user_id: u128, app_id: u128) -> ContractAddress;

    fn register(ref self: TContractState, username: felt252);
    fn grant_access(
        ref self: TContractState,
        user_id: u128,
        app_id: u128,
        message: felt252,
        public_key: felt252,
        salt: felt252
    ) -> ContractAddress;
}

#[starknet::contract]
mod UserRegistry {
    use core::serde::Serde;
    use sonia::app::registry::{IAppRegistryDispatcher, IAppRegistryDispatcherTrait};
    use starknet::{ClassHash, ContractAddress, deploy_syscall};

    const APP_ACCOUNT_CLASS_HASH: felt252 = 0x1;


    #[storage]
    struct Storage {
        app_registry: ContractAddress,
        app_account: LegacyMap<(u128, u128), ContractAddress>,
        uuid: u128,
        id: LegacyMap<felt252, u128>,
        username: LegacyMap<u128, felt252>,
        authorized: LegacyMap<ContractAddress, u128>,
    }

    #[abi(embed_v0)]
    impl UserRegistryImpl of super::IUserRegistry<ContractState> {
        fn get_username(self: @ContractState, id: u128) -> felt252 {
            self.username.read(id)
        }

        fn get_id(self: @ContractState, username: felt252) -> u128 {
            self.id.read(username)
        }

        fn get_app_account(self: @ContractState, user_id: u128, app_id: u128) -> ContractAddress {
            self.app_account.read((user_id, app_id))
        }

        fn register(ref self: ContractState, username: felt252) {
            let caller: ContractAddress = starknet::get_caller_address();
            assert!(self.authorized.read(caller).is_zero(), "this account is already registered");
            assert!(self.get_id(username).is_zero(), "the username is already taken");

            let id: u128 = self.uuid.read() + 1;
            self.uuid.write(id);

            self.authorized.write(caller, id);
            self.username.write(id, username);
            self.id.write(username, id);
        }

        fn grant_access(
            ref self: ContractState,
            user_id: u128,
            app_id: u128,
            message: felt252,
            public_key: felt252,
            salt: felt252
        ) -> ContractAddress {
            let caller: ContractAddress = starknet::get_caller_address();
            assert!(self.authorized.read(caller) == user_id, "this account does not own that id");

            let app_registry = IAppRegistryDispatcher {
                contract_address: self.app_registry.read()
            };

            assert!(app_registry.get_name(app_id).is_non_zero(), "app does not exist");
            let mut app_account = self.get_app_account(user_id, app_id);
            if app_account.is_zero() {
                let mut constructor_calldata = array![];
                public_key.serialize(ref constructor_calldata);
                caller.serialize(ref constructor_calldata); // master account

                let (deployed_address, _) = deploy_syscall(
                    APP_ACCOUNT_CLASS_HASH.try_into().unwrap(),
                    salt,
                    constructor_calldata.span(),
                    false
                )
                    .unwrap();
                app_account = deployed_address;
            }

            return app_account;
        // ensure message was properly signed
        // create account
        }
    }
}
