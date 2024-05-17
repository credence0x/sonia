#[starknet::interface]
trait IUserRegistry<TContractState> {
    fn get_username(self: @TContractState, id: u128) -> felt252;
    fn get_id(self: @TContractState, username: felt252) -> u128;
    fn register(ref self: TContractState, username: felt252);
    fn grant_access(ref self: TContractState, app_id: u128, message: felt252);
}

#[starknet::contract]
mod UserRegistry {
    use sonia::app::registry::{IAppRegistryDispatcher, IAppRegistryDispatcherTrait};
    use starknet::ContractAddress;


    #[storage]
    struct Storage {
        app_registry: ContractAddress,
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

        fn register(ref self: ContractState, username: felt252) {
            let caller: ContractAddress = starknet::get_contract_address();
            assert!(self.authorized.read(caller).is_zero(), "this account is already registered");
            assert!(self.get_id(username).is_zero(), "the username is already taken");

            let id: u128 = self.uuid.read() + 1;
            self.uuid.write(id);

            self.authorized.write(caller, id);
            self.username.write(id, username);
            self.id.write(username, id);
        }

        fn grant_access(ref self: ContractState, app_id: u128, message: felt252) {
            let app_registry = IAppRegistryDispatcher {
                contract_address: self.app_registry.read()
            };
            assert!(app_registry.get_name(app_id).is_non_zero(), "app does not exist");
        // ensure message was properly signed
        // create account
        }


    }
}
