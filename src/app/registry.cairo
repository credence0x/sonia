use starknet::ContractAddress;

#[starknet::interface]
trait IAppRegistry<TContractState> {
    fn get_name(self: @TContractState, id: u128) -> felt252;
    fn register(ref self: TContractState, name: felt252, domain: ByteArray, admin: ContractAddress);
}

#[starknet::contract]
mod AppRegistry {
    use alexandria_storage::list::{List, ListTrait};
    use starknet::ContractAddress;


    #[storage]
    struct Storage {
        uuid: u128,
        name: LegacyMap<u128, felt252>,
        domain: LegacyMap<u128, ByteArray>,
        admin: LegacyMap<u128, ContractAddress>,
    }

    #[abi(embed_v0)]
    impl AppRegistryImpl of super::IAppRegistry<ContractState> {
        fn get_name(self: @ContractState, id: u128) -> felt252 {
            self.name.read(id)
        }

        fn register(
            ref self: ContractState, name: felt252, domain: ByteArray, admin: ContractAddress
        ) {
            let id: u128 = self.uuid.read() + 1;
            self.uuid.write(id);
            self.domain.write(id, domain);
            self.admin.write(id, admin);
            self.name.write(id, name);
        }
    }
}
