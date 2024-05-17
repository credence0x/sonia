#[starknet::contract]
mod AppRegistry {
    use alexandria_storage::list::{List, ListTrait};
    use starknet::ContractAddress;
    use starknet::Store;

    
    #[storage]
    struct Storage {
        uuid: u128,
        name: LegacyMap<u128, ByteArray>,
        domain: LegacyMap<u128, ByteArray>,
        admin: LegacyMap<u128, ContractAddress>,
    }

    #[generate_trait]
    #[abi(per_item)]
    impl AppRegistryImpl of AppRegistryTrait {
        #[abi(embed_v0)]
        fn register(ref self: ContractState, domain: ByteArray, admin: ContractAddress ) {
            let id: u128 = self.uuid.read() + 1;
            self.uuid.write(id);
            self.domain.write(id, domain);
            self.admin.write(id, admin);
        }
    }
}