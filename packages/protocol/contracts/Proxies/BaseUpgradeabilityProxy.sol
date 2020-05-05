pragma solidity ^0.5.0;

import "openzeppelin-solidity/contracts/utils/Address.sol";

import './Proxy.sol';

/**
 * @title BaseUpgradeabilityProxy
 * @dev This contract implements a proxy that allows to change the
 * implementation address to which it will delegate.
 * Such a change is called an implementation upgrade.
 */
 // 用来管理升级的代理合约
 //
 // 
contract BaseUpgradeabilityProxy is Proxy {
    /**
    * @dev Emitted when the implementation is upgraded.
    * @param implementation Address of the new implementation.
    */
    event Upgraded(address indexed implementation);

    /**
    * @dev Storage slot with the address of the current implementation.
    * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
    * validated in the constructor.
    */
    // 具有当前实现地址的存储插槽
    // 这是 "eip1967.proxy.implementation" 的keccak-256哈希值减去1，并在构造函数中进行了验证
    //
    // 这个适用于存储 实现合约地址的 key (statedb中)
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
    * @dev Returns the current implementation.
    * @return Address of the current implementation
    */
    // 返回当前实现
    // 
    // 返参:
    // 当前实现地址
    function _implementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
        impl := sload(slot)
        }
    }

    /**
    * @dev Upgrades the proxy to a new implementation.
    * @param newImplementation Address of the new implementation.
    */
    // 将代理升级到新的实现
    //
    // newImplementation: 新实现的地址
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
    * @dev Sets the implementation address of the proxy.
    * @param newImplementation Address of the new implementation.
    */
    // 设置代理的实现地址
    // newImplementation: 新实现的地址
    function _setImplementation(address newImplementation) internal {
        // 检查下, 入参的 address 是否是一个合约地址
        require(Address.isContract(newImplementation), "Cannot set a proxy implementation to a non-contract address");


        // 获取 实现地址的存储卡槽, statedb 中的 key
        bytes32 slot = IMPLEMENTATION_SLOT;

        assembly {
        
        // 将新的 实现合约 地址 存入 statedb 
        // key: IMPLEMENTATION_SLOT
        // value:  newImplementation
        sstore(slot, newImplementation)
        }
    }
}