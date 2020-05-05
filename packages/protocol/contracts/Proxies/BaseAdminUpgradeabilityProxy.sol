pragma solidity ^0.5.0;

import './UpgradeabilityProxy.sol';

/**
    * @title BaseAdminUpgradeabilityProxy
    * @dev This contract combines an upgradeability proxy with an authorization
    * mechanism for administrative tasks.
    * All external functions in this contract must be guarded by the
    * `ifAdmin` modifier. See ethereum/solidity#3864 for a Solidity
    * feature proposal that would enable this to be done automatically.
 */
contract BaseAdminUpgradeabilityProxy is BaseUpgradeabilityProxy {
    /**
    * @dev Emitted when the administration has been transferred.
    * @param previousAdmin Address of the previous admin.
    * @param newAdmin Address of the new admin.
    */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
    * @dev Storage slot with the admin of the contract.
    * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
    * validated in the constructor.
    */
    // 存储在statedb 中的 admin 地址的 key
    // 使用 "eip1967.proxy.admin"的keccak-256的Hash 减去1之后的值.
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
    * @dev Modifier to check whether the `msg.sender` is the admin.
    * If it is, it will run the function. Otherwise, it will delegate the call
    * to the implementation.
    */
    modifier ifAdmin() {
        // 校验当前交易的地址是否为 admin 的地址
        if (msg.sender == _admin()) {
            _;
        } else {
            // 否则, 最终调用到了 Proxy 中的 _fallback()
            _fallback();
        }
    }

    /**
    * @return The address of the proxy admin.
    */
   // 返回 admin 的地址 (当前 msg.sender 是 admin 地址时,才给予调用)
    function admin() external ifAdmin returns (address) {
        return _admin();
    }

    /**
    * @return The address of the implementation.
    */
    // 返回 实现合约的地址 (当前 msg.sender 是 admin 地址时,才给予调用)
    function implementation() external ifAdmin returns (address) {
        return _implementation();
    }

    /**
    * @dev Changes the admin of the proxy.
    * Only the current admin can call this function.
    * @param newAdmin Address to transfer proxy administration to.
    */
    //  修改 admin 地址 (当前 msg.sender 是 admin 地址时,才给予调用)
    function changeAdmin(address newAdmin) external ifAdmin {
        require(newAdmin != address(0), "Cannot change the admin of a proxy to the zero address");
        emit AdminChanged(_admin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
    * @dev Upgrade the backing implementation of the proxy.
    * Only the admin can call this function.
    * @param newImplementation Address of the new implementation.
    */
    // 更新  实现合约地址 (当前 msg.sender 是 admin 地址时,才给予调用)
    function upgradeTo(address newImplementation) external ifAdmin {
        _upgradeTo(newImplementation);
    }

    /**
    * @dev Upgrade the backing implementation of the proxy and call a function
    * on the new implementation.
    * This is useful to initialize the proxied contract.
    * @param newImplementation Address of the new implementation.
    * @param data Data to send as msg.data in the low level call.
    * It should include the signature and the parameters of the function to be called, as described in
    * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
    */
    // 升级 实现合约地址 且同时调用新实现合约 (代理调用方式)
    function upgradeToAndCall(address newImplementation, bytes calldata data) payable external ifAdmin {
        _upgradeTo(newImplementation);
        (bool success,) = newImplementation.delegatecall(data);
        require(success);
    }

    /**
    * @return The admin slot.
    */
    // 返回 admin 的地址
    function _admin() internal view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
        adm := sload(slot)
        }
    }

    /**
    * @dev Sets the address of the proxy admin.
    * @param newAdmin Address of the new proxy admin.
    */
    // 设置新 admin 地址
    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;

        assembly {
        sstore(slot, newAdmin)
        }
    }

    /**
    * @dev Only fall back when the sender is not the admin.
    */
    // 作为后备功能中的第一件事运行的功能.
    // 可以在派生合同中重新定义以添加功能.
    // 重新定义必须调用super._willFallback().
    //
    // 仅在 msg.sender 不是 admin 时 被调用 (fall back: 回退)
    function _willFallback() internal {
        require(msg.sender != _admin(), "Cannot call fallback function from the proxy admin");
        super._willFallback();
    }
}