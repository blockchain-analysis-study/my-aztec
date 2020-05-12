pragma solidity ^0.5.0;

import './BaseAdminUpgradeabilityProxy.sol';

/**
 * @title AdminUpgradeabilityProxy
 * @dev Extends from BaseAdminUpgradeabilityProxy with a constructor for
 * initializing the implementation, admin, and init data.
 */
// 用来代理升级的 管理员合约
//
// 使用构造函数从BaseAdminUpgradeabilityProxy扩展，用于初始化实现，管理和初始化数据
//
// TODO 用来管理存储合约升级， 记录管理员地址和升级后的地址，防止随意升级。
contract AdminUpgradeabilityProxy is BaseAdminUpgradeabilityProxy, UpgradeabilityProxy {
    /**
    * Contract constructor.
    * @param _logic address of the initial implementation.
    * @param _admin Address of the proxy administrator.
    * @param _data Data to send as msg.data to the implementation to initialize the proxied contract.
    * It should include the signature and the parameters of the function to be called, as described in
    * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
    * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
    */
    // 在 初始化 AdminUpgradeabilityProxy 实例时, 将 某个 实现合约 的地址_logic 
    // 传递给 UpgradeabilityProxy的构造函数, 由UpgradeabilityProxy来设置 实现合约的地址
    // 和根据data是否为空来决定是否发起代理调用 _logic 的逻辑
    constructor(address _logic, address _admin, bytes memory _data) UpgradeabilityProxy(_logic, _data) public payable {
        assert(ADMIN_SLOT == bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1));
        // 校验 admin 是否为空
        require(_admin != address(0x0), "Cannot set the admin address to address(0x0)");
        // 设置 admin 地址
        _setAdmin(_admin);
    }
}
