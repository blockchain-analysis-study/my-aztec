pragma solidity ^0.5.0;

import './BaseUpgradeabilityProxy.sol';

/**
 * @title UpgradeabilityProxy
 * @dev Extends BaseUpgradeabilityProxy with a constructor for initializing
 * implementation and init data.
 */
 // 用构造函数扩展 BaseUpgradeabilityProxy 以初始化实现和初始化数据
contract UpgradeabilityProxy is BaseUpgradeabilityProxy {
    /**
    * @dev Contract constructor.
    * @param _logic Address of the initial implementation.
    * @param _data Data to send as msg.data to the implementation to initialize the proxied contract.
    * It should include the signature and the parameters of the function to be called, as described in
    * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
    * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
    */
    //
    // _logic: 初始 实现合约地址
    // _data: 数据以 msg.data 的形式发送给实现以初始化代理合约
    //
    // 它应包括签名和要调用的函数的参数，如
    // https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding。
    // 此data参数是可选的，如果未提供任何数据，则将跳过对代理合约的初始化调用。
    constructor(address _logic, bytes memory _data) public payable {
        assert(IMPLEMENTATION_SLOT == bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1));
        // 设置 实现合约地址
        _setImplementation(_logic);

        // 决定要不要 代理调用 下实现合约的逻辑
        if(_data.length > 0) {
            (bool success,) = _logic.delegatecall(_data);
            require(success);
        }
    }
}