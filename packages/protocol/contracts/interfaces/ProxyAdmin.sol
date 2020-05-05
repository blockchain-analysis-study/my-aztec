pragma solidity ^0.5.0;

/**
 * @title ProxyAdmin
 * @dev Minimal interface for the proxy contract
 */
 // 代理合同的最小接口
 // 做权限控制用的
contract ProxyAdmin {
    function admin() external returns (address);

    function upgradeTo(address _newImplementation) external;

    function changeAdmin(address _newAdmin) external;
}
