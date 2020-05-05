pragma solidity ^0.5.0;

/**
 * @title Proxy
 * @dev Implements delegation of calls to other contracts, with proper
 * forwarding of return values and bubbling of failures.
 * It defines a fallback function that delegates all calls to the address
 * returned by the abstract _implementation() internal function.
 */
 // 一个代理合约接口
 //
 // 通过正确转发返回值和失败冒泡，实现 委托调用其他合同。
 // 它定义了一个 fallback 函数，该函数将所有调用委派给抽象_implementation（）内部函数返回的地址。
contract Proxy {
    /**
    * @dev Fallback function.
    * Implemented entirely in `_fallback`.
    */
    function () payable external {
        _fallback();
    }

    /**
    * @return The Address of the implementation.
    */
    //
    // 返回 实施合约地址
    function _implementation() internal view returns (address);

    /**
    * @dev Delegates execution to an implementation contract.
    * This is a low level function that doesn't return to its internal call site.
    * It will return to the external caller whatever the implementation returns.
    * @param implementation Address to delegate.
    */
    // 执行一个 合约实例的 代理调用
    //
    // 这是一个底层函数，不会返回其内部调用站点
    // 无论实现返回什么，它将返回给外部调用者
    //
    // implementation: 被代理的合约
    function _delegate(address implementation) internal {
        assembly {
        // Copy msg.data. We take full control of memory in this inline assembly
        // block because it will not return to Solidity code. We overwrite the
        // Solidity scratch pad at memory position 0.
        //
        // 复制msg.data。 我们将完全控制此内联汇编块中的内存，因为它不会返回到Solidity代码.
        // 我们在内存位置0覆盖了Solidity暂存器.
        calldatacopy(0, 0, calldatasize) // calldatasize 哪里定义 ??

        // Call the implementation.
        // out and outsize are 0 because we don't know the size yet.
        // 
        // 调用 一个合约实例
        // out和outsize为0，因为我们尚不知道大小, 下面使用 returndatacopy 获取 调用返回值
        let result := delegatecall(gas, implementation, 0, calldatasize, 0, 0)

        // Copy the returned data.
        returndatacopy(0, 0, returndatasize) // returndatasize 哪里定义 ??

        switch result
        // delegatecall returns 0 on error.
        // 代理调用 返回 0 或者 err 
        // 沃日, function 不是没定义 返回值类型么?? 
        case 0 { revert(0, returndatasize) }
        default { return(0, returndatasize) }
        }
    }

    /**
    * @dev Function that is run as the first thing in the fallback function.
    * Can be redefined in derived contracts to add functionality.
    * Redefinitions must call super._willFallback().
    */
    // TODO 需要被重写
    // 作为后备功能中的第一件事运行的功能.
    // 可以在派生合同中重新定义以添加功能.
    // 重新定义必须调用super._willFallback().
    function _willFallback() internal {
    }

    /**
    * @dev fallback implementation.
    * Extracted to enable manual triggering.
    */
    function _fallback() internal {
        _willFallback();
        _delegate(_implementation());
    }
}