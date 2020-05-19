pragma solidity >=0.5.0 <0.6.0;


/**
 * @title Library of EIP712 utility constants and functions
 * @author AZTEC
 *
 * Copyright 2020 Spilsbury Holdings Ltd 
 *
 * Licensed under the GNU Lesser General Public Licence, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
**/
//
// TODO EIP712 标准: 一个对结构化数据的Hash标准 (让 签名不仅仅只是针对 字符串)
//  
// TODO 这个也是 【AZTEC加密引擎】
contract LibEIP712 {

    // EIP712 Domain Name value
    string constant internal EIP712_DOMAIN_NAME = "AZTEC_CRYPTOGRAPHY_ENGINE";

    // EIP712 Domain Version value
    string constant internal EIP712_DOMAIN_VERSION = "1";

    // Hash of the EIP712 Domain Separator Schema
    //
    // 定义域分隔符的哈希值
    //
    // eip712Domain的类型是一个名为EIP712Domain的结构体，并带有一个或多个以下字段。
    // 协议设计者只需要包含对其签名域名有意义的字段，未使用的字段不在结构体类型中。
    //
    //      string name：用户可读的签名域名的名称。例如Dapp的名称或者协议。
    //      string version：签名域名的目前主版本。不同版本的签名不兼容。
    //      uint256 chainId：EIP-155中的链id。用户代理应当拒绝签名如果和目前的活跃链不匹配的话。
    //      address verifyContract：验证签名的合约地址。用户代理可以做合约特定的网络钓鱼预防。
    //      bytes32 salt：对协议消除歧义的加盐。这可以被用来做域名分隔符的最后的手段。
    // 
    bytes32 constant internal EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH = keccak256(abi.encodePacked(
        "EIP712Domain(",
            "string name,",
            "string version,",
            "address verifyingContract",
        ")"
    ));

    // Hash of the EIP712 Domain Separator data
    // solhint-disable-next-line var-name-mixedcase
    //
    // 定义 域分隔符数据的哈希值
    // solhint-disable-next-line var-name-mixedcase
    bytes32 public EIP712_DOMAIN_HASH;

    constructor ()
        public
    {   
        // 生成当前域的 唯一标识
        //
        // 使用 域分隔符Hash值
        // 使用 domain name
        // 使用 domain version
        // 使用 当前合约 address
        EIP712_DOMAIN_HASH = keccak256(abi.encode(
            EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH,
            keccak256(bytes(EIP712_DOMAIN_NAME)),
            keccak256(bytes(EIP712_DOMAIN_VERSION)),
            address(this)
        ));
    }

    /// @dev Calculates EIP712 encoding for a hash struct in this EIP712 Domain.
    /// @param _hashStruct The EIP712 hash struct.
    /// @return EIP712 hash applied to this EIP712 Domain.
    //
    // todo 计算此EIP712域中哈希结构的EIP712编码
    // 
    // 入参: 
    // _hashStruct: EIP712哈希结构
    // 
    // 返参:
    // EIP712 Hash 应用于此 EIP712域
    function hashEIP712Message(bytes32 _hashStruct)
        internal
        view
        returns (bytes32 _result)
    {
        bytes32 eip712DomainHash = EIP712_DOMAIN_HASH;

        // Assembly for more efficient computing:
        // keccak256(abi.encodePacked(
        //     EIP191_HEADER,
        //     EIP712_DOMAIN_HASH,
        //     hashStruct
        // ));

        // todo 使用 Assembly 以提升计算效率
        //
        // keccak256(abi.encodePacked(
        //     EIP191_HEADER,
        //     EIP712_DOMAIN_HASH,
        //     hashStruct
        // ));

        assembly {
            // Load free memory pointer. We're not going to use it - we're going to overwrite it!
            // We need 0x60 bytes of memory for this hash,
            // cheaper to overwrite the free memory pointer at 0x40, and then replace it, than allocating free memory
            
            // 加载 可用的内存指针. 我们不会去用它, 我们将会覆盖它
            // 我们将给 _hashStruct 0x60 bytes 内存
            // 与分配可用内存相比，在0x40处覆盖可用内存指针，然后替换该指针要便宜得多
            
            let memPtr := mload(0x40) // 先读出在 0x40 处的 可用指针, 因为下面会覆盖它
            mstore(0x00, 0x1901)               // EIP191 header  写入 EIP191 的头
            mstore(0x20, eip712DomainHash)     // EIP712 domain hash  写入本合约中的字段 (即: 构造函数中算出来的 domainHash)
            mstore(0x40, _hashStruct)          // Hash of struct 写入 入参的 _hashStruct

            // keccak256(30, 66) | keccak256(offset, size)
            //
            // 在 opSha3 中是这样写的..
            //
            // offset, size := stack.pop(), stack.pop()
            // data := memory.GetPtr(offset.Int64(), size.Int64())
            // 
            _result := keccak256(0x1e, 0x42)   // compute hash  计算Hash, 这个就是 该函数的返回值啦


            // replace memory pointer
            mstore(0x40, memPtr)  // 重新将之前在0x40 读出来的可用指针, "覆盖" 写回去
        }
    }

    /// @dev Extracts the address of the signer with ECDSA.
    /// @param _message The EIP712 message.
    /// @param _signature The ECDSA values, v, r and s.
    /// @return The address of the message signer.
    ///
    /// 使用ECDSA提取签名者的地址
    /// 
    /// 入参:
    /// _message: EIP712的message
    /// _signature: 一个 ECDSA 的签名值, v, r, s 组成
    /// 
    /// 返参:
    /// 签名了该 message 的 address
    function recoverSignature(
        bytes32 _message,
        bytes memory _signature
    ) internal view returns (address _signer) {
        bool result;
        assembly {
            // Here's a little trick we can pull. We expect `_signature` to be a byte array, of length 0x60, with
            // 'v', 'r' and 's' located linearly in memory. Preceeding this is the length parameter of `_signature`.
            // We *replace* the length param with the signature msg to get a memory block formatted for the precompile
            // load length as a temporary variable

            // 这是我们可以借鉴的小技巧。 
            // 我们期望 `_signature` 是一个字节数组，长度为0x60， 32bytes|32bytes|32bytes == 0x60
            // 其中 'v', 'r' 和 's' 线性地位于内存中。 
            // 在此之前是`_signature`的length参数。
            // 
            // 我们用 签名msg 替换长度参数 (byteLength)，以获取格式化为预编译加载长度的存储块作为临时变量

            let byteLength := mload(_signature) // 先将 _signature 为 offset 取出后32bytes 数据 "byteLength"

            // store the signature message
            mstore(_signature, _message) // 将 message 存入 _signature 作为offset为起点的后32字节

            // load 'v' - we need it for a condition check
            // add 0x60 to jump over 3 words - length of bytes array, r and s
            //
            // 加载 'v' - 我们需要它来进行条件检查
            //
            let v := mload(add(_signature, 0x60)) // 取出 _signature + 0x60 处作为 offset 的数据"v"
            let s := mload(add(_signature, 0x40)) // 取出 _signature + 0x40 处作为 offset 的数据"s"
            v := shr(248, v) // bitshifting, to resemble padLeft  将 v >> 248

            /**
            * Original memory map for input to precompile
            *
            * _signature : _signature + 0x20            message
            * _signature + 0x20 : _signature + 0x40     r
            * _signature + 0x40 : _signature + 0x60     s
            * _signature + 0x60 : _signature + 0x80     v

            * Desired memory map for input to precompile
            *
            * _signature : _signature + 0x20            message
            * _signature + 0x20 : _signature + 0x40     v
            * _signature + 0x40 : _signature + 0x60     r
            * _signature + 0x60 : _signature + 0x80     s
            */

            /**
            * 原始 的内存映射用于输入以进行预编译 (顺序: message > r > s > v)
            *
            * _signature：_signature + 0x20        message
            * _signature + 0x20：_signature + 0x40 r
            * _signature + 0x40：_signature + 0x60 s
            * _signature + 0x60：_signature + 0x80 v

            * 所需 的内存映射以用于预编译输入 (顺序: message > v > r > s)
            *
            * _signature：_signature + 0x20        message
            * _signature + 0x20：_signature + 0x40 v
            * _signature + 0x40：_signature + 0x60 r
            * _signature + 0x60：_signature + 0x80 s
            */

            // move s to v position
            // 移动 s -> v 的位置
            mstore(add(_signature, 0x60), mload(add(_signature, 0x40)))
            // move r to s position
            // 移动 r -> s 的位置
            mstore(add(_signature, 0x40), mload(add(_signature, 0x20)))
            // move v to r position
            // 移动 v -> r 的位置
            mstore(add(_signature, 0x20), v)

            // 最后 求出来的结果是.
            // [(s < 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)&[(验证签名长度  == 0x41)&(v == 27 | v == 28)]] & staticcall(ecrecover合约)
            result := and(

                // 再求 一次 & 值
                and(
                    // validate s is in lower half order
                    // 验证 s 在较低的一半顺序,  s < 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
                    lt(s, 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0),

                    // 算出 下面两个验证结果的 & 值
                    and(
                        // validate signature length == 0x41
                        // 验证签名长度  == 0x41
                        eq(byteLength, 0x41),

                        // validate v == 27 or v == 28
                        // 验证 v == 27 或者 v == 28
                        or(eq(v, 27), eq(v, 28))
                    )
                ),


                // validate call to precompile succeeds
                // 
                // 格式: staticcall(gasLimit, to, inputOffset, inputSize, outputOffset, outputSize)
                // 发起静态调用 ecrecover 合约
                staticcall(gas, 0x01, _signature, 0x80, _signature, 0x20)
            )
            // save the _signer only if the first word in _signature is not `_message` anymore
            // 仅当 `_signature` 中的第一个单词不再是_message时，才保存_signer
            //
            // TODO 那么什么时候 才不是 message 呢? 
            //      上面的代码中看,  staticcall() 这里将返回值 回填到 _signature 了
            switch eq(_message, mload(_signature)) 
            case 0 {

                // 从 _signature 中解出 signer 了, 这个就是 发起签名的 Address
                _signer := mload(_signature)
            }

            // 并将字节长度放回它 原来所属的位置
            mstore(_signature, byteLength) // and put the byte length back where it belongs
        }
        
        // wrap Failure States in a single if test, so that happy path only has 1 conditional jump
        //
        // 将失败状态包装在一个if测试中，以便 正确路径 仅具有1个条件跳转
        //
        // 只有当 验证和staticcall 的结果出问题<不为1> 或者 签名人Address 解出来时, 才进入if
        // 就是为了返回 是哪个没有通过~
        if (!(result && (_signer != address(0x0)))) {
            require(_signer != address(0x0), "signer address cannot be 0");
            require(result, "signature recovery failed");
        }
    }
}

