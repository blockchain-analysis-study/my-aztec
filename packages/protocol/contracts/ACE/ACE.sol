pragma solidity >=0.5.0 <0.6.0;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";

import "./noteRegistry/NoteRegistryManager.sol";

import "../interfaces/IAZTEC.sol";

import "../libs/NoteUtils.sol";
// TODO: v-- harmonize
import "../libs/ProofUtils.sol";
import "../libs/VersioningUtils.sol";
import "../libs/SafeMath8.sol";

/**
 * @title The AZTEC Cryptography Engine
 * @author AZTEC
 * @dev ACE validates the AZTEC protocol's family of zero-knowledge proofs, which enables
 *      digital asset builders to construct fungible confidential digital assets according to the AZTEC token standard.
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
// 分别 集成了, IAZTEC, Ownable, NoteRegistryManager 三个合约
// Ownable 是在 openzeppelin-solidity/contracts/ownership/Ownable.sol 的合约
contract ACE is IAZTEC, Ownable, NoteRegistryManager {
    using NoteUtils for bytes;
    using ProofUtils for uint24;
    using SafeMath for uint256;
    using SafeMath8 for uint8;

    event SetCommonReferenceString(bytes32[6] _commonReferenceString);
    event SetProof(
        uint8 indexed epoch,
        uint8 indexed category,
        uint8 indexed id,
        address validatorAddress
    );
    event IncrementLatestEpoch(uint8 newLatestEpoch);

    // The commonReferenceString contains one G1 group element and one G2 group element,
    // that are created via the AZTEC protocol's trusted setup. All zero-knowledge proofs supported
    // by ACE use the same common reference string.
    //
    // commonReferenceString:
    // 包含一个G1组元素和一个G2组元素，
    // 它们是通过AZTEC协议的受信任设置 (trusted setup) 创建的。 
    // ACE支持的所有零知识证明都使用相同的公共参考字符串。
    bytes32[6] private commonReferenceString; 

    // `validators`contains the addresses of the contracts that validate specific proof types
    // `validators` 包含验证特定proof类型的合约地址
    // 数组的维分别表示, [epoch][category][id] == [256][256][256*256]
    address[0x100][0x100][0x10000] public validators; 

    // a list of invalidated proof ids, used to blacklist proofs in the case of a vulnerability being discovered
    // 无效proof ID的列表，用于在发现漏洞时将proof列入黑名单
    // 数组的维分别表示, [epoch][category][id] == [256][256][256*256]
    bool[0x100][0x100][0x10000] public disabledValidators; 

    // latest proof epoch accepted by this contract
    // 本合约接受的最新证明 epoch (默认是: 1)
    uint8 public latestEpoch = 1;

    /**
    * @dev contract constructor. Sets the owner of ACE
    **/
    // 合约构造函数， 设置 ACE 的 owner, 
    // 由 openzeppelin-solidity/contracts/ownership/Ownable.sol 实现
    constructor() public Ownable() {}

    /**
    * @dev Mint AZTEC notes
    *
    * @param _proof the AZTEC proof object
    * @param _proofData the mint proof construction data
    * @param _proofSender the Ethereum address of the original transaction sender. It is explicitly assumed that
    *        an asset using ACE supplies this field correctly - if they don't their asset is vulnerable to front-running
    * Unnamed param is the AZTEC zero-knowledge proof data
    * @return two `bytes` objects. The first contains the new confidentialTotalSupply note and the second contains the
    * notes that were created. Returned so that a zkAsset can emit the appropriate events
    */
    //
    // 构造AZTEC的票据 note
    //
    // 入参:
    // _proof: aztec 的proof 对象
    // _proofData: burn proof 需要证明的data
    // _proofSender: 原始(最原始的那个发起者)交易发送方的以太坊地址。 
    //               明确假定使用ACE的资产可以正确提供此字段-如果资产不易受前端攻击，
    //               则无名参数是AZTEC零知识证明数据.
    // 
    // 返参:
    // 两个“字节”对象。 第一个包含新的ConfidentialTotalSupply note，第二个包含已创建的 note。
    // 返回，以便zkAsset可以发出适当(appropriate)的事件 
    function mint(
         // 证明
        uint24 _proof,
        // 需要证明的 数据
        bytes calldata _proofData,
        // proof类型 对应的proof合约地址
        address _proofSender
    ) external returns (bytes memory) {

        // 根据 调用该合约的 tx 上级发送者 获取对应的
        // TODO 在 NoteRegistryManager 的 createNoteRegistry() 方法创建的
        NoteRegistry memory registry = registries[msg.sender];

        // 断言校验 当前 msg.sender对应的注册表 的行为合约的address 是否非法
        require(address(registry.behaviour) != address(0x0), "note registry does not exist for the given address");

        // Check that it's a mintable proof
        // 检查这是可铸造的证明
        //
        // 调用的是 ProofUtils的getProofComponents() 函数
        // 返回: epoch, category and proofId
        (, uint8 category, ) = _proof.getProofComponents();

        // 校验 proof 的种类, 如果不是 mint
        require(category == uint8(ProofCategory.MINT), "this is not a mint proof");

        // 根据 证明 和 证明合约 及需要证明的数据, 返回证明结果输出
        // TODO 生成 包含 铸币时的 inputs和outputs的 proofOutput
        //      并将 validateProofHash 置为 true 已被后续 更新 note的 inputs 和 outputs 时使用
        bytes memory _proofOutputs = this.validateProof(_proof, _proofSender, _proofData);

        // 校验 证明结果输出 是否为空
        require(_proofOutputs.getLength() > 0, "call to validateProof failed");

        // 根据 证明输出，和注册表的行为 进行 token 转 加密币
        // 
        // TODO 其实 Behaviour201907 中还未实现 mint.
        // TODO 但是 BehaviourAdjustable201907 实现了, 其继承了 Behaviour201907
        registry.behaviour.mint(_proofOutputs);
        return(_proofOutputs);
    }

    /**
    * @dev Burn AZTEC notes
    *
    * @param _proof the AZTEC proof object
    * @param _proofData the burn proof construction data
    * @param _proofSender the Ethereum address of the original transaction sender. It is explicitly assumed that
    *        an asset using ACE supplies this field correctly - if they don't their asset is vulnerable to front-running
    * Unnamed param is the AZTEC zero-knowledge proof data
    * @return two `bytes` objects. The first contains the new confidentialTotalSupply note and the second contains the
    * notes that were created. Returned so that a zkAsset can emit the appropriate events
    */
     // 【销毁加密币】
    // 加密世界提币到token世界
    // _proof: aztec 的proof 对象
    // _proofData: burn proof 需要证明的data
    // _proofSender: 原始(最原始的那个发起者)交易发送方的以太坊地址。 
    //               明确假定使用ACE的资产可以正确提供此字段-如果资产不易受前端攻击，
    //               则无名参数是AZTEC零知识证明数据.
    // 
    // 返参:
    // 两个“字节”对象。 第一个包含新的ConfidentialTotalSupply note，第二个包含已创建的 note。
    // 返回，以便zkAsset可以发出适当(appropriate)的事件
    function burn(
       
        uint24 _proof,
        bytes calldata _proofData,
        address _proofSender
    ) external returns (bytes memory) {

        // 从 各个账户 的note注册表集中 获取当前 msg.sender 对应的note注册表结构
        // 只是查出来 使用它的某些 状态和函数而已, 所以用 memory
        NoteRegistry memory registry = registries[msg.sender];
        require(address(registry.behaviour) != address(0x0), "note registry does not exist for the given address");

        // Check that it's a burnable proof
        (, uint8 category, ) = _proof.getProofComponents();

        require(category == uint8(ProofCategory.BURN), "this is not a burn proof");

        bytes memory _proofOutputs = this.validateProof(_proof, _proofSender, _proofData);
        require(_proofOutputs.getLength() > 0, "call to validateProof failed");

        // TODO 生成 包含 提币时的 inputs和outputs的 proofOutput
        //      并将 validateProofHash 置为 true 已被后续 更新 note的 inputs 和 outputs 时使用
        //
        // TODO 其实 Behaviour201907 中还未实现 burn.
        // TODO 但是 BehaviourAdjustable201907 实现了, 其继承了 Behaviour201907
        registry.behaviour.burn(_proofOutputs);
        return _proofOutputs;
    }

    /**
    * @dev Validate an AZTEC zero-knowledge proof. ACE will issue a validation transaction to the smart contract
    *      linked to `_proof`. The validator smart contract will have the following interface:
    *
    *      function validate(
    *          bytes _proofData,
    *          address _sender,
    *          bytes32[6] _commonReferenceString
    *      ) public returns (bytes)
    *
    * @param _proof the AZTEC proof object
    * @param _sender the Ethereum address of the original transaction sender. It is explicitly assumed that
    *        an asset using ACE supplies this field correctly - if they don't their asset is vulnerable to front-running
    * Unnamed param is the AZTEC zero-knowledge proof data
    * @return a `bytes proofOutputs` variable formatted according to the Cryptography Engine standard
    */
    //
    // 验证AZTEC的零知识证明。 【ACE将向链接到_proof的智能合约发出验证交易】。 验证者智能合约将具有以下界面：
    //      function validate(
    //          bytes _proofData,
    //          address _sender,
    //          bytes32[6] _commonReferenceString
    //      ) public returns (bytes)
    // 
    // 入参: 
    // _proof: AZTEC证明对象
    // _sender: 原始交易发送方的以太坊地址。 
    //          明确假定使用ACE的资产可以正确提供此字段-如果资产不易受前端攻击，
    //          则无名参数是AZTEC零知识证明数据.
    // _proofData: 需要被证明的数据
    // 返参:
    // 按照加密引擎标准格式化的“ bytesproofOutputs”变量
    // 
    // todo: 说白了，这个就是ACE 指派proof合约对数据进行 证明
    // 只有校验通过的 _proofOutput 才可以进行操作 input 和output 的变更, _proofOutput 包含inputs和outputs
    function validateProof(uint24 _proof, address _sender, bytes calldata) external returns (bytes memory) {
        require(_proof != 0, "expected the proof to be valid");
        // validate that the provided _proof object maps to a corresponding validator and also that
        // the validator is not disabled
        //
        // 验证提供的_proof对象是否映射到相应的验证器，并且验证器未禁用
        // (就是 根据 proof 去statedb查回对应的 proof合约地址)
        address validatorAddress = getValidatorAddress(_proof);

        // 用于接收 返回参数
        bytes memory proofOutputs;

        // TODO 因为使用  汇编的形式 获取 calldata 中的数值
        //      所以代码里面就不直接使用 形参了, 但是 形参必须存在,
        //      存在形参, 这样外面调用的地方才可以传参进来, 
        //      否则 mload(0x40) 这里是取不到 入参的
        assembly {
            // the first evm word of the 3rd function param is the abi encoded location of proof data
            
            // 第三个函数参数的第一个evm词是证明数据的abi编码位置
            // calldataload(数据开始的index) 从 calldata `_proofData` 中 取 32byte的数据,
            // 取出来的数据转成 bigInt 然后和 0x04 相加得到 一个 指针的指向位置
            // 0x04 + calldataload(0x44) == 4 + calldataload(第68byte)
            let proofDataLocation := add(0x04, calldataload(0x44))

            // manually construct validator calldata map
            //
            // 手动构造验证器calldata映射
            // mload 是从memory 中获取从0x40处开始的32byte
            let memPtr := mload(0x40)

            // location in calldata of the start of `bytes _proofData` (0x100)
            // `bytes _proofData` 的开头在calldata中的位置（0x100）
            // mstore(start, val), 将val存入已 start 为指针起始点的 memory中
            //
            // commonReferenceString_slot 和 bytes32[6] private commonReferenceString; 有关系??
            //
            mstore(add(memPtr, 0x04), 0x100)   // 将 0x100 存入 memory的 add(memPtr, 0x04) 指针位置
            mstore(add(memPtr, 0x24), _sender) // 将 sender 存入 memory的 add(memPtr, 0x24) 指针位置 
            mstore(add(memPtr, 0x44), sload(commonReferenceString_slot)) // 将statedb 中的 commonReferenceString_slot对应的数据 存入 memory
            mstore(add(memPtr, 0x64), sload(add(0x01, commonReferenceString_slot)))
            mstore(add(memPtr, 0x84), sload(add(0x02, commonReferenceString_slot)))
            mstore(add(memPtr, 0xa4), sload(add(0x03, commonReferenceString_slot)))
            mstore(add(memPtr, 0xc4), sload(add(0x04, commonReferenceString_slot)))
            mstore(add(memPtr, 0xe4), sload(add(0x05, commonReferenceString_slot)))

            // 0x104 because there's an address, the length 6 and the static array items
            // 0x104，因为这里有一个地址，长度为6 及 静态数组项
            // 得到一个指针的起始位置
            let destination := add(memPtr, 0x104)
            // note that we offset by 0x20 because the first word is the length of the dynamic bytes array
            // 请注意，我们偏移了0x20，因为第一个字是动态字节数组的长度
            let proofDataSize := add(calldataload(proofDataLocation), 0x20)
            // copy the calldata into memory so we can call the validator contract
            // 将calldata复制到内存中，以便我们调用验证人合同
            // destination: 指向memory 中的指针起始位置
            // proofDataLocation: callData (`bytes _proofData`) 中提取数据的起始位置
            // proofDataSize:  calData 中提取数据的Size
            calldatacopy(destination, proofDataLocation, proofDataSize)
            // call our validator smart contract, and validate the call succeeded
            // 调用我们的验证者智能合约，并验证调用是否成功
            // 计算 call 的入参数据的偏移位置 0x104 == 260
            let callSize := add(proofDataSize, 0x104)

            // 发起 static 跨合约调用, 调用 对应的proof 合约 生成 proofOutput (这里面就包含了生成的 inputs 和 outputs) 
            //
            // 使用静态调用 成功是1, 失败是0
            switch staticcall(gas, validatorAddress, memPtr, callSize, 0x00, 0x00)
            case 0 {
                // call失败，因为证据无效
                mstore(0x00, 400) revert(0x00, 0x20) // call failed because proof is invalid
            }

            // copy returndata to memory
            // 将returndata复制到内存
            // returndatacopy(memOffset, dataOffset, length)
            returndatacopy(memPtr, 0x00, returndatasize) // TODO returndatasize 是怎么来的?
            // store the proof outputs in memory
            // 将校样输出存储在内存中
            mstore(0x40, add(memPtr, returndatasize))
            // the first evm word in the memory pointer is the abi encoded location of the actual returned data
            //
            // =================================================== 
            // ===================== 超级重要 =====================
            //
            // 内存指针中的第一个evm字是实际返回数据的abi编码位置
            //
            // 生成 proofOutput (这里面就包含了生成的 inputs 和 outputs)  TODO 很多地方用到
            //
            // =================================================== 
            // =================================================== 
            proofOutputs := add(memPtr, mload(memPtr))
        }

        // if this proof satisfies a balancing relationship, we need to record the proof hash
        // 如果此证明满足平衡关系，我们需要记录证明哈希
        if (((_proof >> 8) & 0xff) == uint8(ProofCategory.BALANCED)) {
            uint256 length = proofOutputs.getLength();
            for (uint256 i = 0; i < length; i += 1) {
                
                // 组个算出 proofHash
                bytes32 proofHash = keccak256(proofOutputs.get(i));

                // 根据proofHash 和当前 msg.sender 算出 proofHash的校验标识key
                bytes32 validatedProofHash = keccak256(abi.encode(proofHash, _proof, msg.sender));

                // =================================================== 
                // ===================== 超级重要 =====================
                // 
                // 将 证明 的Hash 标识置为 可用, 
                // 只有可用的在后面 update note 的 inputs 和 output 时, 才可用
                //
                // =================================================== 
                // =================================================== 
                validatedProofs[validatedProofHash] = true;
            }
        }
        return proofOutputs;
    }

    /**
    * @dev Clear storage variables set when validating zero-knowledge proofs.
    *      The only address that can clear data from `validatedProofs` is the address that created the proof.
    *      Function is designed to utilize [EIP-1283](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1283.md)
    *      to reduce gas costs. It is highly likely that any storage variables set by `validateProof`
    *      are only required for the duration of a single transaction.
    *      E.g. a decentralized exchange validating a swap proof and sending transfer instructions to
    *      two confidential assets.
    *      This method allows the calling smart contract to recover most of the gas spent by setting `validatedProofs`
    * @param _proof the AZTEC proof object
    * @param _proofHashes dynamic array of proof hashes
    */
    /**
    验证零知识证明时清除设置的存储变量。
    *唯一可以从 “ validatedProofs” 中清除数据的地址是创建证明的地址。
    *该功能旨在利用[EIP-1283]（https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1283.md）来降低燃气成本。 由validateProof设置的任何存储变量很可能仅在单个事务期间才需要。
    *例如 验证交换证明并向两个机密资产发送转移指令的分散交易所。
    *此方法允许调用智能合约通过设置`validatedProofs`来收回大部分用气。
    */
    // _proof: aztec 的proof 对象
    // _proofHashes: 证明Hash的动态数组
    function clearProofByHashes(uint24 _proof, bytes32[] calldata _proofHashes) external {
        uint256 length = _proofHashes.length;
        for (uint256 i = 0; i < length; i += 1) {
            
            // proofHash 其实是 keccak256(_proofOutput) 生成
            // 循环 将存储在 validatedProofs 中的当前  msg.sender 和 proof 生成的 proofHash校验状态全部置为 false
            bytes32 proofHash = _proofHashes[i];
            require(proofHash != bytes32(0x0), "expected no empty proof hash");
            bytes32 validatedProofHash = keccak256(abi.encode(proofHash, _proof, msg.sender));
            // 清, 则是 全清
            require(validatedProofs[validatedProofHash] == true, "can only clear previously validated proofs");
            validatedProofs[validatedProofHash] = false;
        }
    }

    /**
    * @dev Set the common reference string.
    *      If the trusted setup is re-run, we will need to be able to change the crs
    * @param _commonReferenceString the new commonReferenceString
    */
    //
    // 设置公共参考字符串。 如果重新运行受信任的设置 (trusted setup)，我们将需要能够更改crs
    //
    // _commonReferenceString: 新的通用参考字符串
    function setCommonReferenceString(bytes32[6] memory _commonReferenceString) public {
        // 不是 ACE 合约的 owner 是不可以 设置 trusted setup 的
        require(isOwner(), "only the owner can set the common reference string");
        commonReferenceString = _commonReferenceString;
        emit SetCommonReferenceString(_commonReferenceString);
    }

    /**
    * @dev Forever invalidate the given proof.
    * @param _proof the AZTEC proof object
    */
    //
    // 将对应的 proof 的合约地址加入 黑名单
    //
    // _proof: AZTEC证明对象
    function invalidateProof(uint24 _proof) public {
        require(isOwner(), "only the owner can invalidate a proof");
        (uint8 epoch, uint8 category, uint8 id) = _proof.getProofComponents();
        // 先校验 三维数组 中根据 epoch, category, proofId 作为下标 获取对应的 proof合约地址 是否合法 
        require(validators[epoch][category][id] != address(0x0), "can only invalidate proofs that exist");
        // 将 proof合约地址置为黑名单
        disabledValidators[epoch][category][id] = true;
    }

    /**
    * @dev Validate a previously validated AZTEC proof via its hash
    *      This enables confidential assets to receive transfer instructions from a dApp that
    *      has already validated an AZTEC proof that satisfies a balancing relationship.
    * @param _proof the AZTEC proof object
    * @param _proofHash the hash of the `proofOutput` received by the asset
    * @param _sender the Ethereum address of the contract issuing the transfer instruction
    * @return a boolean that signifies whether the corresponding AZTEC proof has been validated
    */
    // TODO 重写了 NoteRegisterManager 的 validateProofByHash()
    //
    // 通过哈希验证先前验证过的AZTEC证明
    // 这使机密资产能够从dApp接收转移指令，该dApp已经验证了满足平衡关系的AZTEC证明。
    //
    // 入参:
    // _proof: AZTEC证明对象
    // _proofHash: 资产收到的“ proofOutput”的哈希
    // _sender: 发出转移指令的合约的以太坊地址
    // 
    // 返参:
    // 表示是否已验证相应的AZTEC证明的布尔值
    function validateProofByHash(
        uint24 _proof, // 证明
        bytes32 _proofHash, // 证明的Hash
        address _sender // 交易发起者? 
    ) public view returns (bool) {
        // We need create a unique encoding of _proof, _proofHash and _sender,
        // and use as a key to access validatedProofs
        // We do this by computing bytes32 validatedProofHash = keccak256(ABI.encode(_proof, _proofHash, _sender))
        // We also need to access disabledValidators[_proof.epoch][_proof.category][_proof.id]
        // This bit is implemented in Yul, as 3-dimensional array access chews through
        // a lot of gas in Solidity, as does ABI.encode
        //
        // ================================================================================================
        //
        // 我们需要创建 _proof，_proofHash和_sender的唯一编码，并用作访问validatedProofs的密钥
        // 我们通过计算 bytes32 validatedProofHash = keccak256(ABI.encode(_proof, _proofHash, _sender)) 来做到这一点
        // 我们还需要访问 disabledValidators[_proof.epoch][_ proof.category][_ proof.id] proof合约的黑名单
        
        
        bytes32 validatedProofHash; //  validatedProofHash = keccak256(ABI.encode(_proof, _proofHash, _sender))
        bool isValidatorDisabled; // proof对应的 验证器是否被禁用
        assembly {
            // inside _proof, we have 3 packed variables : [epoch, category, id]
            // each is a uint8.

            // We need to compute the storage key for `disabledValidators[epoch][category][id]`
            // Type of array is bool[0x100][0x100][0x100]
            // Solidity will only squish 32 boolean variables into a single storage slot, not 256
            // => result of disabledValidators[epoch][category] is stored in 0x08 storage slots
            // => result of disabledValidators[epoch] is stored in 0x08 * 0x100 = 0x800 storage slots

            // To compute the storage slot  disabledValidators[epoch][category][id], we do the following:
            // 1. get the disabledValidators slot
            // 2. add (epoch * 0x800) to the slot (or epoch << 11)
            // 3. add (category * 0x08) to the slot (or category << 3)
            // 4. add (id / 0x20) to the slot (or id >> 5)

            // Once the storage slot has been loaded, we need to isolate the byte that contains our boolean
            // This will be equal to id % 0x20, which is also id & 0x1f

            // Putting this all together. The storage slot offset from '_proof' is...
            // epoch: ((_proof & 0xff0000) >> 16) << 11 = ((_proof & 0xff0000) >> 5)
            // category: ((_proof & 0xff00) >> 8) << 3 = ((_proof & 0xff00) >> 5)
            // id: (_proof & 0xff) >> 5
            // i.e. the storage slot offset = _proof >> 5

            // the byte index of the storage word that we require, is equal to (_proof & 0x1f)
            // to convert to a bit index, we multiply by 8
            // i.e. bit index = shl(3, and(_proof & 0x1f))
            // => result = shr(shl(3, and(_proof & 0x1f), value))
            //
            //====================================================================================================
            //
            // 在 proof 中有三部分参数 : [epoch, category, id]
            // 它们每个占 uint8
            //
            // 我们需要计算`disabledValidators [epoch] [category] [id]` 黑名单中的存储密钥
            // 数组类型为bool [0x100] [0x100] [0x100]
            // Solidity只会将32个布尔变量压缩到单个存储插槽中，而不是256个
            // => disableValidators [epoch] [category]的结果存储在0x08存储槽中, 0x08 == 8
            // => disableValidators [epoch]的结果存储在0x08 * 0x100 = 0x800存储插槽中

            // 为了计算存储插槽 disabledValidators [epoch] [category] [id]，我们执行以下操作：
            // 1.获取disabledValidators插槽
            // 2.将 (epoch * 0x800) 添加到插槽 (或 epoch << 11)
            // 3.将 (category* 0x08) 添加到插槽 (或 category << 3)
            // 4.将 (proofId / 0x20) 添加到插槽 或 proof >> 5

            // 加载存储插槽后，我们需要隔离包含布尔值的字节
            // 这将等于 proofId % 0x20, 也就是  proofId ＆ 0x1f

            // 全部放在一起。 与'_proof'相对的存储插槽偏移量是...
            // epoch: ((_proof & 0xff0000) >> 16) << 11 = ((_proof & 0xff0000) >> 5)
            // category: ((_proof & 0xff00) >> 8) << 3 = ((_proof & 0xff00) >> 5)
            // proofId: (_proof & 0xff) >> 5
            // 即 存储插槽偏移量 = _proof >> 5  the storage slot offset

            
            //我们需要的存储字的字节索引等于（_proof＆0x1f）
            //要转换为位索引，我们要乘以8
            //即 bit index = shl(3, and(_proof & 0x1f))
            // => result = shr(shl(3, and(_proof & 0x1f), value)) 
            isValidatorDisabled :=
                shr(
                    shl(
                        0x03,
                        and(_proof, 0x1f)
                    ),

                    // disabledValidators_slot 和 bool[0x100][0x100][0x10000] public disabledValidators; 有关系??
                    //
                    sload(add(shr(5, _proof), disabledValidators_slot))
                )

            // Next, compute validatedProofHash = keccak256(abi.encode(_proofHash, _proof, _sender))
            // cache free memory pointer - we will overwrite it when computing hash (cheaper than using free memory)
            //
            // 然后, 计算 validatedProofHash = keccak256(abi.encode(_proofHash, _proof, _sender))
            // 缓存 可用memory的指针 - 我们将在计算 Hash 时将其覆盖 (比使用空闲内存更便宜)
            let memPtr := mload(0x40)
            mstore(0x00, _proofHash)
            mstore(0x20, _proof)
            mstore(0x40, _sender)
            validatedProofHash := keccak256(0x00, 0x60)
            // 恢复可用内存指针
            mstore(0x40, memPtr) // restore the free memory pointer
        }

        // 最后, 做一波 验证器是否被禁用的校验
        require(isValidatorDisabled == false, "proof id has been invalidated");
        return validatedProofs[validatedProofHash];
    }

    /**
    * @dev Adds or modifies a proof into the Cryptography Engine.
    *       This method links a given `_proof` to a smart contract validator.
    * @param _proof the AZTEC proof object
    * @param _validatorAddress the address of the smart contract validator
    */
    // 在加密引擎中添加或修改证明，此方法将给定的_proof与智能合约验证器链接
    //
    // _proof: AZTEC证明对象
    // _validatorAddress: 该 proof 对应的合约地址
    function setProof(
        uint24 _proof,
        address _validatorAddress
    ) public {
        // 只有 ACE 合约的持有者才可以做这个事
        require(isOwner(), "only the owner can set a proof");
        // 校验 proof 合约的地址是否合法
        require(_validatorAddress != address(0x0), "expected the validator address to exist");

        // 获取 proof 中的三个字段
        (uint8 epoch, uint8 category, uint8 id) = _proof.getProofComponents();
        
        // 校验 proof 中的 epoch
        require(epoch <= latestEpoch, "the proof epoch cannot be bigger than the latest epoch");

        // 根据 proof 的 epoch category proofId 作为索引，查找到对应的 proof合约地址
        // 则,已经表明 该 proof 已经被注册过了
        require(validators[epoch][category][id] == address(0x0), "existing proofs cannot be modified");
        
        // 注册 proof 
        // 使用 proof 的 epoch  category  proofId 作为索引，设置 proof合约地址
        validators[epoch][category][id] = _validatorAddress;

        // 写一个事件
        emit SetProof(epoch, category, id, _validatorAddress);
    }

    /**
     * @dev Increments the `latestEpoch` storage variable.
     */
    //
    // 增加`latestEpoch`存储变量 
    function incrementLatestEpoch() public {
        require(isOwner(), "only the owner can update the latest epoch");
        latestEpoch = latestEpoch.add(1);
        emit IncrementLatestEpoch(latestEpoch);
    }

    /**
    * @dev Returns the common reference string.
    * We use a custom getter for `commonReferenceString` - the default getter created by making the storage
    * variable public indexes individual elements of the array, and we want to return the whole array
    */
    // 我们为“ commonReferenceString”使用自定义getter-通过使 
    // 存储变量对数组的各个元素进行公共索引而创建的默认getter，我们希望返回整个数组
    function getCommonReferenceString() public view returns (bytes32[6] memory) {
        return commonReferenceString;
    }

    /**
    * @dev Get the address of the relevant validator contract
    *
    * @param _proof unique identifier of a particular proof
    * @return validatorAddress - the address of the validator contract
    */
    //
    // 获取相关验证器合约的地址
    //
    // 入参:
    // _proof: 特定证明的唯一标识符
    //
    // 返参:
    // validatorAddress: 验证器合约的地址
    //
    function getValidatorAddress(uint24 _proof) public view returns (address validatorAddress) {
        bool isValidatorDisabled; // 验证器是否已禁用标识
        bool queryInvalid; // 是否 无效的查询
        assembly {
            // To compute the storage key for validatorAddress[epoch][category][id], we do the following:
            // 1. get the validatorAddress slot
            // 2. add (epoch * 0x10000) to the slot
            // 3. add (category * 0x100) to the slot
            // 4. add (id) to the slot
            // i.e. the range of storage pointers allocated to validatorAddress ranges from
            // validatorAddress_slot to (0xffff * 0x10000 + 0xff * 0x100 + 0xff = validatorAddress_slot 0xffffffff)

            // Conveniently, the multiplications we have to perform on epoch, category and id correspond
            // to their byte positions in _proof.
            // i.e. (epoch * 0x10000) = and(_proof, 0xff0000)
            // and  (category * 0x100) = and(_proof, 0xff00)
            // and  (id) = and(_proof, 0xff)

            // Putting this all together. The storage slot offset from '_proof' is...
            // (_proof & 0xffff0000) + (_proof & 0xff00) + (_proof & 0xff)
            // i.e. the storage slot offset IS the value of _proof
            //
            // ===============================================================================================
            //
            // 要计算 validatorAddress [epoch] [category] [id]的存储密钥，请执行以下操作：
            //
            // 1.获取validatorAddress插槽 (validators_slot)
            // 2.将（epoch * 0x10000）添加到插槽
            // 3.将（category* 0x100）添加到插槽
            // 4.在插槽中添加（id）
            // 即分配给 ValidatorAddress 的存储指针范围是从 validatorAddress_slot到
            //（0xffff * 0x10000 + 0xff * 0x100 + 0xff = validatorAddress_slot 0xffffffff）
            //
            // 方便地，我们必须在epoch，category和proofId 上执行的【乘法】对应于它们在_proof中的字节位置
            // 即（epoch * 0x10000）= and（_proof，0xff0000）
            // and  (category * 0x100) = and(_proof, 0xff00)
            // and  (id) = and(_proof, 0xff)

            // 全部放在一起。 与'_proof'相对的存储插槽偏移量是...
            // epoch + category + proofId 
            // (_proof & 0xffff0000) + (_proof & 0xff00) + (_proof & 0xff)
            // 即存储插槽偏移量是_proof的值
            // 
            // 最终根据 add(_proof, validators_slot) 作为 statedb 的key, 查出 value: validatorAddress
            //
            // validators_slot 和 address[0x100][0x100][0x10000] public validators; 有关系 ??
            // 
            validatorAddress := sload(add(_proof, validators_slot))

            isValidatorDisabled :=
                // shift right 右移
                shr(
                    // shift left 左移
                    // and: & 运算
                    shl(0x03, and(_proof, 0x1f)),
                    // getState
                    // add: + 运算
                    sload(add(shr(5, _proof), disabledValidators_slot))
                )
            // or: | 运算
            // iszero: 判断是否为空, 0 非空, 1 为空    
            queryInvalid := or(iszero(validatorAddress), isValidatorDisabled)
        }

        // wrap both require checks in a single if test. This means the happy path only has 1 conditional jump
        // 
        // 只有 发现 出现查询不可用时， 即 queryInvalid == 1
        // 这时候需要检查 是 validatorAddress 为空
        // 还是 isValidatorDisabled 为 true (校验器被禁用) 
        if (queryInvalid) {
            // 
            require(validatorAddress != address(0x0), "expected the validator address to exist");
            require(isValidatorDisabled == false, "expected the validator address to not be disabled");
        }
    }
}

