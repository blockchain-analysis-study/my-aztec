pragma solidity >=0.5.0 <0.6.0;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";

import "../../libs/NoteUtils.sol";
import "../../interfaces/IACE.sol";
import "../../interfaces/IAZTEC.sol";
import "../../interfaces/IZkAsset.sol";
import "../../interfaces/IERC20Mintable.sol";
import "../../libs/LibEIP712.sol";
import "../../libs/MetaDataUtils.sol";
import "../../libs/ProofUtils.sol";
import "..\..\test\libs\NoteUtilsTest.sol";
import "..\..\ACE\ACE.sol";

/**
 * @title ZkAssetBase
 * @author AZTEC
 * @dev A contract defining the standard interface and behaviours of a confidential asset.
 * The ownership values and transfer values are encrypted.
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
// =================================================
// ==================== 超级重要 ====================
//
// TODO 这个是最重要的 合约之一
//
// TODO 资产操作接口， 包括自己从代币合约转入到AZTEC和AZTEC资产转回到代币合约
// TODO 与多种代币合约对接
// =================================================
// =================================================
contract ZkAssetBase is IZkAsset, IAZTEC, LibEIP712 {
    using NoteUtils for bytes;
    using SafeMath for uint256;
    using ProofUtils for uint24;

    // EIP712 Domain Name value
    // EIP712 标准的  域名
    string constant internal EIP712_DOMAIN_NAME = "ZK_ASSET";

    
    // hashStruct(s : 𝕊) = keccak256(typeHash ‖ encodeData(s)) ，
    // 其中 typeHash = keccak256(encodeType(typeOf(s)))
    // 
    // 对 ProofSignature 结构求 typeHash 
    // typeHash对于给定结构类型来说是一个常量，并不需要运行时再计算
    bytes32 constant internal PROOF_SIGNATURE_TYPE_HASH = keccak256(abi.encodePacked(
        "ProofSignature(",
            "bytes32 proofHash,",
            "address spender,",
            "bool approval",
        ")"
    ));

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
    string private constant EIP712_DOMAIN  = "EIP712Domain(string name,string version,address verifyingContract)";
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(abi.encodePacked(EIP712_DOMAIN));


    // hashStruct(s : 𝕊) = keccak256(typeHash ‖ encodeData(s)) ，
    // 其中 typeHash = keccak256(encodeType(typeOf(s)))
    // 
    // 对 NoteSignature 结构求 typeHash 
    // typeHash对于给定结构类型来说是一个常量，并不需要运行时再计算
    bytes32 constant internal NOTE_SIGNATURE_TYPEHASH = keccak256(abi.encodePacked(
        "NoteSignature(",
            "bytes32 noteHash,",
            "address spender,",
            "bool spenderApproval",
        ")"
    ));

    // 同上, 是 `JoinSplitSignature` 结构的 typeHash
    bytes32 constant internal JOIN_SPLIT_SIGNATURE_TYPE_HASH = keccak256(abi.encodePacked(
        "JoinSplitSignature(",
            "uint24 proof,",
            "bytes32 noteHash,",
            "uint256 challenge,",
            "address sender",
        ")"
    ));



    // 是一个对外的接口合约, 聚合了 ACE、NoteRegistryMnager、Behaviour201907 等等合约的某些对外方法
    // 所以, 它是一个 IACE的临时量 (根据上述几个合约地址动态的对应各个合约实例)
    IACE public ace;
    IERC20Mintable public linkedToken;


    // todo 存放 某些note可以花费的被授权addr
    //
    // (proofOutputHash => (被授权可以花费note的addr => 是否被授权, true: 是, false: 否))
    // 其中, proofOutputHash = keccak256(proofOutput)
    mapping(bytes32 => mapping(address => bool)) public confidentialApproved;

    // 记录 note 创建的 时间
    // (noteHash => createTime), 其中 createTime 是 取自当前 block的 timestamp
    mapping(bytes32 => uint256) public metaDataTimeLog;

    // 记录note被批准花费的addr的信息
    // (addressId => timestamp), todo 其中 addressID = keccak256(abi.encodePacked(extractedAddress, noteHash)), timestamp取 block.timestamp
    mapping(bytes32 => uint256) public noteAccess;

    // 记录所有的 签名, 做去重 防双花 防重放
    //
    // (signatureHash => bool), 其中 signatureHash = keccak256(_proofSignature)
    mapping(bytes32 => bool) public signatureLog;



    // 构造函数
    constructor(
        address _aceAddress, // 指定 ACE 合约地址
        address _linkedTokenAddress, // 指定ERC20 合约地址
        uint256 _scalingFactor, // token 和 加密币 的转换 比例
        bool _canAdjustSupply // 是否支持 mint 和 burn 等转换操作
    ) public {

        // 根据 ERC20 的地址是否为 空, 确定是否可以做 转换动作
        bool canConvert = (_linkedTokenAddress == address(0x0)) ? false : true;


        // 修改 LibEIP712 中的值
        EIP712_DOMAIN_HASH = keccak256(abi.encodePacked(
            EIP712_DOMAIN_SEPARATOR_SCHEMA_HASH,
            keccak256(bytes(EIP712_DOMAIN_NAME)),
            keccak256(bytes(EIP712_DOMAIN_VERSION)),
            bytes32(uint256(address(this)))
        ));

        // 在使用时, 传入具体的合约地址
        // 合约为:  ACE、NoteRegistryMnager、Behaviour201907 等等合约
        // TODO 注意, 一定要传对, 不然 某些合约可没有对应的方法
        ace = IACE(_aceAddress);

        // 实例化, 某个ERC20 合约实例
        linkedToken = IERC20Mintable(_linkedTokenAddress);

        // todo 实际上是调用了, (ACE => NoteRegistryManager的 createNoteRegistry() 函数)
        //
        // 每一个 ZKAssetBase 合约的创建, 都会往ACE 的 registries 中注册一个对应 NoteRegistry 信息
        ace.createNoteRegistry(
            _linkedTokenAddress,
            _scalingFactor,
            _canAdjustSupply,
            canConvert
        );

        // 发送 事件, 记录 ZKAsset 合约的实例化
        emit CreateZkAsset(
            _aceAddress,
            _linkedTokenAddress,
            _scalingFactor, // token 和 加密币 的转换 比例
            _canAdjustSupply,
            canConvert
        );
    }

    /**
    * @dev Executes a basic unilateral, confidential transfer of AZTEC notes
    * Will submit _proofData to the validateProof() function of the Cryptography Engine.
    *
    * Upon successfull verification, it will update note registry state - creating output notes and
    * destroying input notes.
    *
    * @param _proofId - id of proof to be validated. Needs to be a balanced proof.
    * @param _proofData - bytes variable outputted from a proof verification contract, representing
    * transfer instructions for the IACE
    * @param _signatures - array of the ECDSA signatures over all inputNotes
    */
    //
    // 执行AZTEC note 的基本单方面 confidential transfer 将_proofData提交给 Cryptography Engine 的 validateProof()函数
    // 验证成功后，它将更新note注册表状态-创建新的 output notes 并销毁旧的 input notes
    //
    // _proofId: 要验证的证明。 需要成为 balanced的证明
    // _proofData: 验证合同的输出字节变量，表示IACE的传输指令
    // _signatures: 所有 inputs 上的ECDSA签名数组
    //
    function confidentialTransfer(uint24 _proofId, bytes memory _proofData, bytes memory _signatures) public {
        // Check that it's a balanced proof
        //
        // 从 proof 中解析出 category
        (, uint8 category, ) = _proofId.getProofComponents();

        // 如果 proof 的category只能是 balaced 类型
        // todo 隐私币之间的 资产转移, 需要满足 BALANCED(平衡), 100 + 50 (input notes) == 90 + 20 + 40 (output notes)
        require(category == uint8(ProofCategory.BALANCED), "this is not a balanced proof");

        // todo 这个就是ACE 指派proof合约对 proofData进行校验证明且解析出 proofOutputs
        bytes memory proofOutputs = ace.validateProof(_proofId, msg.sender, _proofData); // todo msg.sender 在func中貌似没用到

        // 调用 隐私交易的 内部函数, 继续处理逻辑
        confidentialTransferInternal(_proofId, proofOutputs, _signatures, _proofData);
    }

    /**
    * @dev Executes a basic unilateral, confidential transfer of AZTEC notes
    * Will submit _proofData to the validateProof() function of the Cryptography Engine.
    *
    * Upon successfull verification, it will update note registry state - creating output notes and
    * destroying input notes.
    *
    * @param _proofData - bytes variable outputted from a proof verification contract, representing
    * transfer instructions for the IACE
    * @param _signatures - array of the ECDSA signatures over all inputNotes
    */
    // 执行AZTEC note 的基本单方面 confidential transfer 将_proofData提交给 Cryptography Engine 的 validateProof()函数
    // 验证成功后，它将更新note注册表状态-创建新的 output notes 并销毁旧的 input notes
    //
    // _proofData: 验证合同的输出字节变量，表示IACE的传输指令
    // _signatures: 所有 inputs 上的ECDSA签名数组
    //
    // TODO 对外的方法
    function confidentialTransfer(bytes memory _proofData, bytes memory _signatures) public {
        // 传递一个 proof 类型
        confidentialTransfer(JOIN_SPLIT_PROOF, _proofData, _signatures);
    }

    /**
    * @dev Note owner approving a third party, another address, to spend the note on
    * owner's behalf. This is necessary to allow the confidentialTransferFrom() method
    * to be called
    *
    * @param _noteHash - keccak256 hash of the note coordinates (gamma and sigma)
    * @param _spender - address being approved to spend the note
    * @param _spenderApproval - defines whether the _spender address is being approved to spend the
    * note, or if permission is being revoked. True if approved, false if not approved
    * @param _signature - ECDSA signature from the note owner that validates the
    * confidentialApprove() instruction
    */

    // todo 授权 第三方addr 代理花费当前 note  ##################### 单个授权
    //
    //  note 所有者批准第三方（另一个地址）代表所有者花费当前note。
    //  这是必要的，以便允许调用 confidentialApprove()方法
    //
    // _noteHash: 需要被授权的 note的Hash
    // _spender: 需要被授权的 账户
    // _spenderApproval: 是否授权的标识
    // _signature: todo 这里的签名 必须是 note的owner的签名
    function confidentialApprove(
        bytes32 _noteHash,
        address _spender,
        bool _spenderApproval,
        bytes memory _signature
    ) public {

        // 先查询 当前note 的状态
        ( uint8 status, , , ) = ace.getNote(address(this), _noteHash);
        require(status == 1, "only unspent notes can be approved");


        // 计算 签名Hash
        bytes32 signatureHash = keccak256(abi.encodePacked(_signature));
        // 校验 是否重放
        require(signatureLog[signatureHash] != true, "signature has already been used");

        // Only need to prevent replay from calls where msg.sender isn't owner of note.
        //
        // 只需要防止msg.sender不是note所有者的调用重放。
        if (_signature.length != 0) {
            signatureLog[signatureHash] = true;
        }



        // hashStruct(s : 𝕊) = keccak256(typeHash ‖ encodeData(s)) ，
        // 其中 typeHash = keccak256(encodeType(typeOf(s)))

        bytes32 _hashStruct = keccak256(abi.encode(
                NOTE_SIGNATURE_TYPEHASH,
                _noteHash,
                _spender,
                _spenderApproval
        ));

        // todo 校验签名中的 signer 要么是 该note的owner, 或者是 当前 msg.sender是 该note的owner
        // todo 只有这两种情况才可以动用 note
        validateSignature(_hashStruct, _noteHash, _signature);
        // todo 开始 做对当前 note的第三方addr花费授权
        confidentialApproved[_noteHash][_spender] = _spenderApproval;
    }

    /**
     * @dev Note owner can approve a third party address, such as a smart contract,
     * to spend a proof on their behalf. This allows a batch approval of notes
     * to be performed, rather than individually for each note via confidentialApprove().
     *
     * @param _proofId - id of proof to be approved. Needs to be a balanced proof.
     * @param _proofOutputs - data of proof
     * @param _spender - address being approved to spend the notes
     * @param _proofSignature - ECDSA signature over the proof, approving it to be spent
     */

    // TODO 批准 第三者对 notes 进行花费的证明   ##################### 批量授权
    //
    // note 所有者 可以批准第三方地址（例如智能合约）来代表他们花费 note。
    // 这允许对 notes 执行批处理批准，而不是通过 confidentialApprove() 对每个 note 进行单独批准。
    //
    // _proofId: 待批准的证明编号。 需要成为平衡的证明
    // _proofOutputs: 证明数据
    // _spender: 被批准可以花费note的地址
    // _proofSignature: 在proof上的ECDSA签名，批准将其花费
    //
    function approveProof(
        uint24 _proofId,
        bytes calldata _proofOutputs,
        address _spender,
        bool _approval,
        bytes calldata _proofSignature
    ) external {

        // Prevent possible replay attacks
        //
        // 防止可能的重放攻击
        bytes32 signatureHash = keccak256(_proofSignature);
        require(signatureLog[signatureHash] != true, "signature has already been used");
        signatureLog[signatureHash] = true;


        // 其实这个就是 定义域分隔符的哈希值 domainSeparator
        // 下面的 hashBid 会用到
        bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256("ZK_ASSET"),
            keccak256("1"),
            address(this)
        ));

        // ================================================================================
        // =================================== 超级 重要 ===================================
        //
        // 其实这个就是 EIP712 标准中的 hashBid
        //
        // encode(domainSeparator : 𝔹²⁵⁶, message : 𝕊) = "\x19\x01" ‖ domainSeparator ‖ hashStruct(message)，
        // ================================================================================
        // ================================================================================
        bytes32 msgHash = keccak256(abi.encodePacked(
            "\x19\x01",

            // domainSeparator
            DOMAIN_SEPARATOR,

            // proof 的 hashStruct
            keccak256(abi.encode(
                PROOF_SIGNATURE_TYPE_HASH,
                keccak256(_proofOutputs),
                _spender,
                _approval
            ))
        ));

        // 通过 hashBid 和 Signature 解析出 签名者
        address signer = recoverSignature(
            msgHash,
            _proofSignature
        );


        // 遍历 proofOutputs
        for (uint i = 0; i < _proofOutputs.getLength(); i += 1) {

            // 逐个 拿出 proofOutput 中的  input notes
            bytes memory proofOutput = _proofOutputs.get(i);
            //
            // todo 为什么这里只拿 input notes ?
            // todo 因为, 交易中的(proofOutput中的) input notes 就是之前某些 未花费输出 output notes ？？ 是这么解释么 ？？
            (bytes memory inputNotes,,,) = proofOutput.extractProofOutput();

            // 逐个遍历 input notes
            for (uint256 j = 0; j < inputNotes.getLength(); j += 1) {

                // owner, noteHash, metadata
                (, bytes32 noteHash, ) = inputNotes.get(j).extractNote();

                // 根据 noteHash 去获取对应的 note (先是 ACE => NoteRegistryManager => behaviour201907 中获取 note信息)
                //
                // status, createOn, destroyedOn, owner
                ( uint8 status, , , address noteOwner ) = ace.getNote(address(this), noteHash);

                // 只有 未花费的 note 才可以被 授权批准
                require(status == 1, "only unspent notes can be approved");

                // 只有 proof中的 signer 是 note的owner时，该 note才可以被批准
                require(noteOwner == signer, "the note owner did not sign this proof");
            }


            // todo 对单个 note 给予 spender 可以花费的证明 (还是需要看, _approval 的值是 true 还是 false)
            confidentialApproved[keccak256(proofOutput)][_spender] = _approval;
        }
    }

    /**
    * @dev Perform ECDSA signature validation for a signature over an input note
    *
    * @param _hashStruct - the data to sign in an EIP712 signature
    * @param _noteHash - keccak256 hash of the note coordinates (gamma and sigma)
    * @param _signature - ECDSA signature for a particular input note
    */
    // 对 input note 上的签名执行ECDSA签名验证 todo (使用 EIP712 签名规范)
    //
    function validateSignature(
        bytes32 _hashStruct,
        bytes32 _noteHash,
        bytes memory _signature
    ) internal view {

        // 根据 noteHash 取出 note owner
        (, , , address noteOwner ) = ace.getNote(address(this), _noteHash);

        address signer;

        // 如果有 签名, 则校验签名者是否 是note的 owner
        if (_signature.length != 0) {
            // validate EIP712 signature
            bytes32 msgHash = hashEIP712Message(_hashStruct);
            signer = recoverSignature(
                msgHash,
                _signature
            );
        } else { // 否则, 没有签名的话, 则校验当前 交易发送者是否 是 note 的 owner
            signer = msg.sender;
        }

        // 校验 是否是 该note 的owner
        // todo 校验不通过, 则 交易state会被回滚
        require(signer == noteOwner, "the note owner did not sign this message");
    }

    /**
    * @dev Extract the appropriate ECDSA signature from an array of signatures,
    *
    * @param _signatures - array of ECDSA signatures over all inputNotes
    * @param _i - index used to determine which signature element is desired
    */

    // 从签名数组中提取适当的ECDSA签名
    //
    // _signatures: 所有的 input notes 的ECDSA签名数组
    // i: 用于提取所需签名元素的索引
    function extractSignature(bytes memory _signatures, uint _i) internal pure returns (
        bytes memory _signature
    ){

        // 签名中的, R, S, V
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // memory map of signatures
            // 0x00 - 0x20 : length of signature array
            // 0x20 - 0x40 : first sig, r
            // 0x40 - 0x60 : first sig, s
            // 0x61 - 0x62 : first sig, v
            // 0x62 - 0x82 : second sig, r
            // and so on...
            // Length of a signature = 0x41

            // 在memory中签名数据的布局
            // 0x00 - 0x20 : 签名数组的长度
            // 0x20 - 0x40 : 第一个签名的R
            // 0x40 - 0x60 : 第一个签名的S
            // 0x61 - 0x62 : 第一个签名的V
            // 0x62 - 0x82 : 第二个签名的R
            // 以此类推 ...
            // 每个签名长度= 0x41 (65byte)

            let sigLength := 0x41

            // 按照索引偏移量, 对应索引的签名的提取 R, S, V
            r := mload(add(add(_signatures, 0x20), mul(_i, sigLength)))
            s := mload(add(add(_signatures, 0x40), mul(_i, sigLength)))
            v := mload(add(add(_signatures, 0x41), mul(_i, sigLength)))
        }

        // 根据 R, S, V 重装出 签名
        _signature = abi.encodePacked(r, s, v);
    }

    /**
    * @dev Executes a value transfer mediated by smart contracts. The method is supplied with
    * transfer instructions represented by a bytes _proofOutput argument that was outputted
    * from a proof verification contract.
    *
    * @param _proof - uint24 variable which acts as a unique identifier for the proof which
    * _proofOutput is being submitted. _proof contains three concatenated uint8 variables:
    * 1) epoch number 2) category number 3) ID number for the proof
    * @param _proofOutput - output of a zero-knowledge proof validation contract. Represents
    * transfer instructions for the IACE
    */
    function confidentialTransferFrom(uint24 _proof, bytes memory _proofOutput) public {
        (bytes memory inputNotes,
        bytes memory outputNotes,
        address publicOwner,
        int256 publicValue) = _proofOutput.extractProofOutput();

        bytes32 proofHash = keccak256(_proofOutput);

        if (confidentialApproved[proofHash][msg.sender] != true) {
            uint256 length = inputNotes.getLength();
            for (uint i = 0; i < length; i += 1) {
                (, bytes32 noteHash, ) = inputNotes.get(i).extractNote();
                require(
                    confidentialApproved[noteHash][msg.sender] == true,
                    "sender does not have approval to spend input note"
                );
            }
        }

        ace.updateNoteRegistry(_proof, _proofOutput, msg.sender);

        logInputNotes(inputNotes);
        logOutputNotes(outputNotes);

        if (publicValue < 0) {
            emit ConvertTokens(publicOwner, uint256(-publicValue));
        }
        if (publicValue > 0) {
            emit RedeemTokens(publicOwner, uint256(publicValue));
        }
    }

    /**
    * @dev Internal method to act on transfer instructions from a successful proof validation.
    * Specifically, it:
    * - extracts the relevant objects from the proofOutput object
    * - validates an EIP712 signature over each input note
    * - updates note registry state
    * - emits events for note creation/destruction
    * - converts or redeems tokens, according to the publicValue
    * @param _proofId - id of proof resulting in _proofData
    * @param proofOutputs - transfer instructions from a zero-knowledege proof validator
    * contract
    * @param _signatures - ECDSA signatures over a set of input notes
    * @param _proofData - cryptographic proof data outputted from a proof construction
    * operation
    */

    // todo 从成功的证明验证开始对 transfer 执行操作的内部方法。
    // 具体来说，它：
    // -从证明输出对象(proofOutput object)中提取相关对象
    // -验证每个 input note 上的EIP712签名
    // -更新 note 注册表状态
    // -发出 创建/销毁 note 的 event
    // -根据 publicValue 转换或兑换 token
    //
    // _proofId: 产生_proofData的 proof三元组信息 (很多时候直接称之为 proofId, 原因是, 该三元组可以直接标识某个 proof合约)
    // proofOutputs: 从零知识proof验证合约中 解析proofData得出来的 proofOutputs
    // _signatures: 一组 input notes 上的 ECDSA 签名
    // _proofData: 从证明构造操作(这部分是链下做的, js的库)输出的 加密 proof数据

    function confidentialTransferInternal(
        uint24 _proofId,          //
        bytes memory proofOutputs,// 多个 proofOutput集
        bytes memory _signatures, // 多个签名的集 (对应 input notes的数目, 每一个 proofOutput 中都有一组 input notes)
        bytes memory _proofData   //
    ) internal {

        // 取出 _challenge, todo 这里面到底放的是什么啊? 语义为挑战,提议, 难道是 salt ?
        bytes32 _challenge;
        assembly {
            _challenge := mload(add(_proofData, 0x40))
        }

        // 遍历 proofOutputs
        for (uint i = 0; i < proofOutputs.getLength(); i += 1) {

            // 逐个处理 每一个 proofOutput 中的 一组 input notes 和 output notes
            bytes memory proofOutput = proofOutputs.get(i);
            // todo 更新 note 注册表信息
            // todo 主要是更新 input notes 和 output notes
            ace.updateNoteRegistry(_proofId, proofOutput, address(this));


            // 解出当前 proofOutput 中的 input notes, output notes, publicOwner, publicValue
            (bytes memory inputNotes,
            bytes memory outputNotes,
            address publicOwner,
            int256 publicValue) = proofOutput.extractProofOutput();

            // 如果有 input notes 则, 遍历 input notes
            if (inputNotes.getLength() > uint(0)) {
                for (uint j = 0; j < inputNotes.getLength(); j += 1) {

                    // 根据 input notes 的索引, 取出对应的  input notes 的签名
                    //
                    // todo  疑问, 我们有多个 proofOutput, 每个 proofOutput 中又有多个input notes
                    // todo  那么, 这样纸取 索引的话, 说明,每个 proofOutput 中的 input notes 个数必须是一样的 ...
                    bytes memory _signature = extractSignature(_signatures, j);

                    // 组个 获取 input note Hash
                    (, bytes32 noteHash, ) = inputNotes.get(j).extractNote();

                    // 计算 hashStruct
                    bytes32 hashStruct = keccak256(abi.encode(
                        JOIN_SPLIT_SIGNATURE_TYPE_HASH,
                        _proofId,
                        noteHash,
                        _challenge,
                        msg.sender
                    ));

                    // 主要校验 input note 的签名者或者本次交易的msg.sender是否为 该 input note的 owner
                    validateSignature(hashStruct, noteHash, _signature);
                }
            }


            // 该笔 proofOutput 的所有 input notes 校验过了, todo 则就是真正花费 input notes 生成 output notes

            // 将这些事情记录到 event 中
            logInputNotes(inputNotes);    // 这个就只是简单的记录销毁 event
            logOutputNotes(outputNotes);  // 这个记录创建event, 还有提取和记录当前note的所有被批准花费的地址 approvedAddress

            // 下面这个只有 mint 和 burn 的时候才会有
            if (publicValue < 0) {

                // 转换token event, 发生 mint的时候
                emit ConvertTokens(publicOwner, uint256(-publicValue));
            }
            if (publicValue > 0) {

                // 赎回token event, 发生 burn的时候
                emit RedeemTokens(publicOwner, uint256(publicValue));
            }

        }
    }

    /**
    * @dev Update the metadata of a note that already exists in storage.
    * @param noteHash - hash of a note, used as a unique identifier for the note
    * @param metaData - metadata to update the note with
    */
    function updateNoteMetaData(bytes32 noteHash, bytes memory metaData) public {
        // Get the note from this assets registry
        ( uint8 status, , , address noteOwner ) = ace.getNote(address(this), noteHash);

        bytes32 addressID = keccak256(abi.encodePacked(msg.sender, noteHash));
        require(
            (noteAccess[addressID] >= metaDataTimeLog[noteHash] || noteOwner == msg.sender) && status == 1,
            'caller does not have permission to update metaData'
        );

        // Approve the addresses in the note metaData
        approveAddresses(metaData, noteHash);

        // Set the metaDataTimeLog to the latest block time
        setMetaDataTimeLog(noteHash);

        emit UpdateNoteMetaData(noteOwner, noteHash, metaData);
    }

    /**
    * @dev Set the metaDataTimeLog mapping
    * @param noteHash - hash of a note, used as a unique identifier for the note
    */
    //
    // 记录当前 note 的createTime
    function setMetaDataTimeLog(bytes32 noteHash) internal {
        metaDataTimeLog[noteHash] = block.timestamp;
    }

    /**
    * @dev Add approved addresses to a noteAccess mapping and to the global collection of addresses that
    * have been approved
    * @param metaData - metaData of a note, which contains addresses to be approved
    * @param noteHash - hash of an AZTEC note, a unique identifier of the note
    */
    // todo 将批准的地址添加到 noteAccess map和 已批准的地址的全局集合中
    //
    // metaData: note 的metaData，其中包含要批准的地址
    // noteHash: AZTEC note的Hash，note的唯一标识符
    function approveAddresses(bytes memory metaData, bytes32 noteHash) internal {
        /**
        * Memory map of metaData
        * 0x00 - 0x20 : length of metaData
        * 0x20 - 0x81 : ephemeral key
        * 0x81 - 0xa1 : approved addresses offset
        * 0xa1 - 0xc1 : encrypted view keys offset
        * 0xc1 - 0xe1 : app data offset
        * 0xe1 - L_addresses : approvedAddresses
        * (0xe1 + L_addresses) - (0xe1 + L_addresses + L_encryptedViewKeys) : encrypted view keys
        * (0xe1 + L_addresses + L_encryptedViewKeys) - (0xe1 + L_addresses + L_encryptedViewKeys + L_appData) : appData
        */

        // 在memory中的 metadata 的数据布局
        // 0x00 - 0x20 :  metaData 的总长度 (多少字节)                ------32byte
        // 0x20 - 0x81 :  ephemeral key (临时秘钥) todo 干嘛的???     ------32byte
        // 0x81 - 0xa1 :  被批准的 addr 集的起始位置                  ------32byte
        // 0xa1 - 0xc1 :  encrypted view key 集的起始位置 (用来查看 note 中的 金额的 view key, 但是不能花费其中的金额)
        // 0xc1 - 0xe1 :  app data 的起始位置, todo app的数据 ?
        // 0xe1 - L_addresses : 被批准的 addr 集 数据
        // (0xe1 + L_addresses) - (0xe1 + L_addresses + L_encryptedViewKeys) : encrypted view key 集 数据
        // (0xe1 + L_addresses + L_encryptedViewKeys) - (0xe1 + L_addresses + L_encryptedViewKeys + L_appData) : appData

        // TODO 注意: L_addresses, 表示 addrCount, addr1, addr2, ..., addrN
        // TODO 参考 MetaDataUtils.extractAddress() 中的注释就明白了


        bytes32 metaDataLength;
        bytes32 numAddresses;
        assembly {

            // 获得整个 metaData的长度
            metaDataLength := mload(metaData)

            // 获得 0xe1 起始处存储的第一个 32byte, 其内容不是 Addr而是 addr的数目
            numAddresses := mload(add(metaData, 0xe1))
        }

        // if customData has been set, approve the relevant addresses
        //
        // 如果已设置customData，请批准相关地址
        //
        // todo uint256(metaDataLength) > 0x61 这是一个很粗的 判断
        if (uint256(metaDataLength) > 0x61) { // 0x61 == 97, 说明 metaData 的长度已经超过 97 byte 说明, todo 入参的 metaData 中肯定是指定了 被批准addr的


            // 根据 approved addr 的数目进行 for, 逐个提取出在 当前 note metadata中的 被批准地址 approvedAddr
            for (uint256 i = 0; i < uint256(numAddresses); i += 1) {

                // 根据 索引取出 metadata中的 approvedAddr
                address extractedAddress = MetaDataUtils.extractAddress(metaData, i);

                // 计算 addrId
                bytes32 addressID = keccak256(abi.encodePacked(extractedAddress, noteHash));

                // 记录 note 和 被批准地址, 及当前block时间
                noteAccess[addressID] = block.timestamp;
            }
        }
    }


    /**
    * @dev Emit events for all input notes, which represent notes being destroyed
    * and removed from the note registry
    *
    * @param inputNotes - input notes being destroyed and removed from note registry state
    */
    // todo 发出所有 input notes 的event，这些event表示 note 被销毁并从 note注册表中删除
    //
    // inputNotes: input notes 被销毁并从 note注册表 state中删除
    function logInputNotes(bytes memory inputNotes) internal {

        // 逐个遍历 input notes
        for (uint i = 0; i < inputNotes.getLength(); i += 1) {

            // 提取出 owner 和 Hash
            (address noteOwner, bytes32 noteHash, ) = inputNotes.get(i).extractNote();

            // 记录 event
            emit DestroyNote(noteOwner, noteHash);
        }
    }

    /**
    * @dev Emit events for all output notes, which represent notes being created and added
    * to the note registry
    *
    * @param outputNotes - outputNotes being created and added to note registry state
    */
    // todo 为所有 output notes 发出 event，这些event表示正在创建并添加到 note注册表的 note
    //
    // outputNotes: 正在创建 outputNotes 并将其添加到note注册表状态
    function logOutputNotes(bytes memory outputNotes) internal {

        // 逐个遍历 output notes
        for (uint i = 0; i < outputNotes.getLength(); i += 1) {

            // 提取 output note 的 owner, hash, metadata
            (address noteOwner, bytes32 noteHash, bytes memory metaData) = outputNotes.get(i).extractNote();

            // 记录 note 创建时的时间戳, 取 block.timestamp
            setMetaDataTimeLog(noteHash);

            // 提取和记录当前note的所有被批准花费的地址 approvedAddress
            approveAddresses(metaData, noteHash);

            // 记录创建 note 的event
            emit CreateNote(noteOwner, noteHash, metaData);
        }
    }
}
