pragma solidity >=0.5.0 <0.6.0;

/**
 * @title IACE
 * @author AZTEC
 * @dev Standard defining the interface for ACE.sol
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
// 这个是 最主要的 组件接口
// ACE: AZTEC Cryptography Engine
contract IACE {

    uint8 public latestEpoch;

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
    ) external returns (bytes memory);


        /**
    * @dev Default noteRegistry creation method. Doesn't take the id of the factory to use,
            but generates it based on defaults and on the passed flags.
    *
    * @param _linkedTokenAddress - address of any erc20 linked token (can not be 0x0 if canConvert is true)
    * @param _scalingFactor - defines the number of tokens that an AZTEC note value of 1 maps to.
    * @param _canAdjustSupply - whether the noteRegistry can make use of minting and burning
    * @param _canConvert - whether the noteRegistry can transfer value from private to public
        representation and vice versa
    */
    // TODO NoteRegisterManager 实现
    // 
    // 默认的noteRegistry创建方法。 不采用要使用的工厂ID，而是根据默认值和传递的标志生成该ID
    //
    // _linkedTokenAddress: 任何erc20链接令牌的地址 (如果canConvert为true，则不能为0x0)
    // _scalingFactor: 定义AZTEC注释值1映射到的令牌数量.
    // _canAdjustSupply: noteRegistry是否可以使用【mint】和 【burn】
    // _canConvert: noteRegistry是否可以将 【价值从私人代表转移到公共代表，反之亦然】
    function createNoteRegistry(
        address _linkedTokenAddress,
        uint256 _scalingFactor,
        bool _canAdjustSupply,
        bool _canConvert
    ) external;
m 
    /**
    * @dev NoteRegistry creation method. Takes an id of the factory to use.
    *
    * @param _linkedTokenAddress - address of any erc20 linked token (can not be 0x0 if canConvert is true)
    * @param _scalingFactor - defines the number of tokens that an AZTEC note value of 1 maps to.
    * @param _canAdjustSupply - whether the noteRegistry can make use of minting and burning
    * @param _canConvert - whether the noteRegistry can transfer value from private to public
        representation and vice versa
    * @param _factoryId - uint24 which contains 3 uint8s representing (epoch, cryptoSystem, assetType)
    */
    //
    // NoteRegistry创建方法。 取得要使用的工厂的ID
    //
    // _linkedTokenAddress: 任何erc20链接令牌的地址 (如果canConvert为true，则不能为0x0)
    // _scalingFactor: 定义AZTEC注释值1映射到的令牌数量.
    // _canAdjustSupply: noteRegistry是否可以使用【mint】和 【burn】
    // _canConvert: noteRegistry是否可以将 【价值从私人代表转移到公共代表，反之亦然】
    // _factoryId: uint24，其中包含3个uint8，分别表示 (epoch，cryptoSystem，assetType)
    function createNoteRegistry(
        address _linkedTokenAddress,
        uint256 _scalingFactor,
        bool _canAdjustSupply,
        bool _canConvert,
        uint24 _factoryId
    ) external;

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
     *唯一可以从“ validatedProofs”中清除数据的地址是创建证明的地址。
     *该功能旨在利用[EIP-1283]（https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1283.md）来降低燃气成本。 由validateProof设置的任何存储变量很可能仅在单个事务期间才需要。
     *例如 验证交换证明并向两个机密资产发送转移指令的分散交易所。
     *此方法允许调用智能合约通过设置`validatedProofs`来收回大部分用气。
     */
     // _proof: aztec 的proof 对象
     // _proofHashes: 证明Hash的动态数组
    function clearProofByHashes(uint24 _proof, bytes32[] calldata _proofHashes) external;

    /**
    * @dev Returns the common reference string.
    * We use a custom getter for `commonReferenceString` - the default getter created by making the storage
    * variable public indexes individual elements of the array, and we want to return the whole array
    */
    // 我们为“ commonReferenceString”使用自定义getter-通过使 
    // 存储变量对数组的各个元素进行公共索引而创建的默认getter，我们希望返回整个数组
    function getCommonReferenceString() external view returns (bytes32[6] memory);


    /**
    * @dev Get the factory address associated with a particular factoryId. Fail if resulting address is 0x0.
    *
    * @param _factoryId - uint24 which contains 3 uint8s representing (epoch, cryptoSystem, assetType)
    */
    // 获取与特定factoryId关联的工厂地址。 (工厂合约对应的Address) 如果结果地址为0x0，则失败。
    // _factoryId: uint24，其中包含3个uint8，分别表示（epoch，cryptoSystem，assetType）
    function getFactoryAddress(uint24 _factoryId) external view returns (address factoryAddress);

    /**
     * @dev Returns the registry for a given address.
     *
     * @param _registryOwner - address of the registry owner in question
     *
     * @return linkedTokenAddress - public ERC20 token that is linked to the NoteRegistry. This is used to
     * transfer public value into and out of the system
     * @return scalingFactor - defines how many ERC20 tokens are represented by one AZTEC note
     * @return totalSupply - represents the total current supply of public tokens associated with a particular registry
     * @return confidentialTotalMinted - keccak256 hash of the note representing the total minted supply
     * @return confidentialTotalBurned - keccak256 hash of the note representing the total burned supply
     * @return canConvert - flag set by the owner to decide whether the registry has public to private, and
     * vice versa, conversion privilege
     * @return canAdjustSupply - determines whether the registry has minting and burning privileges
     */
     // 返回给定地址的注册表
     //
     // 入参：
     // _registryOwner: 有关注册表所有者的地址
     //
     // 返参: 
     // linkedToken: 链接到NoteRegistry的公共ERC20合约。 这用于将公共价值传入和传出系统
     // scalingFactor: 定义 一个 AZTEC note 值 兑换多少令牌数量 的比例 
     // confidentialTotalMinted: AZTEC票据的哈希值代表 mint 的总量
     // confidentialTotalBurned: AZTEC票据的哈希值代表 burn 的总量 
     // totalSupply: 代表与特定注册表关联的公共令牌的当前总供应量
     // totalSupplemented: total补充
     // canConvert: 布尔值定义了 noteRegistry 是否可以在 public 和 private 之间转换
     // canAdjustSupply: 布尔值定义了 noteRegistry 是否可以使用 mint 和 burn 方法
    function getRegistry(address _registryOwner) external view returns (
        address linkedToken,
        uint256 scalingFactor,
        bytes32 confidentialTotalMinted,
        bytes32 confidentialTotalBurned,
        uint256 totalSupply,
        uint256 totalSupplemented,
        bool canConvert,
        bool canAdjustSupply
    );

    /**
     * @dev Returns the note for a given address and note hash.
     *
     * @param _registryOwner - address of the registry owner
     * @param _noteHash - keccak256 hash of the note coordiantes (gamma and sigma)
     *
     * @return status - status of the note, details whether the note is in a note registry
     * or has been destroyed
     * @return createdOn - time the note was created
     * @return destroyedOn - time the note was destroyed
     * @return noteOwner - address of the note owner
     */
     //
     // 返回给定地址的注释和注释哈希
     // 
     // 入参:
     // _registryOwner: 注册表所有者的地址
     // _noteHash: keccak256注释坐标的哈希值（ gamma 和 sigma）
     //
     // 返参: 
     // status: note的状态，详细说明note是否在note注册表中或已被销毁
     // createdOn: note创建的时间
     // destroyedOn: note销毁的事件
     // noteOwner: note所有者的地址
     // 
    function getNote(address _registryOwner, bytes32 _noteHash) external view returns (
        uint8 status,
        uint40 createdOn,
        uint40 destroyedOn,
        address noteOwner
    );

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
    function getValidatorAddress(uint24 _proof) external view returns (address validatorAddress);

    /**
    * @dev Increment the default registry epoch
    */
    //
    // 增加默认注册表epoch
    function incrementDefaultRegistryEpoch() external;

    /**
     * @dev Increments the `latestEpoch` storage variable.
     */
    //
    // 增加`latestEpoch`存储变量
    function incrementLatestEpoch() external;

    /**
    * @dev Forever invalidate the given proof.
    * @param _proof the AZTEC proof object
    */
    //
    // 永远使给定的证据无效
    //
    // _proof: AZTEC证明对象
    function invalidateProof(uint24 _proof) external;

    // 这个是？    
    function isOwner() external view returns (bool);

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
        uint24 _proof,
        bytes calldata _proofData,
        address _proofSender
    ) external returns (bytes memory);
    

    // 这个是 ?
    function owner() external returns (address);

    /**
    * @dev Adds a public approval record to the noteRegistry, for use by ACE when it needs to transfer
        public tokens it holds to an external address. It needs to be associated with the hash of a proof.
    */
    // 将【公共批准记录】添加到noteRegistry中，以供ACE在需要将其持有的公共令牌转移到外部地址时使用。 它需要与证明的哈希关联
    function publicApprove(address _registryOwner, bytes32 _proofHash, uint256 _value) external;


    // 放弃所有权
    function renounceOwnership() external;

    /**
    * @dev Set the common reference string.
    *      If the trusted setup is re-run, we will need to be able to change the crs
    * @param _commonReferenceString the new commonReferenceString
    */
    //
    // 设置公共参考字符串。 如果重新运行受信任的设置 (trusted setup)，我们将需要能够更改crs
    //
    // _commonReferenceString: 新的通用参考字符串
    function setCommonReferenceString(bytes32[6] calldata _commonReferenceString) external;

    /**
    * @dev Set the default crypto system to be used
    * @param _defaultCryptoSystem - default crypto system identifier
    */
    // 设置要使用的默认密码系统
    // _defaultCryptoSystem: 默认密码系统标识符
    function setDefaultCryptoSystem(uint8 _defaultCryptoSystem) external;

    /**
    * @dev Register a new Factory, iff no factory for that ID exists.
            The epoch of any new factory must be at least as big as
            the default registry epoch. Each asset type for each cryptosystem for
            each epoch should have a note registry
    *
    * @param _factoryId - uint24 which contains 3 uint8s representing (epoch, cryptoSystem, assetType)
    * @param _factoryAddress - address of the deployed factory
    */
    //
    // 如果不存在该ID的工厂，请注册一个新工厂.
    // 任何新工厂的epoch必须至少与默认注册表epoch一样大.
    // 每个时期每个密码系统的每种资产类型应具有一个注释注册表.
    function setFactory(uint24 _factoryId, address _factoryAddress) external;

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
    ) external;

    /**
    * @dev called when a mintable and convertible asset wants to perform an
            action which puts the zero-knowledge and public
            balance out of balance. For example, if minting in zero-knowledge, some
            public tokens need to be added to the pool
            managed by ACE, otherwise any private->public conversion runs the risk of not
            having any public tokens to send.
    *
    * @param _value the value to be added
    */
    //
    // 当可铸造和可转换资产要执行一项使零知识和公共平衡失衡的动作时调用。 
    // 例如，如果铸造零知识，则需要将某些公共令牌添加到ACE管理的池中，
    // 否则任何私有->公共转换都将面临没有任何公共令牌要发送的风险.
    //
    // _value: 要增加的价值
    function supplementTokens(uint256 _value) external;

    // 这个是 ?
    function transferOwnership(address newOwner) external;


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
    //
    // 返参:
    // 按照加密引擎标准格式化的“ bytesproofOutputs”变量
    // 
    // todo: 说白了，这个就是ACE 指派proof合约对数据进行 证明
    function validateProof(uint24 _proof, address _sender, bytes calldata) external returns (bytes memory);

    /**
    * @dev Validate a previously validated AZTEC proof via its hash
    *      This enables confidential assets to receive transfer instructions from a dApp that
    *      has already validated an AZTEC proof that satisfies a balancing relationship.
    * @param _proof the AZTEC proof object
    * @param _proofHash the hash of the `proofOutput` received by the asset
    * @param _sender the Ethereum address of the contract issuing the transfer instruction
    * @return a boolean that signifies whether the corresponding AZTEC proof has been validated
    */
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
    function validateProofByHash(uint24 _proof, bytes32 _proofHash, address _sender) external view returns (bool);

    /**
    * @dev Method to upgrade the registry linked with the msg.sender to a new factory, based on _factoryId.
    * The submitted _factoryId must be of epoch equal or greater than previous _factoryId, and of the same assetType.
    *
    * @param _factoryId - uint24 which contains 3 uint8s representing (epoch, cryptoSystem, assetType)
    */
    //
    // 基于_factoryId 将与 msg.sender 链接的注册表升级到新工厂的方法。
    // 提交的_factoryId必须等于或大于先前的_factoryId，并且必须具有相同的assetType。
    //
    // _factoryId: uint24，其中包含3个uint8，分别表示（epoch，cryptoSystem，assetType）
    function upgradeNoteRegistry(uint24 _factoryId) external;

    /**
    * @dev Update the state of the note registry according to transfer instructions issued by a
    * zero-knowledge proof. This method will verify that the relevant proof has been validated,
    * make sure the same proof has can't be re-used, and it then delegates to the relevant noteRegistry.
    *
    * @param _proof - unique identifier for a proof
    * @param _proofOutput - transfer instructions issued by a zero-knowledge proof
    * @param _proofSender - address of the entity sending the proof
    */
    //
    // 根据零知识证明发出的传输指令更新note注册表的状态。 
    // 此方法将验证相关proof已被验证，确保相同的proof不能重复使用，
    // 然后将proof委托给相关的noteRegistry。
    //
    // 入参:
    // _proof: 证明的唯一标识符
    // _proofOutput: 零知识证明发出的转移指令
    // _proofSender: 发送证明的实体的地址
    //
    function updateNoteRegistry(
        uint24 _proof,
        bytes calldata _proofOutput,
        address _proofSender
    ) external;


    event SetCommonReferenceString(bytes32[6] _commonReferenceString);
    
    event SetProof(
        uint8 indexed epoch,
        uint8 indexed category,
        uint8 indexed id,
        address validatorAddress
    );

    event IncrementLatestEpoch(uint8 newLatestEpoch);

    event SetFactory(
        uint8 indexed epoch,
        uint8 indexed cryptoSystem,
        uint8 indexed assetType,
        address factoryAddress
    );

    event CreateNoteRegistry(
        address registryOwner,
        address registryAddress,
        uint256 scalingFactor,
        address linkedTokenAddress,
        bool canAdjustSupply,
        bool canConvert
    );

    event UpgradeNoteRegistry(
        address registryOwner,
        address proxyAddress,
        address newBehaviourAddress
    );
    
    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}

