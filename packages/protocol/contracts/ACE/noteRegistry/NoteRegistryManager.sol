pragma solidity >=0.5.0 <0.6.0;

import "openzeppelin-solidity/contracts/token/ERC20/ERC20.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";

import "../../interfaces/IAZTEC.sol";
import "../../libs/VersioningUtils.sol";
import "../../interfaces/IERC20Mintable.sol";
import "./interfaces/NoteRegistryBehaviour.sol";
import "./interfaces/NoteRegistryFactory.sol";
import "../../Proxies/AdminUpgradeabilityProxy.sol";

/**
 * @title NoteRegistryManager
 * @author AZTEC
 * @dev NoteRegistryManager will be inherrited by ACE, and its purpose is to manage the entire
        lifecycle of noteRegistries and of
        factories. It defines the methods which are used to deploy and upgrade registries, the methods
        to enact state changes sent by
        the owner of a registry, and it also manages the list of factories which are available.
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
// 票据 note 注册表 管理合约 
// 继承 
contract NoteRegistryManager is IAZTEC, Ownable {
    using SafeMath for uint256;
    using VersioningUtils for uint24;

    /**
    * @dev event transmitted if and when a factory gets registered.
    */
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

    // Every user has their own note registry
    //
    // =================================================
    // TODO 这个东西至关重要
    // =================================================
    // 
    // 每个用户都有自己的票据note注册表
    struct NoteRegistry {
        // 这是一个 票决注册表行为 合约类型
        NoteRegistryBehaviour behaviour;
        // 这是一个 具备 mint 功能的 ERC20 合约类型
        IERC20Mintable linkedToken;
        // 
        uint24 latestFactory;
        // note 总额?
        uint256 totalSupply;
        // note 总额的 补充?
        uint256 totalSupplemented;

        // [_publicOwner][_proofHash]=> approve (_publicOwner: 是 public token 的owner)
        // 【公共批准记录】添加到noteRegistry中，以供ACE在需要将其持有的 【公共令牌】 转移到外部地址时使用。 它需要与_proofHash关联
        // TODO 剩余被批准可使用的 token数目, 是用于零知识证明的kPublic值, (使用时和 publicValue 同含义, 不同transferValue)
        mapping(address => mapping(bytes32 => uint256)) publicApprovals;
    }

    // TODO 各个账户的note注册表集
    // 定义 一个装载  该发起者的 一个 加密票据note 的注册列表结构
    mapping(address => NoteRegistry) public registries;

    /**
    * @dev index of available factories, using very similar structure to proof registry in ACE.sol.
    * The structure of the index is ().
    */
    // 可用工厂的索引，使用非常相似的结构来证明ACE.sol中的注册表
    // 索引的结构是 (epoch, cryptoSystem, assetType)
    //
    // 0x100 == 256  0x10000 == 65536 == 256*256
    address[0x100][0x100][0x10000] factories;


    uint8 public defaultRegistryEpoch = 1; // 默认注册表epoch
    uint8 public defaultCryptoSystem = 1; // 默认密码系统标识符


    // 这里面记录的是, 做过 校验的proofHash的标识
    // ACE 的 validateProof()函数 和 clearProofByHashes()函数 有用
    //
    // key是由 keccak256(abi.encode(proofHash, _proof, msg.sender))
    // value: bool
    mapping(bytes32 => bool) public validatedProofs;

    /**
    * @dev Increment the default registry epoch
    */
    // 增加默认注册表epoch
    function incrementDefaultRegistryEpoch() public onlyOwner { // 只有 合约的Owner 可以调
        defaultRegistryEpoch = defaultRegistryEpoch + 1;
    }

    /**
    * @dev Set the default crypto system to be used
    * @param _defaultCryptoSystem - default crypto system identifier
    */
    // 设置要使用的默认密码系统
    // _defaultCryptoSystem: 默认密码系统标识符
    function setDefaultCryptoSystem(uint8 _defaultCryptoSystem) public onlyOwner { // 只有 合约的Owner 可以调
        defaultCryptoSystem = _defaultCryptoSystem;
    }

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
    // 每个epoch每个密码系统的每种资产类型应具有一个注释注册表.
    // 
    // 工厂合约, 用于保存对应的 token 和 加密币的 一个存储相关的 合约??
    //
    // [该合约的owner才可以调用]
    function setFactory(uint24 _factoryId, address _factoryAddress) public onlyOwner {

        // 校验 该factory合约是否为空
        require(_factoryAddress != address(0x0), "expected the factory contract to exist");
        // 根据 factoryId 解析出对应的三元组 (epoch, cryptoSystem, assetType) 
        // 做法类似 根据 proof 解出 (epoch, category, proofId) 
        (uint8 epoch, uint8 cryptoSystem, uint8 assetType) = _factoryId.getVersionComponents();
        
        // 根据 三元组 (epoch, cryptoSystem, assetType) 获取对应的 factory 合约
        // 判断该 factory 是否已经存在了
        require(factories[epoch][cryptoSystem][assetType] == address(0x0), "existing factories cannot be modified");
        
        // 注册 factory 合约地址
        factories[epoch][cryptoSystem][assetType] = _factoryAddress;

        // 记录事件
        emit SetFactory(epoch, cryptoSystem, assetType, _factoryAddress);
    }

    /**
    * @dev Get the factory address associated with a particular factoryId. Fail if resulting address is 0x0.
    *
    * @param _factoryId - uint24 which contains 3 uint8s representing (epoch, cryptoSystem, assetType)
    */
    //
    // 获取与特定factoryId关联的工厂地址 (statedb中获取)。 如果结果地址为0x0，则失败
    // _factoryId: uint24，其中包含3个uint8，分别表示 (epoch，cryptoSystem，assetType)
    function getFactoryAddress(uint24 _factoryId) public view returns (address factoryAddress) {

        // 临时变量, factoryAddress 是否为空标识, 0: 非空, 1: 为空
        bool queryInvalid;
        assembly {
            // To compute the storage key for factoryAddress[epoch][cryptoSystem][assetType], we do the following:
            // 1. get the factoryAddress slot
            // 2. add (epoch * 0x10000) to the slot
            // 3. add (cryptoSystem * 0x100) to the slot
            // 4. add (assetType) to the slot
            // i.e. the range of storage pointers allocated to factoryAddress ranges from
            // factoryAddress_slot to (0xffff * 0x10000 + 0xff * 0x100 + 0xff = factoryAddress_slot 0xffffffff)

            // Conveniently, the multiplications we have to perform on epoch, cryptoSystem and assetType correspond
            // to their byte positions in _factoryId.
            // i.e. (epoch * 0x10000) = and(_factoryId, 0xff0000)
            // and  (cryptoSystem * 0x100) = and(_factoryId, 0xff00)
            // and  (assetType) = and(_factoryId, 0xff)

            // Putting this all together. The storage slot offset from '_factoryId' is...
            // (_factoryId & 0xffff0000) + (_factoryId & 0xff00) + (_factoryId & 0xff)
            // i.e. the storage slot offset IS the value of _factoryId

            // =====================================================================================================================
            // 
            // 要计算 factoryAddress[epoch][cryptoSystem][assetType] 的存储密钥，请执行以下操作
            // 1.获取factoryAddress插槽
            // 2.将 (epoch * 0x10000) 添加到插槽
            // 3.将 (cryptoSystem * 0x100) 添加到插槽
            // 4.将 (assetType) 添加到插槽
            // 即分配给factoryAddress的存储指针范围为
            // factoryAddress_slot 到 (0xffff * 0x10000 + 0xff * 0x100 + 0xff = factoryAddress_slot 0xffffffff)
            
            // 方便地，我们必须在epoch, cryptoSystem 和 assetType 上执行的乘法对应于它们在_factoryId中的字节位置
            //
            // 例如. (epoch * 0x10000) = and(_factoryId, 0xff0000)
            // and  (cryptoSystem * 0x100) = and(_factoryId, 0xff00)
            // and  (assetType) = and(_factoryId, 0xff)
            
            // 全部放在一起。 相对于'_factoryId'的存储插槽偏移为...
            // (_factoryId & 0xffff0000) + (_factoryId & 0xff00) + (_factoryId & 0xff)
            // 即, 存储插槽偏移量是_factoryId的值
           
            factoryAddress := sload(add(_factoryId, factories_slot))

            // factoryAddress 是否为空, 0: 非空, 1: 为空
            queryInvalid := iszero(factoryAddress)
        }

        // wrap both require checks in a single if test. This means the happy path only has 1 conditional jump
        // 如果 factoryAddress 为空时
        if (queryInvalid) {
            require(factoryAddress != address(0x0), "expected the factory address to exist");
        }
    }

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
    // 补充代币 (token -> 加密币)
    // 
    // 当可铸造和可转换资产要执行一项使零知识和公共平衡失衡的动作时调用。 
    // 例如，如果铸造零知识，则需要将某些公共 token 添加到ACE管理的池中，
    // 否则任何 private -> 公 public 转换都将面临没有任何公共 token 要发送的风险。
    //
    // _value: 本次需要补充的 token 数目
    function supplementTokens(uint256 _value) external {

        // 从各个账户的note注册表集中查出当前msg.sneder对应的注册表结构
        NoteRegistry storage registry = registries[msg.sender];
        require(address(registry.behaviour) != address(0x0), "note registry does not exist");
        // 给当前 msg.sender 账户对应的note注册表结构增加 加密币时 消耗的token发行总量和补充总量
        registry.totalSupply = registry.totalSupply.add(_value);
        registry.totalSupplemented = registry.totalSupplemented.add(_value);
        
        // 获取 对应的 注册信息
        (
            uint256 scalingFactor,
            ,,
            bool canConvert,
            bool canAdjustSupply
        ) = registry.behaviour.getRegistry();

        require(canConvert == true, "note registry does not have conversion rights");
        require(canAdjustSupply == true, "note registry does not have mint and burn rights");
        // 这是绑定的 某种 ERC20 代币 
        // (允许 当前tx发起者 从当前注册表中绑定的 erc20 合约中转 value个token,
        // 并转成 _value.mul(scalingFactor) 个 加密币 到当前 合约中)
        registry.linkedToken.transferFrom(msg.sender, address(this), _value.mul(scalingFactor));
    }

    /**
    * @dev Query the ACE for a previously validated proof
    * @notice This is a virtual function, that must be overwritten by the contract that inherits from NoteRegistry
    *
    * @param _proof - unique identifier for the proof in question and being validated
    * @param _proofHash - keccak256 hash of a bytes proofOutput argument. Used to identify the proof in question
    * @param _sender - address of the entity that originally validated the proof
    * @return boolean - true if the proof has previously been validated, false if not
    */
    // TODO 未实现 
    // TODO 被 ACE 重写了
    //
    // 查询ACE以获取先前验证的证据 
    // 这是一个虚拟函数，必须由继承自NoteRegistry的合同覆盖
    //
     // 入参:
    // _proof: 待验证证据的唯一标识符 (一个 proof)
    // _proofHash: keccak256字节proofOutput参数的哈希。 用于识别有问题的证据
    // _sender: 最初验证证明的实体的地址 (交易发起者??)
    // 
    // 返参:
    // 表示是否已验证相应的AZTEC证明的布尔值
    // 如果先前已验证过，则为true；否则为false
    function validateProofByHash(uint24 _proof, bytes32 _proofHash, address _sender) public view returns (bool);

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
    // TODO 实现了 IACE 中的 
    // createNoteRegistry (
    //    address _linkedTokenAddress,
    //    uint256 _scalingFactor,
    //    bool _canAdjustSupply,
    //    bool _canConvert)
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
    ) public {
        
        // assetType是0b00，其中的位表示（canAdjust，canConvert），因此assetType可以是1、2、3之一，其中
        //
        // 0 ==没有 convert/没有 adjust (无效标识)
        // 1 ==可以 convert/不可以 adjust
        // 2 ==没有 convert/可以 adjust
        // 3 ==可以 convert/可以 adjust
        uint8 assetType = getAssetTypeFromFlags(_canConvert, _canAdjustSupply);

        // 内部实用程序方法，可将三个uint8转换为uint24 的 通用方法
        //
        // a*0x100000|b*0x100|c <==> a*256*256|b*256|c <==> a<<16|b<<8|c
        uint24 factoryId = computeVersionFromComponents(defaultRegistryEpoch, defaultCryptoSystem, assetType);

        // 调用自己的重载方法
        createNoteRegistry(
            _linkedTokenAddress,
            _scalingFactor,
            _canAdjustSupply,
            _canConvert,
            factoryId
        );
    }

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
    ) public {

        // 先校验 当前 交易发起者 的注册表中的行为合约是否未被注册过
        require(address(registries[msg.sender].behaviour) == address(0x0),
            "address already has a linked note registry");
        // 是否可以 支持转换 ?    
        if (_canConvert) {
            // 校验下 ERC20 的地址
            require(_linkedTokenAddress != address(0x0), "expected the linked token address to exist");
        }

        // 从 _factoryId 中获取 三元组 的 资产类型 (支持转换/支持调整)
        (,, uint8 assetType) = _factoryId.getVersionComponents();
        // assetType is 0b00 where the bits represent (canAdjust, canConvert),
        // so assetType can be one of 1, 2, 3 where
        // 0 == no convert/no adjust (invalid)
        // 1 == can convert/no adjust
        // 2 == no convert/can adjust
        // 3 == can convert/can adjust
        //
        // ======================================================================
        //
        // assetType是0b00，其中的位表示（canAdjust，canConvert），因此assetType可以是1、2、3之一，其中
        //
        // 0 ==没有 convert/没有 adjust (无效标识)
        // 1 ==可以 convert/不可以 adjust
        // 2 ==没有 convert/可以 adjust
        // 3 ==可以 convert/可以 adjust
        uint8 flagAssetType = getAssetTypeFromFlags(_canConvert, _canAdjustSupply);
        
        // 校验入参的 资产类型和自己从 factoryId 中解析出来的对比
        require (flagAssetType != uint8(0), "can not create asset with convert and adjust flags set to false");
        require (flagAssetType == assetType, "expected note registry to match flags");

        // 获取与特定factoryId关联的工厂地址 (statedb中获取)。 如果结果地址为0x0，则失败
        address factory = getFactoryAddress(_factoryId);

        // ============================================
        // ================= 超级 重要 =================
        // 实例化一个 工厂合约 
        // 并由 当前工厂合约 部署一个新的 注册行为合约实例
        // ============================================
        // ============================================
        address behaviourAddress = NoteRegistryFactory(factory).deployNewBehaviourInstance();

        
        // 跨合约调用的方法编码
        bytes memory behaviourInitialisation = abi.encodeWithSignature(
            "initialise(address,uint256,bool,bool)",
            address(this), // 行为合约的 所有权 只能是 当前 manager 合约
            _scalingFactor, // token 和 加密币 的转换 比例
            _canAdjustSupply, // 是否支持调整(mint/burn)的标识位
            _canConvert // 是否支持转换的标识位
        );

        // 创建一个代理合约实例
        address proxy = address(new AdminUpgradeabilityProxy(
            behaviourAddress, // 实现合约 地址, 参数: _logic
            factory, // admin 地址, 参数: _admin
            behaviourInitialisation // 调用入参, 参数: _data
        ));


        // 往 Note注册表中 添加一个新的关于msg.sender的 note注册信息
        registries[msg.sender] = NoteRegistry({
            behaviour: NoteRegistryBehaviour(proxy), // 这里其实用到了 Ownable 合约的构造, 将behaviour的代理合约地址赋值
            linkedToken: IERC20Mintable(_linkedTokenAddress), // 实例化一个 ERC20 合约实例, 该合约地址为 _linkedTokenAddress
            latestFactory: _factoryId, // 工厂的 Id (可以用来获取 工厂合约地址, 和可以获取 (epoch，cryptoSystem，assetType) 三元组)
            totalSupply: 0, // 记录 token -> 加密币 时消耗的 token数
            totalSupplemented: 0 // 记录 补充 token -> 加密币 时消耗的 token数
        });


        // 记录事件
        emit CreateNoteRegistry(
            msg.sender,
            proxy,
            _scalingFactor,
            _linkedTokenAddress,
            _canAdjustSupply,
            _canConvert
        );
    }

    /**
    * @dev Method to upgrade the registry linked with the msg.sender to a new factory, based on _factoryId.
    * The submitted _factoryId must be of epoch equal or greater than previous _factoryId, and of the same assetType.
    *
    * @param _factoryId - uint24 which contains 3 uint8s representing (epoch, cryptoSystem, assetType)
    */

    // 升级 note 注册表
    // 
    // 基于_factoryId将与msg.sender链接的注册表升级到新工厂的方法
    // 提交的_factoryId必须等于或大于先前的_factoryId，并且具有相同的assetType
    // _factoryId: (epoch, cryptoSystem, assetType)
    function upgradeNoteRegistry(
        uint24 _factoryId
    ) public {

        // 获取当前 msg.sender 对应的 note 注册表信息
        NoteRegistry storage registry = registries[msg.sender];
        require(address(registry.behaviour) != address(0x0), "note registry for sender doesn't exist");

        // 解出_factoryId三元组
        (uint8 epoch,, uint8 assetType) = _factoryId.getVersionComponents();

        // 获取之前的 factoryId
        uint24 oldFactoryId = registry.latestFactory;
        // 解出旧factoryId 的三元组
        (uint8 oldEpoch,, uint8 oldAssetType) = oldFactoryId.getVersionComponents();

        // 校验 epoch 和 assertType
        require(epoch >= oldEpoch, "expected new registry to be of epoch equal or greater than existing registry");
        require(assetType == oldAssetType, "expected assetType to be the same for old and new registry");
        

        // 获取新的 factory地址
        address factory = getFactoryAddress(_factoryId);
        // 部署新的 行为合约
        address newBehaviour = NoteRegistryFactory(factory).deployNewBehaviourInstance();

        // 获取旧的 factory地址
        address oldFactory = getFactoryAddress(oldFactoryId);
        registry.latestFactory = _factoryId; // 更换 note注册表中记录的factoryId

        // 变更代理合约中的信息
        // 这样做的目的是 不变更底层的 ProxyAdmin 合约, 只是变更ProxyAdmin中记录的 admin 和 implementation 地址
        NoteRegistryFactory(oldFactory).handoverBehaviour(address(registry.behaviour), newBehaviour, factory);
        
        // 记录事件
        emit UpgradeNoteRegistry(
            msg.sender,
            address(registry.behaviour),
            newBehaviour
        );
    }

    /**
    * @dev Internal method dealing with permissioning and transfer of public tokens.
    *
    * @param _publicOwner - the non-ACE party involved in this transaction. Either current or desired
    *   owner of public tokens
    * @param _transferValue - the total public token value to transfer. Seperate value to abstract
    *   away scaling factors in first version of AZTEC
    * @param _publicValue - the kPublic value to be used in zero-knowledge proofs
    * @param _proofHash - use for permissioning, hash of the proof that this spend is enacting
    *
    */
    //
    // 处理 public token 的许可和转让的内部方法
    //
    // _publicOwner: 参与此交易的非ACE一方。 public token 的当前 owner或期望 owner (基本上是某个token的合约)
    // _transferValue: 要转让的public token总价值。 分离值以抽象化AZTEC第一版中的缩放因子  TODO 这个才是 token 的value
    // _publicValue: 用于零知识证明的kPublic值 <就是 token -> 加密币时的值 有正负之分>  TODO 这个是 token value 的处理过后的值
    // _proofHash: 用于许可，此支出正在制定的证据的哈希
    function transferPublicTokens(
        address _publicOwner,
        uint256 _transferValue,
        int256 _publicValue,
        bytes32 _proofHash
    )
        internal
    {

        // 获取当前 msg.sender 的 note注册表信息
        // 设计到 registry 的修改, 所以用 storage
        NoteRegistry storage registry = registries[msg.sender];
        // if < 0, depositing
        // else withdrawing

        // 如果 _publicValue < 0 说明是 token -> 加密币  TODO 充币
        if (_publicValue < 0) {

            // 根据 public token 的owner 和 proofHash 获取 approve
            uint256 approvalForAddressForHash = registry.publicApprovals[_publicOwner][_proofHash];
            
            // 将本次 token -> 加密币的 token 数量叠加记录到 note注册表信息的 totalSupply 字段
            registry.totalSupply = registry.totalSupply.add(uint256(-_publicValue));
            
            // TODO 剩余的 被批准可以试用的 value 的数目必须大于目前正要试用的数目
            require(
                approvalForAddressForHash >= uint256(-_publicValue),
                "public owner has not validated a transfer of tokens"
            );


            // 将剩余被批准可使用的 数目减去 本次铸币时消耗的数目
            registry.publicApprovals[_publicOwner][_proofHash] = approvalForAddressForHash.sub(uint256(-_publicValue));
            
            // 让 owner 往当前合约转 _transferValue  public token
            registry.linkedToken.transferFrom(
                _publicOwner,
                address(this),
                _transferValue);


        } else { // 加密币 -> token  TODO 提币

             // 将本次 加密币 -> token 的 token 数量叠加记录到 note注册表信息的 totalSupply 字段
            registry.totalSupply = registry.totalSupply.sub(uint256(_publicValue));

            // 当前 合约 转 _transferValue 到 _publicOwner 合约
            registry.linkedToken.transfer(
                _publicOwner,
                _transferValue
            );
        }
    }

    /**
    * @dev Update the state of the note registry according to transfer instructions issued by a
    * zero-knowledge proof. This method will verify that the relevant proof has been validated,
    * make sure the same proof has can't be re-used, and it then delegates to the relevant noteRegistry.
    *
    * @param _proof - unique identifier for a proof
    * @param _proofOutput - transfer instructions issued by a zero-knowledge proof
    * @param _proofSender - address of the entity sending the proof
    */
    // 根据零知识证明发出的传输指令更新笔记注册表的状态. 
    // 此方法将验证相关证明是否已通过验证，确保相同的证明不能重复使用，然后将其委托给相关的注释.
    //
    // _proof: 证明的唯一标识符
    // _proofOutput: 零知识证明发出的转移指令
    // _proofSender: 发送证明的实体的地址
    function updateNoteRegistry(
        uint24 _proof,
        bytes memory _proofOutput,
        address _proofSender
    ) public {

        // 因为 不改变 registry 本身数据 而只是需要用 registry 中的某些变量
        NoteRegistry memory registry = registries[msg.sender];
        // 改 registry 的实现合约 behaviour 必须存在
        require(address(registry.behaviour) != address(0x0), "note registry does not exist");

        // 根据入参的 output 算出 Hash
        bytes32 proofHash = keccak256(_proofOutput);

        // 算出 validatedProofHash
        bytes32 validatedProofHash = keccak256(abi.encode(proofHash, _proof, msg.sender));

        require(
            // 表示是否已验证相应的AZTEC证明的布尔值, 在ACE中得到实现
            validateProofByHash(_proof, proofHash, _proofSender) == true,
            "ACE has not validated a matching proof"
        );
        // clear record of valid proof - stops re-entrancy attacks and saves some gas
        // 清除 有效证明记录-阻止 重放攻击 并节省一些gas
        // 也就是说, 使用过后就需要 销毁掉
        validatedProofs[validatedProofHash] = false;

        // publicValue: 用于零知识证明的kPublic值
        // transferValue: 转让的public token总价值
        // publicOwner: token 的合约
        //
        // 这个方法里面最终有直接操作 state中的note的逻辑 (变更proofOutput解析出来的 input 和 output)
        (
            address publicOwner,
            uint256 transferValue,
            int256 publicValue
        ) = registry.behaviour.updateNoteRegistry(_proof, _proofOutput);

        // ================================= 
        // ================================= 
        // TODO 这个才是真正的去变更 registry 中的相关信息, 铸币还是提币
        //      transferPublicTokens() 里面于自己 操作 storage registry 的逻辑
        // ================================= 
        // ================================= 
        if (publicValue != 0) {
            transferPublicTokens(publicOwner, transferValue, publicValue, proofHash);
        }
    }

    /**
    * @dev Adds a public approval record to the noteRegistry, for use by ACE when it needs to transfer
        public tokens it holds to an external address. It needs to be associated with the hash of a proof.
    */
    // 将【公共批准记录】添加到noteRegistry中，以供ACE在需要将其持有的公共令牌转移到外部地址时使用。 它需要与证明的哈希关联。
    //
    // _registryOwner: 有关注册表所有者的地址
    // _proofHash: 由 keccak256(proofOutput) 生成
    // _value: 被批准 可以试用的 value 数目, 是用于零知识证明的kPublic值 
    function publicApprove(address _registryOwner, bytes32 _proofHash, uint256 _value) public {

        // 获取对应的 note注册表 信息
        NoteRegistry storage registry = registries[_registryOwner];
        // 校验注册表对应的 行为实现合约
        require(address(registry.behaviour) != address(0x0), "note registry does not exist");
        registry.publicApprovals[msg.sender][_proofHash] = _value;
    }

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
     // scalingFactor: 定义一个AZTEC注释代表多少个ERC20令牌
     // confidentialTotalMinted: keccak256票据的哈希值，代表铸造的总供应量
     // confidentialTotalBurned: keccak256票据哈希值，代表总消耗量
     // totalSupply: 代表与特定注册表关联的公共令牌的当前总供应量
     // totalSupplemented: total补充
     // canConvert: 布尔值定义了 noteRegistry 是否可以在 public 和 private 之间转换
     // canAdjustSupply: 布尔值定义了 noteRegistry 是否可以使用 mint 和 burn 方法

    function getRegistry(address _registryOwner) public view returns (
        address linkedToken,
        uint256 scalingFactor,
        bytes32 confidentialTotalMinted,
        bytes32 confidentialTotalBurned,
        uint256 totalSupply,
        uint256 totalSupplemented,
        bool canConvert,
        bool canAdjustSupply
    ) {
        NoteRegistry memory registry = registries[_registryOwner];
        (
            scalingFactor,
            confidentialTotalMinted,
            confidentialTotalBurned,
            canConvert,
            canAdjustSupply
        ) = registry.behaviour.getRegistry();
        linkedToken = address(registry.linkedToken);
        totalSupply = registry.totalSupply;
        totalSupplemented = registry.totalSupplemented;
    }

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
    function getNote(address _registryOwner, bytes32 _noteHash) public view returns (
        uint8 status,
        uint40 createdOn,
        uint40 destroyedOn,
        address noteOwner
    ) {
        NoteRegistry memory registry = registries[_registryOwner];
        return registry.behaviour.getNote(_noteHash);
    }

    /**
    * @dev Internal utility method which converts two booleans into a uint8 where the first boolean
    * represents (1 == true, 0 == false) the bit in position 1, and the second boolean the bit in position 2.
    * The output is 1 for an asset which can convert between public and private, 2 for one with no conversion
    * but with the ability to mint and/or burn, and 3 for a mixed asset which can convert and mint/burn
    *
    */
    // 内部实用程序方法，它将两个布尔值转换为uint8，
    // 其中第一个布尔值表示（1 == true，0 == false）位置1的位，第二个布尔值表示位置2的位。
    //
    // 对于可以在 public 和 private 之间转换的资产，输出为1；
    // 对于【没有转换】但具有【mint】 和/或 【burn】功能的资产，输出为2；
    // 对于【可以转换】和【mint】/【burn】的混合资产，输出为3。
    // 
    // 就是用来判断 canConvert 和 canAdjust 标识位的
    // 
    function getAssetTypeFromFlags(bool _canConvert, bool _canAdjust) internal pure returns (uint8 assetType) {
        uint8 convert = _canConvert ? 1 : 0;
        uint8 adjust = _canAdjust ? 2 : 0;

        assetType = convert + adjust;
    }

    /**
    * @dev Internal utility method which converts three uint8s into a uint24
    *
    */
    // 内部实用程序方法，可将三个uint8转换为uint24 的 通用方法
    //
    // a*0x100000|b*0x100|c
    // 
    // a*256*256|b*256|c
    // 
    // a<<16|b<<8|c
    function computeVersionFromComponents(
        uint8 _first,
        uint8 _second,
        uint8 _third
    ) internal pure returns (uint24 version) {
        assembly {
            version := or(mul(_first, 0x10000), or(mul(_second, 0x100), _third))
        }
    }

    /**
    * @dev used for slow release, useless afterwards.
    */
    function makeAssetAvailable(address _registryOwner) public onlyOwner {
        NoteRegistry memory registry = registries[_registryOwner];
        registry.behaviour.makeAvailable();
    }
}
