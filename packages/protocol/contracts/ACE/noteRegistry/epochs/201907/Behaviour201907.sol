pragma solidity >=0.5.0 <0.6.0;

import "../../../../interfaces/IAZTEC.sol";
import "../../../../libs/NoteUtils.sol";
import "../../interfaces/NoteRegistryBehaviour.sol";
import "../../NoteRegistryManager.sol";

/**
 * @title Behaviour201907
 * @author AZTEC
 * @dev Details the methods and the storage schema of a note registry.
        Is an ownable contract, and should always inherrit from the previous
        epoch of the behaviour contract. This contract defines the shared methods
        between all asset types for the 201907 generation (epoch 1).
 * Methods are documented in interface.
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
// TODO 注意, 这个是大头
// 
// 定义了 note 注册表结构的 行为
contract Behaviour201907 is NoteRegistryBehaviour {

    // 使用 NoteUtils 来处理 bytes
    using NoteUtils for bytes;

    /**
    * Note struct. This is the data that we store when we log AZTEC notes inside a NoteRegistry
    *
    * Data structured so that the entire struct fits in 1 storage word.
    *
    * @notice Yul is used to pack and unpack Note structs in storage for efficiency reasons,
    *   see `NoteRegistry.updateInputNotes` and `NoteRegistry.updateOutputNotes` for more details
    **/
    //
    // 票据结构。 这是我们在NoteRegistry中记录AZTEC 票据时 存储的数据
    // 
    // 数据结构化，因此整个结构适合1个存储字
    //
    // 为了提高效率，Yul用于打包和解压缩存储中的Note结构，
    // 有关更多详细信息，请参见`NoteRegistry.updateInputNotes`和`NoteRegistry.updateOutputNotes`.
    struct Note {
        // `status` uses the IAZTEC.NoteStatus enum to track the lifecycle of a note.
        //
        // `status`使用 IAZTEC.NoteStatus 枚举来跟踪 note 的生命周期
        uint8 status; // 目前只有三种状态,  DOES_NOT_EXIST  (票据不存在), UNSPENT (票据未花费), SPENT (票据已花费)

        // `createdOn` logs the timestamp of the block that created this note. There are a few
        // use cases that require measuring the age of a note, (e.g. interest rate computations).
        // These lifetime are relevant on timescales of days/months, the 900-ish seconds that a miner
        // can manipulate a timestamp has little effect, but should be considered when utilizing this parameter.
        // We store `createdOn` in 5 bytes of data - just in case this contract is still around in 2038 :)
        // This kicks the 'year 2038' problem down the road by about 400 years
        //
        // `createdOn` 记录创建该 note 的块的时间戳。 有一些用例需要测量笔记的使用期限（例如，利率计算）
        // 这些生命周期与天/月的时间尺度相关，矿工可以操纵时间戳的900-ish秒影响不大，但是在使用此参数时应予以考虑
        // 我们将 `createdOn` 存储在5个字节的数据中，以防万一该合同在2038年仍然存在:)
        // 这将 "2038年" 问题推后了大约400年
        //
        uint40 createdOn;

        // `destroyedOn` logs the timestamp of the block that destroys this note in a transaction.
        // Default value is 0x0000000000 for notes that have not been spent.
        // `destroyedOn`记录在交易中销毁该票据的区块的时间戳。
        // 尚未使用的笔记的默认值为0x0000000000。
        uint40 destroyedOn;

        // The owner of the note
        // 票据的持有者地址 (指的是一个明文的 以太坊Address么?)
        address owner;
    }


    // Note 注册行为结构
    struct Registry {
        // 本次注册是否可用
        bool active;
        // 比例因子
        uint256 scalingFactor;
        // 机密总铸造
        bytes32 confidentialTotalMinted;
        // 机密总烧毁
        bytes32 confidentialTotalBurned;
        // 是否可以转换标识
        bool canConvert;
        // 是否可以调整标识
        bool canAdjustSupply;
        // 票据集 (noteHash => note)
        mapping(bytes32 => Note) notes;
    }

    // 当前 行为合约 绑定的注册表
    // (行为合约是 描述改注册表的行为的一个合约)
    Registry public registry;

    // 定义一个 0 值的 票据Hash
    bytes32 public constant ZERO_VALUE_NOTE_HASH = 0x26d21f105b054b61e8d9680855c3af0633bd7c140b87de95f0ac218046fc71db;
    constructor () NoteRegistryBehaviour() public {}

    // 初始化noteRegistry的数据。 应该只调用一次
    // _newOwner: 初始化调用将 交易所有权转的地址, (权限控制的 某个以太坊地址)
    // _scalingFactor: 定义 一个 AZTEC note 值 兑换多少令牌数量 的比例 
    // _canAdjustSupply: noteRegistry 是否可以使用 mint 和 burn
    // _canConvert: noteRegistry 是否可以将价值从 private 转移到 public，反之亦然
    function initialise(

        // 票据的持有者
        address _newOwner,
        // 比例因子
        uint256 _scalingFactor,
        // 是否可以调整标识
        bool _canAdjustSupply,
        // 是否可以转换标识
        bool _canConvert
    ) public {

        // 检查 note注册表是否已经初始化过了
        require(initialised != true, "registry already initialised");

        // 这个是 Ownable 合约的方法, 管理 交易的所有权
        // 即, 只有 owner 才可以操作当前 行为合约
        _transferOwnership(_newOwner);

        // 记录 note注册交易发起者
        dataLocation = msg.sender;


        // 实例化一个 注册 实体
        registry = Registry({
            // 状态置为, 可用
            active: true,
            // 设置 比例因子
            scalingFactor: _scalingFactor,
            // 初始化 mint, 0 note Hash
            confidentialTotalMinted: ZERO_VALUE_NOTE_HASH,
            // 初始化 burn, 0 note Hash
            confidentialTotalBurned: ZERO_VALUE_NOTE_HASH,
            // 设置 是否转换标识位
            canConvert: _canConvert,
            // 设置 是否调整标识位
            canAdjustSupply: _canAdjustSupply
        });

        // 票据注册表是否已经初始化 标识 设置为, 已初始化
        initialised = true;
    }


    // 获取当前 note 的 注册信息
    //
    // scalingFactor: 定义 一个 AZTEC note 值 兑换多少令牌数量 的比例 
    // confidentialTotalMinted: AZTEC票据的哈希值代表 mint 的总量
    // confidentialTotalBurned: AZTEC票据的哈希值代表 burn 的总量 
    // canConvert: 布尔值定义了 noteRegistry 是否可以在 public 和 private 之间转换
    // canAdjustSupply: 布尔值定义了 noteRegistry 是否可以使用 mint 和 burn 方法
    function getRegistry() public view returns (
        uint256 scalingFactor,
        bytes32 confidentialTotalMinted,
        bytes32 confidentialTotalBurned,
        bool canConvert,
        bool canAdjustSupply
    ) {
        require(registry.active == true, "expected registry to be created");
        scalingFactor = registry.scalingFactor;
        confidentialTotalMinted = registry.confidentialTotalMinted;
        confidentialTotalBurned = registry.confidentialTotalBurned;
        canConvert = registry.canConvert;
        canAdjustSupply = registry.canAdjustSupply;
    }

    // 未实现 ?
    // 在成功验证烧伤证明后执行所需的状态修改
    // _proofOutputs: burn 验证器的输出
    function burn(bytes memory /* _proofOutputs */) public onlyOwner {
        require(registry.canAdjustSupply == true, "this asset is not burnable");
    }

    // 未实现 ?
     // 通过成功验证的 mint 证明，实施所需的状态修改
    // _proofOutputs: mint 验证器的 output
    function mint(bytes memory  /* _proofOutputs */) public onlyOwner {
        require(registry.canAdjustSupply == true, "this asset is not mintable");
    }

    // todo 更新 note注册表中的某些note??
    // 
    // ##############################################################
    // ### 单个 proofOutput 中包含一组 input notes 和 output notes ###
    // ##############################################################
    //
    // 根据已成功 验证的输出 (_proofOutput) ，执行所需的状态修改.
    // 
    // 当前行为合同使用 _proofId 参数来（如果需要）限制 note 注册表支持的 proof 版本，
    // 例如，在proofOutputs模式发生更改时很有用.
    //
    function updateNoteRegistry(
        uint24 _proof,
        bytes memory _proofOutput
    ) public onlyOwner returns (
        address publicOwner,
        uint256 transferValue,
        int256 publicValue
    ) {

        // 当前行为合约 绑定的 注册表实例
        //
        // 校验下 当前注册表的 状态 
        require(registry.active == true, "note registry does not exist for the given address");
        bytes memory inputNotes;
        bytes memory outputNotes;

        // 提取`bytes _proofOutput`对象的组成元素
        // 
        // 入参:
        // _proofOutput: AZTEC证明输出
        // 
        // 返参:
        // inputNotes: 输入AZTEC notes 的 AZTEC-ABI 动态数组
        // outputNotes: 输出AZTEC notes 的 AZTEC-ABI 动态数组
        // publicOwner: proof 所涉及的任何 公共令牌 所有者的以太坊地址,  token 的合约
        // publicValue: proof 中涉及的 公共代币数量，用于零知识证明的kPublic值
        // 如果 (publicValue > 0), 这代表将 token 从ACE转移到publicOwner (加密世界 到 token世界)
        // 如果 (publicValue < 0), 这表示将 token 从publicOwner转移到ACE (token世界 到 加密世界)
        (
            inputNotes,
            outputNotes,
            publicOwner,
            publicValue
        ) = _proofOutput.extractProofOutput();


        // 给定字节数组的内部函数更新noteRegistry
        // _inputNotes: 一组 UTXO的 input 的 note
        updateInputNotes(inputNotes);

        // 给定字节数组的内部函数更新noteRegistry
        // _outputNotes: 一组 UTXO的 output 的 note
        updateOutputNotes(outputNotes);

        // If publicValue != 0, enact a token transfer if asset is convertible
        //
        // 如果publicValue！= 0，则在资产可转换的情况下进行令牌转移
        if (publicValue != 0) {

            // 判断下 是否支持 private 和 public 的互转
            require(registry.canConvert == true, "asset cannot be converted into public tokens");
            
            // 如果 token value 的 正负, 分别计算 token 和加密币 转换的比例的相对值
            // publicValue: 用于零知识证明的kPublic值
            // transferValue: 转让的public token总价值
            if (publicValue < 0) { 
                transferValue = uint256(-publicValue).mul(registry.scalingFactor);
            } else {
                transferValue = uint256(publicValue).mul(registry.scalingFactor);
            }
        }
    }

    // 未实现?
    // 将secretTotalMinted设置为新值。 该值必须是 note 的Hash
    // _newTotalNoteHash: 表示资产总 铸造 价值的 note Hash
    function setConfidentialTotalMinted(bytes32 /* newTotalNoteHash */) internal onlyOwner returns (bytes32) {
        require(registry.canAdjustSupply == true, "this asset is not mintable");

    }

    // 未实现?
    // 将secretTotalBurned设置为新值。 该值必须是 note 的Hash
    // _newTotalNoteHash: 表示资产总 燃烧 价值的 note Hash
    function setConfidentialTotalBurned(bytes32 /* newTotalNoteHash */) internal onlyOwner returns (bytes32) {
        require(registry.canAdjustSupply == true, "this asset is not burnable");
    }


    // 根据 noteHash 从注册表中 查询 note 信息, 并将 note存入 storage
    function getNote(bytes32 _noteHash) public view returns (
        uint8 status,
        uint40 createdOn,
        uint40 destroyedOn,
        address noteOwner
    ) {
        require(
            registry.notes[_noteHash].status != uint8(NoteStatus.DOES_NOT_EXIST),
            "expected note to exist"
        );
        Note storage notePtr = registry.notes[_noteHash];

        // 获取 note 的相关字段
        // 这里就是 后面 createNote() 和 deleteNote() 操作的 note 信息
        assembly {
            let note := sload(notePtr_slot)
            status := and(note, 0xff)
            createdOn := and(shr(8, note), 0xffffffffff)
            destroyedOn := and(shr(48, note), 0xffffffffff)
            noteOwner := and(shr(88, note), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    // 给定字节数组的内部函数更新noteRegistry
    // _inputNotes: 一组 UTXO 的 input 的 note
    function updateInputNotes(bytes memory inputNotes) internal {
        uint256 length = inputNotes.getLength();

        // 逐个 处理 inputs 中的 note
        for (uint256 i = 0; i < length; i += 1) {
            // 提取AZTEC note 的组成元素
            // 
            // 入参: 
            // _note: 一个 AZTEC note信息
            // 
            // 返参: 
            // owner: note 所有者的以太坊地址
            // noteHash: note 公钥的Hash
            // metadata: note 的特定元数据（包含公钥和 note owner 需要的任何其他数据）
            //
            // 返回三元组 (owner, noteHash, metadata)
            (address noteOwner, bytes32 noteHash,) = inputNotes.get(i).extractNote();
            // 变更note 状态为 已花费 SPENT, 设置 destryOn 为当前时间戳
            // 即: 花费调 inputNote
            deleteNote(noteHash, noteOwner);

        }
    }

    // 给定字节数组的内部函数更新noteRegistry
    // _outputNotes: 一组 UTXO的 output 的 note
    function updateOutputNotes(bytes memory outputNotes) internal {
        uint256 length = outputNotes.getLength();

        // 组个 遍历 outputs 中的 note
        for (uint256 i = 0; i < length; i += 1) {

            // 提取AZTEC note 的组成元素
            // 
            // 入参: 
            // _note: 一个 AZTEC note信息
            // 
            // 返参: 
            // owner: note 所有者的以太坊地址
            // noteHash: note 公钥的Hash
            // metadata: note 的特定元数据（包含公钥和 note owner 需要的任何其他数据）
            //
            // 返回三元组 (owner, noteHash, metadata)
            (address noteOwner, bytes32 noteHash,) = outputNotes.get(i).extractNote();
            require(noteOwner != address(0x0), "output note owner cannot be address(0x0)");

            // 创建新的 为未花费 note
            createNote(noteHash, noteOwner);
        }
    }

    // 内部函数创建一个新的note对象
    // _noteHash: 一个 note 的Hash
    // _noteOwner: 该 note 对应的 owner (一个 以太坊地址)
    function createNote(bytes32 _noteHash, address _noteOwner) internal {
        // set up some temporary variables we'll need
        // 设置一些我们需要的临时变量
        uint256 noteStatus = uint256(NoteStatus.UNSPENT);

        // 根据noteHash 从 注册表中获取对应的 note信息
        // 
        // 这个 没有的话, 是返回一个新的空的note对象 notePtr 指针 ???? 
        Note storage notePtr = registry.notes[_noteHash];

        // 获取的 note 的状态 必须为, 不存在
        require(notePtr.status == uint256(NoteStatus.DOES_NOT_EXIST), "output note exists");
        // We manually pack our note struct in Yul, because Solidity can be a bit liberal with gas when doing this
        // 我们手动将 note结构打包在Yul中，因为这样做时，Solidity在使用Gas时可能会比较宽松
        // (注: Yul（以前也称为JULIA或IULIA）是一种中间语言，可以将其编译为用于不同后端的字节码)
        assembly {
            // Write a new note into storage
            // 将新 note 写到storage
            sstore(
                notePtr_slot,
                // combine `status`, `createdOn` and `owner` via logical OR opcodes
                // 通过逻辑 | 操作码组合 "status", "createdOn"和"owner"
                or(
                    or(
                        // `status` occupies byte position 0
                        // `status'占据字节位置0
                        and(noteStatus, 0xff), // mask to 1 byte (uint8)  掩码为1个字节（uint8）
                        // `createdOn` occupies byte positions 1-5 => shift by 8 bits
                        // `createdOn`占据字节位置1-5 =>移位8位
                        shl(8, and(timestamp, 0xffffffffff)) // mask timestamp to 40 bits 掩码时间戳为40位
                    ),
                    // `owner` occupies byte positions 11-31 => shift by 88 bits
                    // "owner" 占据字节位置11-31 =>移位88位
                    shl(88, _noteOwner) // _noteOwner already of address type, no need to mask  _noteOwner已经为地址类型，无需屏蔽
                )
            )
        }
    }


    // 内部功能删除 note 对象 (变更note 状态为 已花费 SPENT, 设置 destryOn 为当前时间戳)
    // _noteHash: 一个 note 的Hash
    // _noteOwner: 该 note 对应的 owner (一个 以太坊地址)
    function deleteNote(bytes32 _noteHash, address _noteOwner) internal {
        // set up some temporary variables we'll need
        // N.B. the status flags are NoteStatus enums, but written as uint8's.
        // We represent them as uint256 vars because it is the enum values that enforce type safety.
        // i.e. if we include enums that range beyond 256,
        // casting to uint8 won't help because we'll still be writing/reading the wrong note status
        // To summarise the summary - validate enum bounds in tests, use uint256 to save some gas vs uint8
        // set up some temporary variables we'll need

        // ====================================================================================================
        // 设置一些临时变量我们需要N.B. 状态标志是 NoteStatus枚举，但写为uint8
        // 我们将它们表示为uint256 vars，因为强制类型安全的是枚举值.
        // 也就是说，如果我们包含的枚举数超出256, 则广播到uint8将无济于事，因为我们仍然会写/读错误的音符状态.
        // 总结摘要 - 验证测试中的枚举范围，使用uint256节省一些成本，而uint8则设置一些我们需要的临时变量.

        uint256 noteStatusNew = uint256(NoteStatus.SPENT);  // 票据已花费 状态
        uint256 noteStatusOld;
        address storedNoteOwner; // 中转 note 的 owner ??


        // 根据当前 noteHash 从当前 注册表中 查回对应的 note信息
        Note storage notePtr = registry.notes[_noteHash];
        // We manually pack our note struct in Yul, because Solidity can be a bit liberal with gas when doing this
        // Update the status of each `note`:
        // 1. set the note status to SPENT
        // 2. update the `destroyedOn` timestamp to the current timestamp
        // We also must check the following:
        // 1. the note has an existing status of UNSPENT
        // 2. the note owner matches the provided input
        //
        // =======================================================================================================
        // 我们手动将 note 结构打包在 Yul 中，因为这样做时，Solidity在使用Gas时可能会比较宽松
        // (注: Yul（以前也称为JULIA或IULIA）是一种中间语言，可以将其编译为用于不同后端的字节码)
        //
        // 更新每个`note`的状态：
        // 1.将 note 状态设置为 "SPENT"
        // 2.将`destroyedOn`时间戳更新为当前时间戳
        // 我们还必须检查以下内容：
        // 1. note 的状态为UNSPENT
        // 2. note所有者与提供的 UTXO input 匹配
        assembly {
                // load up our note from storage
                // 从存储中加载我们的 note 
                let storedNote := sload(notePtr_slot)

                // extract the status of this note (we'll check that it is UNSPENT outside the asm block)
                // 提取此 note 的状态（我们将检查它是否在asm块之外为UNSPENT）
                noteStatusOld := and(storedNote, 0xff)

                // extract the owner of this note (we'll check that it is _owner outside the asm block)
                // 提取此 note 的所有者（我们将检查它是否在asm块之外为_owner）
                storedNoteOwner := and(shr(88, storedNote), 0xffffffffffffffffffffffffffffffffffffffff)

                // update the input note and write it into storage.
                // We need to change its `status` from UNSPENT to SPENT, and update `destroyedOn`
                //
                // 更新 input note 并将其写入 storage。
                // 我们需要将其状态从 UNSPENT 更改为 SPENT，然后更新destroyedOn。
                sstore(
                    notePtr_slot,
                    or(
                        // zero out the bits used to store `status` and `destroyedOn`
                        // `status` occupies byte index 1, `destroyedOn` occupies byte indices 6 - 11.
                        // We create bit mask with a NOT opcode to reduce contract bytecode size.
                        // We then perform logical AND with the bit mask to zero out relevant bits
                        //
                        // 将用于存储“状态”和“ destroyedOn”的位清零
                        // `status'占用字节索引1，`destroyedOn`占用字节索引6-11
                        // 我们使用 NOT操作码创建位掩码，以减少合同字节码的大小
                        // 然后，我们使用位掩码执行 & 以将相关位清零
                        and(
                            storedNote,
                            not(0xffffffffff0000000000ff)
                        ),
                        // Now that we have zeroed out storage locations of `status` and `destroyedOn`, update them
                        // 现在我们已经将`status`和`destroyedOn`的存储位置清零了，对其进行更新
                        or(
                            // Create 5-byte timestamp and shift into byte positions 6-11 with a bit shift
                            // 创建5字节的时间戳记，并将其移位到6-11个字节位置
                            shl(48, and(timestamp, 0xffffffffff)),
                            // Combine with the new note status (masked to a uint8)
                            // 结合新的 note 状态（掩盖为uint8）
                            and(noteStatusNew, 0xff)
                        )
                    )
                )
            }
        // Check that the note status is UNSPENT
        require(noteStatusOld == uint256(NoteStatus.UNSPENT), "input note status is not UNSPENT");
        // Check that the note owner is the expected owner
        require(storedNoteOwner == _noteOwner, "input note owner does not match");
    }

    function makeAvailable() public {}
}
