pragma solidity >=0.5.0 <0.6.0;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";

import "../../../interfaces/IAZTEC.sol";

/**
 * @title NoteRegistryBehaviour interface which defines the base API
        which must be implemented for every behaviour contract.
 * @author AZTEC
 * @dev This interface will mostly be used by ACE, in order to have an API to
        interact with note registries through proxies.
 * The implementation of all write methods should have an onlyOwner modifier.
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
// 定义 票决note注册表行为 合约
//
// TODO 主要是, 定义存储合约的接口，根据不同版本有多种实现

contract NoteRegistryBehaviour is Ownable, IAZTEC {
    using SafeMath for uint256;

    // 是否是 活动的行为
    bool public isActiveBehaviour;

    // 票据注册表是否已经初始化 标识
    bool public initialised;

    // 属于谁发起的 note注册, 存 msg.sender
    address public dataLocation;

    constructor () Ownable() public {
        // 初始化时, 是激活的
        isActiveBehaviour = true;
    }

    /**
        * @dev Initialises the data of a noteRegistry. Should be called exactly once.
        *
        * @param _newOwner - the address which the initialise call will transfer ownership to
        * @param _scalingFactor - defines the number of tokens that an AZTEC note value of 1 maps to.
        * @param _canAdjustSupply - whether the noteRegistry can make use of minting and burning
        * @param _canConvert - whether the noteRegistry can transfer value from private to public
            representation and vice versa
    */
    // 初始化noteRegistry的数据。 应该只调用一次
    // _newOwner: 初始化调用将 交易所有权转的地址, (权限控制的 某个以太坊地址)
    // _scalingFactor: 定义 一个 AZTEC note 值 兑换多少令牌数量 的比例 
    // _canAdjustSupply: noteRegistry 是否可以使用 mint 和 burn
    // _canConvert: noteRegistry 是否可以将价值从 private 转移到 public，反之亦然 
    function initialise(
        address _newOwner,
        uint256 _scalingFactor,
        bool _canAdjustSupply,
        bool _canConvert
    ) public;

    /**
        * @dev Fetches data of the registry
        *
        * @return scalingFactor - defines the number of tokens that an AZTEC note value of 1 maps to.
        * @return confidentialTotalMinted - the hash of the AZTEC note representing the total amount
            which has been minted.
        * @return confidentialTotalBurned - the hash of the AZTEC note representing the total amount
            which has been burned.
        * @return canConvert - the boolean whih defines if the noteRegistry can convert between
            public and private.
        * @return canConvert - the boolean whih defines if the noteRegistry can make use of
            minting and burning methods.
    */
    // 获取注册表数据
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
    );

    /**
        * @dev Enacts the state modifications needed given a successfully validated burn proof
        *
        * @param _proofOutputs - the output of the burn validator
    */
    // 在成功验证烧伤证明后执行所需的状态修改
    // _proofOutputs: burn 验证器的输出
    function burn(bytes memory _proofOutputs) public;

    /**
        * @dev Enacts the state modifications needed given a successfully validated mint proof
        *
        * @param _proofOutputs - the output of the mint validator
    */
    // 通过成功验证的 mint 证明，实施所需的状态修改
    // _proofOutputs: mint 验证器的 output
    function mint(bytes memory _proofOutputs) public;

    /**
        * @dev Enacts the state modifications needed given the output of a successfully validated proof.
        * The _proofId param is used by the behaviour contract to (if needed) restrict the versions of proofs
        * which the note registry supports, useful in case the proofOutputs schema changes for example.
        *
        * @param _proof - the id of the proof
        * @param _proofOutput - the output of the proof validator
        *
        * @return publicOwner - the non-ACE party involved in this transaction. Either current or desired
        *   owner of public tokens
        * @return transferValue - the total public token value to transfer. Seperate value to abstract
        *   away scaling factors in first version of AZTEC
        * @return publicValue - the kPublic value to be used in zero-knowledge proofs
    */
    // 根据已成功 验证的输出 (_proofOutputs) ，执行所需的状态修改.
    // 行为合同使用 _proofId 参数来（如果需要）限制 note 注册表支持的 proof版本，
    // 例如，在proofOutputs模式发生更改时很有用.
    //
    function updateNoteRegistry(
        uint24 _proof,
        bytes memory _proofOutput
    ) public returns (
        address publicOwner,
        uint256 transferValue,
        int256 publicValue
    );

    /**
        * @dev Sets confidentialTotalMinted to a new value. The value must be the hash of a note;
        *
        * @param _newTotalNoteHash - the hash of the note representing the total minted value for an asset.
    */
    // 将secretTotalMinted设置为新值。 该值必须是 note 的Hash
    // _newTotalNoteHash: 表示资产总 铸造 价值的 note Hash
    function setConfidentialTotalMinted(bytes32 _newTotalNoteHash) internal returns (bytes32);

    /**
        * @dev Sets confidentialTotalBurned to a new value. The value must be the hash of a note;
        *
        * @param _newTotalNoteHash - the hash of the note representing the total burned value for an asset.
    */
    // 将secretTotalBurned设置为新值。 该值必须是 note 的Hash
    // _newTotalNoteHash: 表示资产总 燃烧 价值的 note Hash
    function setConfidentialTotalBurned(bytes32 _newTotalNoteHash) internal returns (bytes32);

    /**
        * @dev Gets a defined note from the note registry, and returns the deconstructed object.
            This is to avoid the interface to be
        * _too_ opninated on types, even though it does require any subsequent note type to have
            (or be able to mock) the return fields.
        *
        * @param _noteHash - the hash of the note being fetched
        *
        * @return status - whether a note has been spent or not
        * @return createdOn - timestamp of the creation time of the note
        * @return destroyedOn - timestamp of the time the note was destroyed (if it has been destroyed, 0 otherwise)
        * @return noteOwner - address of the stored owner of the note
    */
    function getNote(bytes32 _noteHash) public view returns (
        uint8 status,
        uint40 createdOn,
        uint40 destroyedOn,
        address noteOwner
    );

    /**
        * @dev Internal function to update the noteRegistry given a bytes array.
        *
        * @param _inputNotes - a bytes array containing notes
    */
    // 给定字节数组的内部函数更新noteRegistry
    // _inputNotes: 一组 UTXO的 input 的 note
    function updateInputNotes(bytes memory _inputNotes) internal;

    /**
        * @dev Internal function to update the noteRegistry given a bytes array.
        *
        * @param _outputNotes - a bytes array containing notes
    */
    // 给定字节数组的内部函数更新noteRegistry
    // _outputNotes: 一组 UTXO的 output 的 note
    function updateOutputNotes(bytes memory _outputNotes) internal;

    /**
        * @dev Internal function to create a new note object.
        *
        * @param _noteHash - the noteHash
        * @param _noteOwner - the address of the owner of the note
    */
    // 内部函数创建一个新的笔记对象
    // _noteHash: 一个 note 的Hash
    // _noteOwner: 该 note 对应的 owner (一个 以太坊地址)
    function createNote(bytes32 _noteHash, address _noteOwner) internal;

    /**
        * @dev Internal function to delete a note object.
        *
        * @param _noteHash - the noteHash
        * @param _noteOwner - the address of the owner of the note
    */
    // 内部功能删除 note 对象
    // _noteHash: 一个 note 的Hash
    // _noteOwner: 该 note 对应的 owner (一个 以太坊地址)
    function deleteNote(bytes32 _noteHash, address _noteOwner) internal;

    /**
        * @dev Public function used during slow release phase to manually enable an asset.
    */
    function makeAvailable() public;
}
