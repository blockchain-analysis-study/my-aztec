pragma solidity >=0.5.0 <0.6.0;

/**
 * @title IZkAsset
 * @author AZTEC
 * @dev An interface defining the ZkAsset standard
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

// 定义ZkAsset标准的接口
// 
interface IZkAsset {

    /**
     * @dev Note owner can approve a third party address, such as a smart contract,
     * to spend multiple notes on their behalf. This allows a batch approval of notes
     * to be performed, rather than individually for each note via confidentialApprove().
     *
    * @param _proofId - data of proof
     * @param _proofOutputs - data of proof
     * @param _spender - address being approved to spend the notes
     * @param _approval - bool (true if approving, false if revoking)
     * @param _proofSignature - ECDSA signature over the proof, approving it to be spent
     */
     //
     // note 所有者可以 批准第三方地址（例如智能合约）来代表他们花费多个 note。 
     // 这允许对 notes 进行批处理批准，而不是通过 confidentialApprove()方法 对每个 note 进行单独批准。
     //
     // _proofId: proof的Id
     // _proofOutputs: 该proof参与生成的 proofOutput (里面含有 input 和 output)
     // _spender: 地址被批准用于花费 notes
     // _approval: bool（如果批准，则为true，如果撤消，则为false）
     // _proofSignature: ECDSA在证据上签名，批准将其花费
    function approveProof(
        uint24 _proofId,
        bytes calldata _proofOutputs,
        address _spender,
        bool _approval,
        bytes calldata _proofSignature
    ) external;

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
    //
    // note所有者批准第三方（另一个地址）代表所有者花费notes. 
    // 这是允许调用 confidentialTransferFrom() 方法的必要条件.
    //
    // _noteHash: note坐标的keccak256 hash (gamma and sigma)
    //             请参考 Behaviuor201907中的registry.notes 和 NoteUtils的 extractNote()
    // _spender: 地址被批准用于花费 note
    // _spenderApproval: 定义是否批准_spender地址用于花费 note，或者是否撤消权限。
    //                   如果批准则为 true，否则为false
    // _signature: 来自 note 所有者的ECDSA签名，用于验证 confidentialApprove() 指令
    function confidentialApprove(
        bytes32 _noteHash,
        address _spender,
        bool _spenderApproval,
        bytes calldata _signature
    ) external;

    /**
    * @dev Executes a value transfer mediated by smart contracts. The method is supplied with
    * transfer instructions represented by a bytes _proofOutput argument that was outputted
    * from a proof verification contract.
    *
    * @param _proof - uint24 variable which acts as a unique identifier for the proof which
    * _proofOutput is being submitted. _proof contains three concatenated uint8 variables:
    * 1) epoch number 2) category number 3) ID number for the proof
    * @param _proofOutput - output of a zero-knowledge proof validation contract. Represents
    * transfer instructions for the ACE
    */
    //
    // 执行以智能合约为中介的价值转移。 
    // 该方法提供有transfer指令，该transfer指令由从 [证明验证合约] 输出的字节_proofOutput 来表示
    //
    // _proof: uint24变量，用作 提交_proofOutput的证明的唯一标识符。 _proof包含三个串联的uint8变量：
    //          1）epoch 2）category 3）proofId
    // _proofOutput: 零知识证明验证合同的输出。 代表ACE的转移说明 (内含有 N个 inputs 和 M个outputs 及一些其他信息)
    function confidentialTransferFrom(uint24 _proof, bytes calldata _proofOutput) external;


    /**
    * @dev Executes a basic unilateral, confidential transfer of AZTEC notes
    * Will submit _proofData to the validateProof() function of the Cryptography Engine.
    *
    * Upon successfull verification, it will update note registry state - creating output notes and
    * destroying input notes.
    *
    * @param _proofData - bytes variable outputted from a proof verification contract, representing
    * transfer instructions for the ACE
    * @param _signatures - array of the ECDSA signatures over all inputNotes
    */
    //
    // 执行AZTEC note 的基本单方面 confidential transfer 将_proofData提交到 [密码引擎] 的 validateProof() 函数
    // 验证成功后，它将更新 【note注册表】 状态 - 创建 output notes 并销毁 input notes
    // 
    // TODO 这就是 一次 加密交易啊
    //
    // _proofData: 从 proof验证合约 中输出的字节变量，表示ACE的传输指令
    // _signatures: 所有 inputs上的ECDSA签名数组
    function confidentialTransfer(bytes calldata _proofData, bytes calldata _signatures) external;

    /**
    * @dev Executes a basic unilateral, confidential transfer of AZTEC notes
    * Will submit _proofData to the validateProof() function of the Cryptography Engine.
    *
    * Upon successfull verification, it will update note registry state - creating output notes and
    * destroying input notes.
    *
    * @param _proofId - id of proof to be validated. Needs to be a balanced proof.
    * @param _proofData - bytes variable outputted from a proof verification contract, representing
    * transfer instructions for the ACE
    * @param _signatures - array of the ECDSA signatures over all inputNotes
    */
    //
    // 重载 加了 proofId 参数入参
    // 
    function confidentialTransfer(uint24 _proofId, bytes calldata _proofData, bytes calldata _signatures) external;

    /**
    * @dev Update the metadata of a note that already exists in storage.
    * @param noteHash - hash of a note, used as a unique identifier for the note
    * @param metaData - metadata to update the note with
    */
    //
    // 更新存储中已存在的 note 的元数据
    // noteHash: note的哈希，用作note的唯一标识符
    // metaData: 元数据来更新 note
    function updateNoteMetaData(bytes32 noteHash, bytes calldata metaData) external;

    event CreateZkAsset(
        address indexed aceAddress,
        address indexed linkedTokenAddress,
        uint256 scalingFactor,
        bool indexed _canAdjustSupply,
        bool _canConvert
    );

    event CreateNoteRegistry(uint256 noteRegistryId);

    event CreateNote(address indexed owner, bytes32 indexed noteHash, bytes metadata);

    event DestroyNote(address indexed owner, bytes32 indexed noteHash);

    event ConvertTokens(address indexed owner, uint256 value);

    event RedeemTokens(address indexed owner, uint256 value);

    event UpdateNoteMetaData(address indexed owner, bytes32 indexed noteHash, bytes metadata);
}
