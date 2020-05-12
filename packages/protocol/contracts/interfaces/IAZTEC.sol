pragma solidity >=0.5.0 <0.6.0;

/**
 * @title IAZTEC
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
contract IAZTEC {

    // 定义了 proof种类的 枚举类型
    enum ProofCategory {
        NULL,// 一个 空证明 ? 默认 0
        BALANCED, // 满足 joinsplit 类型的证明, ACE.validateProof() 中用到  默认 1
        MINT, // token 转成 加密币  默认 2
        BURN, // 加密币 转成 token  默认 3
        UTILITY //       默认 4
    }

    // 定义了 票据note状态的 枚举类型
    enum NoteStatus {
        DOES_NOT_EXIST, // 票据不存在
        UNSPENT, // 票据未花费
        SPENT // 票据已花费
    }
    // proofEpoch = 1 | proofCategory = 1 | proofId = 1
    // 1 * 256**(2) + 1 * 256**(1) ++ 1 * 256**(0)
    uint24 public constant JOIN_SPLIT_PROOF = 65793;  // 表示 joinsplit 动作的proof

    // proofEpoch = 1 | proofCategory = 2 | proofId = 1
    // (1 * 256**(2)) + (2 * 256**(1)) + (1 * 256**(0))
    uint24 public constant MINT_PROOF = 66049;        // 表示 mint 动作的proof

    // proofEpoch = 1 | proofCategory = 3 | proofId = 1
    // (1 * 256**(2)) + (3 * 256**(1)) + (1 * 256**(0))
    uint24 public constant BURN_PROOF = 66305;        // 表示 burn 动作的proof

    // proofEpoch = 1 | proofCategory = 4 | proofId = 2
    // (1 * 256**(2)) + (4 * 256**(1)) + (2 * 256**(0))
    uint24 public constant PRIVATE_RANGE_PROOF = 66562;  // 表示 private range 动作的proof

        // proofEpoch = 1 | proofCategory = 4 | proofId = 3
    // (1 * 256**(2)) + (4 * 256**(1)) + (2 * 256**(0))
    uint24 public constant PUBLIC_RANGE_PROOF = 66563;    // 表示 public range 动作的proof

    // proofEpoch = 1 | proofCategory = 4 | proofId = 1
    // (1 * 256**(2)) + (4 * 256**(1)) + (2 * 256**(0))
    uint24 public constant DIVIDEND_PROOF = 66561;       // 表示 dividend 动作的proof
}
