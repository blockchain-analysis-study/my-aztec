pragma solidity >=0.5.0 <= 0.6.0;

/**
 * @title MetaDataUtils
 * @author AZTEC
 * @dev Library of MetaData manipulation operations
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

library MetaDataUtils {


    /**
    * @dev Extract a single approved address from the metaData
    * @param metaData - metaData containing addresses according to the schema defined in x
    * @param addressPos - indexer for the desired address, the one to be extracted
    * @return desiredAddress - extracted address specified by the inputs to this function
    */

    // todo 从metaData中提取一个批准的地址 (根据 addr集的索引)
    //
    // 入参:
    //  metaData: note 的metaData
    //  addressPos: 被批准花费当前 note 的addr的索引
    //
    // 返参:
    //  desiredAddress: 对应索引的 被批准花费 该note 的addr

    function extractAddress(bytes memory metaData, uint256 addressPos) pure internal returns (address desiredAddress) {
        /**
        * Memory map of metaData. This is the ABI encoding of metaData, supplied by the client
        * The first word of any dynamic bytes array within this map, is the number of discrete elements in that 
        * bytes array. e.g. first word at 0xe1 is the number of approvedAddresses
        * 0x00 - 0x20 : length of metaData
        * 0x20 - 0x81 : ephemeral key
        * 0x81 - 0xa1 : approved addresses offset
        * 0xa1 - 0xc1 : encrypted view keys offset
        * 0xc1 - 0xe1 : app data offset
        * 0xe1 - L_addresses : approvedAddresses
        * (0xe1 + L_addresses) - (0xe1 + L_addresses + L_encryptedViewKeys) : encrypted view keys
        * (0xe1 + L_addresses + L_encryptedViewKeys) - (0xe1 + L_addresses + L_encryptedViewKeys + L_appData) : appData
        */


        // 在memory中的 metadata 的数据布局, 这是客户端提供的metaData的ABI编码
        // 此布局内  todo 任何动态字节数组的第一个字是该字节数组中离散元素的数量。
        //          todo 例如 0xe1处的第一个 word 是 approved addr的数量 (1 word == 32 byte)
        //
        //
        // 0x00 - 0x20 :  metaData 的总长度 (多少字节)                ------32byte
        // 0x20 - 0x81 :  ephemeral key (临时秘钥) todo 干嘛的???     ------32byte
        // 0x81 - 0xa1 :  被批准的 addr 集的起始位置                  ------32byte
        // 0xa1 - 0xc1 :  encrypted view key 集的起始位置 (用来查看 note 中的 金额的 view key, 但是不能花费其中的金额)
        // 0xc1 - 0xe1 :  app data 的起始位置, todo app的数据 ?
        // 0xe1 - L_addresses : 被批准的 addr 集 数据
        // (0xe1 + L_addresses) - (0xe1 + L_addresses + L_encryptedViewKeys) : encrypted view key 集 数据
        // (0xe1 + L_addresses + L_encryptedViewKeys) - (0xe1 + L_addresses + L_encryptedViewKeys + L_appData) : appData


        uint256 numAddresses;
        assembly {

            // TODO 为什么编译时取, numAddresses := mload(add(metaData, 0xe1)) ？？ 沃日
            numAddresses := mload(add(metaData, 0x20)) // todo 这不是取到  ephemeral key 了么?

            // 取出第j个 approved addr
            desiredAddress := mload(
                // todo 这里才是取的第j个地址的起始位置
                add(
                    // 开始去 第一个 approved addr 的起始位置
                    add(
                        metaData,

                        // 先越过 approved Addr 集处的第一个 word (approved addr 的数目)
                        add(0xe1, 0x20)  // go to the start of addresses, jump over first word
                    ),

                    // 索引, j * 32byte 得到第j个地址的偏移量
                    mul(addressPos, 0x20) // jump to the desired address
                )
            )
        }

        require(
            // todo 判断的 condition是对的, 但是 numAddress 取的不对吧??
            addressPos < numAddresses, 
            'addressPos out of bounds - addressPos must be less than the number of addresses to be approved'
        );
    }
}
