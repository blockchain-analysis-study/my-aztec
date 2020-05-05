pragma solidity >=0.5.0 <0.6.0;

import "../../../interfaces/NoteRegistryFactory.sol";
import "./BehaviourAdjustable201907.sol";

/**
 * @title FactoryAdjustable201907
 * @author AZTEC
 * @dev Deploys a BehaviourAdjustable201907
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
 // 这是 Adjust 合约工厂合约实例
contract FactoryAdjustable201907 is NoteRegistryFactory {
    // 将 _aceAddress 传递给 NoteRegistryFactory合约构造器
    constructor(address _aceAddress) public NoteRegistryFactory(_aceAddress) {}

    // 通过当前 工厂, 部署一个 行为合约
    function deployNewBehaviourInstance()
        public
        onlyOwner
        returns (address)
    {
        BehaviourAdjustable201907 behaviourContract = new BehaviourAdjustable201907();
        emit NoteRegistryDeployed(address(behaviourContract));
        return address(behaviourContract);
    }
}
