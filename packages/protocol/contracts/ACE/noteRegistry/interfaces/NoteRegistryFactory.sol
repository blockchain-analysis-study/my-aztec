pragma solidity >=0.5.0 <0.6.0;

import "openzeppelin-solidity/contracts/token/ERC20/ERC20.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";

import "../../../interfaces/IAZTEC.sol";
import "../../../interfaces/ProxyAdmin.sol";

/**
 * @title NoteRegistryFactory
 * @author AZTEC
 * @dev Interface definition for factories. Factory contracts have the responsibility of managing the full lifecycle of
 * Behaviour contracts, from deploy to eventual upgrade. They are owned by ACE, and all methods should only be callable
 * by ACE.
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
 // NoteRegistry 的 工厂
 //
contract NoteRegistryFactory is IAZTEC, Ownable  {
    event NoteRegistryDeployed(address behaviourContract);

    constructor(address _aceAddress) public Ownable() {
        // 这个 address 只是为了设置 交易所有权的
        transferOwnership(_aceAddress);
    }

    function deployNewBehaviourInstance() public returns (address);

    // 切换行为
    //
    // 变更 一个新的admin地址 ： _newProxyAdmin
    // 变更 一个新的实现合约地址 ：_newImplementation
    function handoverBehaviour(address _proxy, address _newImplementation, address _newProxyAdmin) public onlyOwner {
        // 先检查下就有的 admin地址, 该方法只有就有的 admin 合约可以调用
        require(ProxyAdmin(_proxy).admin() == address(this), "this is not the admin of the proxy");
        
        // 更新相关合约的地址
        ProxyAdmin(_proxy).upgradeTo(_newImplementation);
        // 将 _newProxyAdmin 替换 _proxy
        ProxyAdmin(_proxy).changeAdmin(_newProxyAdmin);
    }
}
