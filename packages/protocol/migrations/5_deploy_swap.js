/* global artifacts */
const { proofs } = require('@aztec/dev-utils');

const ACE = artifacts.require('./ACE.sol');
const Swap = artifacts.require('./Swap.sol');
const SwapInterface = artifacts.require('./SwapInterface.sol');

Swap.abi = SwapInterface.abi;

module.exports = (deployer) => {

    // 第五步, 部署 票据(note) 交换Proof合约
    return deployer.deploy(Swap).then(async ({ address: swapAddress }) => {

        // 然后, 注册 note交换Proof至 ACE中
        const ace = await ACE.at(ACE.address);
        await ace.setProof(proofs.SWAP_PROOF, swapAddress);
    });
};
