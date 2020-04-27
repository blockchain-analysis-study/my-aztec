/* global artifacts */
const { proofs } = require('@aztec/dev-utils');

const ACE = artifacts.require('./ACE.sol');
const JoinSplit = artifacts.require('./JoinSplit.sol');
const JoinSplitInterface = artifacts.require('./JoinSplitInterface.sol');

JoinSplit.abi = JoinSplitInterface.abi;

module.exports = (deployer) => {

    // 第三步, 部署 JoinSplit Proof 合约
    return deployer.deploy(JoinSplit).then(async ({ address: joinSplitAddress }) => {

        // 部署完成后, 将JoinSplit Proof 注册到 ACE 
        const ace = await ACE.at(ACE.address);
        await ace.setProof(proofs.JOIN_SPLIT_PROOF, joinSplitAddress);
    });
};
