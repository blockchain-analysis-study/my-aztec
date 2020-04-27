/* global artifacts */
const { proofs } = require('@aztec/dev-utils');

const ACE = artifacts.require('./ACE.sol');
const JoinSplitFluid = artifacts.require('./JoinSplitFluid.sol');
const JoinSplitFluidInterface = artifacts.require('./JoinSplitFluidInterface.sol');

JoinSplitFluid.abi = JoinSplitFluidInterface.abi;

module.exports = (deployer) => {

    // 第四步, 部署 JoinSplitFluid 合约
    return deployer.deploy(JoinSplitFluid).then(async ({ address: joinSplitFluidAddress }) => {
        
        // 部署完成后, 将 质押token转换成隐私币的Proof 和 销毁 隐私币转换成token的Proof
        const ace = await ACE.at(ACE.address);
        await ace.setProof(proofs.MINT_PROOF, joinSplitFluidAddress);
        await ace.setProof(proofs.BURN_PROOF, joinSplitFluidAddress);
    });
};
