/* global artifacts */
const bn128 = require('@aztec/bn128');

const ACE = artifacts.require('./ACE.sol');

module.exports = (deployer) => {

    // 第二步, 部署 ACE 合约
    return deployer.deploy(ACE).then(async (ace) => {

        // 设置, 范围证明需要用的 信赖系统资料库
        await ace.setCommonReferenceString(bn128.CRS);
    });
};
