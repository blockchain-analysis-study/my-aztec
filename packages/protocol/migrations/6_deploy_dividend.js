/* global artifacts */
const { proofs } = require('@aztec/dev-utils');

const ACE = artifacts.require('./ACE.sol');
const Dividend = artifacts.require('./Dividend.sol');
const DividendInterface = artifacts.require('./DividendInterface.sol');

Dividend.abi = DividendInterface.abi;

module.exports = (deployer) => {

    // 第六步, 部署 转换note 输入和输出间的一个 倍数乘积的 公开值
    return deployer.deploy(Dividend).then(async ({ address: dividendAddress }) => {
        const ace = await ACE.at(ACE.address);
        await ace.setProof(proofs.DIVIDEND_PROOF, dividendAddress);
    });
};
