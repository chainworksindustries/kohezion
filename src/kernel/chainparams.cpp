// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <arith_uint256.h>
#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <chainparamsbase.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

void SolveEquihashGenesis(CBlock& block, uint256 powLimit);

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "chainworks industries 17072023";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"), SCRIPT_VERIFY_NONE);
        consensus.script_flag_exceptions.emplace( // Taproot exception
            uint256S("0x0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"), SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.MinBIP9WarningHeight = 483840; // segwit activation height + miner confirmation window
        consensus.nEquihashN = 200;
        consensus.nEquihashK = 9;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 9 * 60;
        consensus.nPowTargetSpacing = 3 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPosTargetTimespan = 9 * 60;
        consensus.nPosTargetSpacing = 3 * 60;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 30;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].min_activation_height = 0; // No activation delay

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 709632; // Approximately November 12th, 2021

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xa3;
        pchMessageStart[1] = 0xa6;
        pchMessageStart[2] = 0xa9;
        pchMessageStart[3] = 0xa7;
        nDefaultPort = 3690;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 2;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(
            1689530550,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000002"),
            ParseHex("0033f5e2c310e9255dcc71d7e098392131c95014a11593eceeca145311108c54cc2d4715713f4712951f03c9fd8fd0a30fbbf72c272ea84e0fca4192722ce5148e46a260497d6bb0a593f70bbbd4322de3fc69f307565380966e0543ea05f3996b497086f7173deeb0333323cfec126c4ab216470f8a46fd42f85cbeed0310eb9ce51ce452013f8902ba5077f79dc443d8c911193e598d595b0f4f79995804466423d6d00dddee710ae7cecd1a2713399f8c28009a52db96a24d770155144928a92c98bddbf5ba03fb864a2be2b3f2b73b35102161288118fa8345b0b6443b38290327227a92b83ec13b9e4a980d5dab0e53ffd920f84d7d5656150917ad51190a13a359ac2c6245ae476997b3253dbc374436a75fe4e090d57530f454b2bc531eed51bf26e019e34ee91b51e182b75e57dbb3f27947ee7f1ffc8e325ec2441065448d6dd7d3746b6d2d8ce114dd9e9903273f3bb0d544f37b0559ac2ff1d5ab0e6c79b5fc55878ee9125d528119c826be3b40cab21dec7b9a3a03794be1d3c94153c70f58f7ac726aeeb6015adc3c0b22ef812ed7dc5fda9551e1afe74ef5251029c54d136094f5302116b99de4d2d48cfe51f5ee9af26b051b1d1e484cd341978497b40409ecd1d5c3085f92ea1e7a93ee8fc9b781669b43576aa02021b73d3ea1e622f5839f5d11a60b9703a88736553c93529f9d511f04a7c12605868aa0487d9bce46dfe74760f7bc0d251fc409578d56526de937b730b5cd4f8ecd529d43c910d56a6ad18902b52263d71793d7b74ef6be1e5688159d2c0da23a0ae3f955f28cb3400c68e046d10961051551b424ac6d19d36233e8b17eccda21daff2c9f0eecc093f6c9e7353e4123e81af2e65232d25ea95f0b2a3d75e3c4ba573d599136c762d9a4dae22ba4632edd66f8795f6381ca00546e09361241efe4102d3e009882fad04be7899ea84231649a6a9ceb45db3dd82b89c56a6f5e4fb3ab8c341c99da112f075fba6b7916d1e7a95c5f2e25935f92f5865f222248faf641c44ca67aad40df4025446118d82c53c3368ab53d7fb402c5392f025c23d303c254fd216f0f01d3de3a435309771e01f214f1e3b85e867dbfd0fd069e54f5a5c20f17d3deb2c460c683161528c62f035d52339879b91c3be77abd1334c3cb6cf2677cc8453158362e8c030a77c5245d50defd79a8b465366598f27029b7fdec0f4093a04022b8837c1bda438ff9c327dcf6dfab51116ecffb76925767ee1e85ff23b729119fde4dacfd635d04477222644551e7c63a1dee2e5644d5798ee2138395ec26d279c31385a25f846694090d56b5d7e431fe4b6515969086faf459e4a77f8686bfdb7cddae2aabae6221cc611c6437b350629e2bf91e8fab232a3196aa5698d8cc40d8caf9e26ad539173ac37ca2630ef8f96e47a7e10f50edc3987633835a473dbf37691c52b3d6668ca2179bad67e042dac44e90adffffdb178fabdf3a8dc2238f58c209c89c4eb9919e709d7521c92e0ece1542e3ea0ba698d95c70c601083afd082a32daefe294784dde8737ed96e6033e6ae1173c0a3ce3f641245f327b2f42c4a6bb5852313b390cc7a835e2e3b6961978c5cfaa748bcb7e272f5eb75d37233fea66c9ad576ad107675b81cfff3362e8d01bcafc19681d1c5606ff5c439d856949cd7b5985e479325620c1bfed50cd42455047f43badc6b9721d871285f51ca231bec1193bc1052491f384469936733653ec442e76963e2b5aa6c77db0b39502a6c379814ed6afc41cfa6a686758e887be8df3d3dff6fe810483ba94e31ebdfb9908945b00f788553dfb5287d710e978fb1229ca92c530a7271196bed6e0e768a0125e25532f5d3dade59f65944035647299247668bf667d39fddb79"),
            0x207fffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x693987735cd761e87f47c5b783a63264e2a546c20e2b796ad280a6a51f4cde58"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,191);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "khz";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {     0, genesis.GetHash()                                                             },
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
         // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 000000000000000000035c3f0d31e71a5ee24c5aaf3354689f65bd7b07dee632
            .nTime    = 1680665245,
            .nTxCount = 820876044,
            .dTxRate  = 3.672283614033389,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"), SCRIPT_VERIFY_NONE);
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.MinBIP9WarningHeight = 836640; // segwit activation height + miner confirmation window
        consensus.nEquihashN = 200;
        consensus.nEquihashK = 9;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 9 * 60;
        consensus.nPowTargetSpacing = 3 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPosTargetTimespan = 9 * 60;
        consensus.nPosTargetSpacing = 3 * 60;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 30;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].min_activation_height = 0; // No activation delay

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xd5;
        pchMessageStart[1] = 0x1f;
        pchMessageStart[2] = 0x35;
        pchMessageStart[3] = 0x29;
        nDefaultPort = 48932;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 2;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(
            1689530551,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000001"),
            ParseHex("0027eee91243f39a436b516dd93cbeaea2ffd57d4220cc96753d0dd4bbfd46225aaf79dc3235d578a597032d9a0fb17256c3e45a153709f0440f707edb8a4a395d94cddd1061e5d4c5957b4168e422cf8a19b72e0dcd727d415d363bcf1f420674eb84a6d1dd79d5e817b70d396f1e7a130ad251ced5aa61f0f4497b9da522964f01461a0895ac757233e2428bedb19b4e81f5360447ebb216bd6ec2f273d9b1c1dfab2931998856007f570c925b78c1d105d1bf9dda5d1d56568bb23f1973615a3c08356caf6b91d06074a6b2f6fd597b8e06726880503c9687fccfc41ad0ad431a990df8bb831f2b1b9646cdd71f8ff272c520e77e6e28f017905e0d55948d9148472b16f1b15212f8bcad7ec276f15d14fa12c9b8f003f5c4b405aa897eff15a2457c8bbb1ca8026efe16841d1dbf24d6623e8de27e28dc1dc6b0b56dfa15b965e9e5498be4a6fd5607373b5caaae03527af15c9f52511468f079aae685653ab77b3cfd403fc6266b531991607e37d6e3ef2f870c7abe9c6f0ba03bc67b5d1083dcd8b260a561fb4d82015351394aa78d681cf0cdafbcd4c4d655e2183b26d63c0d6505f436386f52ec17bc7a146e52f5812a6ce77b220e15aa0d13f488f2eff5774582323a44b5e7105b72aa1cbf5b0ba295105dfc7b021559597439713b2d3e872b9f46270fcec4e34ba6538b46f37e09107b51b93e044a8ddf2891168baad89186ae64ccd2a1f2b83856059cffdc019a9274e3ae660343d7e8d5d42bbde3ca0b95e45c1ecf3f0fedd0d2f3beecb4a4f43c2813e61a2dd139d75200f6da48a5b0d357692e09b0d96db306f83fe2664f5c011f2aa086555c065956d9ede8b82a0c0dad90d5ca8beb49f30a44c540af8f45fe16a90e0e9249a0613fc3927fa2d904267f49cf91fef71b382a57ff9adb60f3296113ab22b38f53d9bbdfb82a00f1239a3cca7bf2e67cd28149f393c1e26871addf1a284b1c9c18d5dff2bf22d2b26a17622ffd91dd8707b9a9268a4ee913a5fb85234d72ef25756052b6b60b5698ca9fc8bcedbd35c467c4c95015b9a1d9f74d080bb7a6bb88338e475e75f324c3d9de8e7e56c32b261f12b2a69be1ab452c15b9ff77f92d810cd2ac5b0b72fece900b74c1032ad1a87dfbe4754b3bdc79ee1e39c4b4bc29dfc3b8d58368901c8b3b6032bd6c900206a15a2546d74a5237751f757c8779d6f77b908106f820c2f329f519ee0805e01e5af5db55167f46590dfa0b8854089cb54ede44f7f2d38b475288dd142a4c27a64e1b9579052c3e85c5765318a21480172a5b093686cc6b2302b38ba5423620969538a55c469f140e95456d34486049d76493bb985c41598cf48cb4ae0afe2a68bd21bb15c3cb60eb5de18f01b80cb90cce161591773e18b1f2f8fe419deea44ff1bd97df24e502252cf7714f55c9253f82aa47d71dc99a3df3cf190413298e004362cb8a98d0ca899d85f4d0aa1465811b0c2103ec629cfdcf932235d34e04e1ac7fd792fb66c35ee8909be0d32aed571ec264ae9ac9739b79c305dedeb22e68720bb5cdd68879775332235f19567820e14f404c4e7c73128f57c6e8e67bb68f4e98ccd928b2f64e9b579cefd6fde3c1d44b14395567b276af5ab3de26bf5e9b5de45c177e1f6f5882fad99d006203b3806efa2216115a2ee868cef9fa6a3e47b921121f0fbda832f548a1c1ea4480a43aed05fc7437629f24472dbef3a349212ac1633e805605550df548b168601b664a9ed927b3f81cf6dc9aec5cc9f99319c974062523a13998641f10e06457486e74ef9f44bd29082090ad4ac8d323d8da5d885918639c6e9d999a17710a986b2c3d9c7e97419de53dd43cc3ede2255697c91da1c554af4d326746ecb2c83998abe3c75c3faef5"),
            0x207fffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x4174e3d2a0506092e2820b584abfb86a0a4fcd241b16046d48f19c65408c80ed"));

        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,78);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,193);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tkhz";

        //vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {     0, genesis.GetHash()                                                             },
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            // TODO to be specified in a future patch.
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000000000021bc50a89cde4870d4a81ffe0153b3c8de77b435a2fd3f6761
            .nTime    = 1681542696,
            .nTxCount = 65345929,
            .dTxRate  = 0.09855282814711661,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            vSeeds.emplace_back("seed.signet.bitcoin.sprovoost.nl.");

            // Hardcoded nodes can be removed once there are more DNS seeds
            vSeeds.emplace_back("178.128.221.177");
            vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
            consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 0000004429ef154f7e00b4f6b46bfbe2d2678ecd351d95bbfca437ab9a5b84ec
                .nTime    = 1681127428,
                .nTxCount = 2226359,
                .dTxRate  = 0.006424463050600656,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        strNetworkID = CBaseChainParams::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPosTargetTimespan = 5 * 60;
        consensus.nPosTargetSpacing = 1 * 60;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 30;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.nEquihashN = 200;
        consensus.nEquihashK = 9;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].min_activation_height = 0; // No activation delay

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        memcpy(pchMessageStart, hash.begin(), 4);

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1477641360,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001257"),
            ParseHex("000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce157"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        //vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.nEquihashN = 200;
        consensus.nEquihashK = 9;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.posLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPosTargetTimespan = 5 * 60;
        consensus.nPosTargetSpacing = 1 * 60;
        consensus.nStakeMinAge = 10 * 60;
        consensus.nStakeMaxAge = 60 * 60 * 24 * 30;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].min_activation_height = 0; // No activation delay

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateGenesisBlock(
            1477641360,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001257"),
            ParseHex("000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce157"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        //vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {     0, genesis.GetHash()                                                             },
            }
        };

        m_assumeutxo_data = MapAssumeutxo{
            {
                110,
                {AssumeutxoHash{uint256S("0x1ebbf5850204c0bdb15bf030f47c7fe91d45c44c712697e4509ba67adb01c618")}, 110},
            },
            {
                200,
                {AssumeutxoHash{uint256S("0x51c8d11d8b5c1de51543c579736e786aa2736206d1e11e627568029ce092cf62")}, 200},
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}
