// Copyright (c) 2023 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <crypto/equihash.h>
#include <consensus/merkle.h>
#include <util/system.h>
#include <version.h>

#include <sodium.h>

#include <mutex>

static bool CheckProofOfWork(uint256 hash, unsigned int nBits, uint256 powLimit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

void SolveEquihashGenesis(CBlock& block, uint256 powLimit)
{
    block.hashMerkleRoot = BlockMerkleRoot(block);

    unsigned int n = 200;
    unsigned int k = 9;

    // Initialize state
    crypto_generichash_blake2b_state eh_state;
    EhInitialiseState(n, k, eh_state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{block};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;

    // H(I||...
    crypto_generichash_blake2b_update(&eh_state, (unsigned char*)&ss[0], ss.size());

    while (true)
    {
        block.nNonce = ArithToUint256(UintToArith256(block.nNonce) + 1);

        // H(I||V||...
        crypto_generichash_blake2b_state curr_state(eh_state);
        crypto_generichash_blake2b_update(&curr_state,
                                      block.nNonce.begin(),
                                      block.nNonce.size());

        // (x_1, x_2, ...) = A(I, V, n, k)
        std::function<bool(std::vector<unsigned char>)> validBlock =
            [&block, powLimit](std::vector<unsigned char> soln) {
                block.nSolution = soln;
                return CheckProofOfWork(block.GetHash(), block.nBits, powLimit);
        };

        std::mutex m_cs;
        bool cancelSolver = false;
        std::function<bool(EhSolverCancelCheck)> cancelled = [&m_cs, &cancelSolver](EhSolverCancelCheck pos) {
                std::lock_guard<std::mutex> lock{m_cs};
                return cancelSolver;
        };

        if (EhOptimisedSolve(n, k, curr_state, validBlock, cancelled)) {
                goto endloop;
        }
    }
endloop:

    // genesis block solved
    LogPrintf("%s\n", block.ToString().c_str());
    LogPrintf("%s\n", block.nNonce.ToString().c_str());
    LogPrintf("%s\n", HexStr(block.nSolution));

    return;
}
