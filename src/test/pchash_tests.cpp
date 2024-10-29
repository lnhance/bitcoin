// Copyright (c) 2013-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <addresstype.h>
#include <validation.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <common/system.h>
#include <random.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

namespace {
    typedef std::vector<unsigned char> valtype;
    typedef Span<const unsigned char> Raw;

    static const unsigned char test1_expected_result[32] = {
        0x57, 0xaf, 0x85, 0x35, 0xe7, 0x7b, 0xee, 0x32,
        0xc3, 0x16, 0x84, 0xec, 0x4b, 0x58, 0x61, 0x55,
        0xd2, 0x6a, 0xff, 0x07, 0x7d, 0xc6, 0xf7, 0xd7,
        0x95, 0x4a, 0x51, 0xc8, 0x62, 0x0a, 0xff, 0xcc
    };

    static const unsigned char test2_expected_result[32] = {
        0xd3, 0xed, 0x6d, 0x42, 0x4f, 0x70, 0xb3, 0x19,
        0x4c, 0x20, 0x0c, 0x0c, 0xb1, 0x9c, 0xaf, 0xbb,
        0x2b, 0xc1, 0x2e, 0xcf, 0x8d, 0x4c, 0x00, 0x0b,
        0x9e, 0x1c, 0x1e, 0x28, 0x3b, 0xdc, 0xb8, 0x59    
    };
}

BOOST_FIXTURE_TEST_SUITE(pchash_tests, BasicTestingSetup)

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_from_data)
{
    uint256 hash1 = PairCommitHash(
        // "Hello "
        valtype{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20},
        // "World!"
        valtype{0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21}
    );
    BOOST_CHECK_EQUAL(hash1, uint256(test1_expected_result));

    uint256 hash2 = PairCommitHash(
        // "Hello"
        valtype{0x48, 0x65, 0x6c, 0x6c, 0x6f},
        // " World!"
        valtype{0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21}
    );
    BOOST_CHECK_EQUAL(hash2, uint256(test2_expected_result));
}

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_reproduce)
{
    // pc_tag_hash = SHA256("PairCommit")
    uint256 pc_tag_hash;
    std::string pc_tag = "PairCommit";
    CSHA256().Write((const unsigned char*)pc_tag.data(), pc_tag.size()).Finalize(pc_tag_hash.begin());

    // "Hello "
    const valtype x1 = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20};
    // "World!"
    const valtype x2 = {0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    // uint32_t(6) in little endian serilaization
    const valtype x1_size = {0x06, 0x00, 0x00, 0x00};
    // uint32_t(6) in little endian serilaization
    const valtype x2_size = {0x06, 0x00, 0x00, 0x00};
    // uint32_t(0x01000000u) in little endian serilaization
    const valtype padding = {0x00, 0x00, 0x00, 0x01};

    uint256 hash1 = PairCommitHash(x1, x2);

    HashWriter ss;
    ss << Raw{pc_tag_hash}
       << Raw{pc_tag_hash}
       << Raw{x1}
       << Raw{x2}
       << Raw(x1_size)
       << Raw(padding)
       << Raw(x2_size)
       << Raw(padding);

    uint256 hash2 = ss.GetSHA256();

    BOOST_CHECK_EQUAL(hash1, hash2);
}

// Goal: check that OP_PAIRCOMMIT behaves as expected in script
BOOST_AUTO_TEST_CASE(pchash_tapscript)
{
    // "Hello "
    const valtype x1 = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20};
    // "World!"
    const valtype x2 = {0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};

    // <x1> <x2> OP_PAIRCOMMIT <test1_expected_result> OP_EQUAL
    CScript script;
    script << ToByteVector(x1);
    script << ToByteVector(x2);
    script << OP_PAIRCOMMIT;
    script << ToByteVector(uint256{test1_expected_result});
    script << OP_EQUAL;

    auto witVerifyScript = ToByteVector(script);

    // Build a taproot address...
    XOnlyPubKey key_inner{ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")};
    TaprootBuilder builder;
    builder.Add(/*depth=*/0, witVerifyScript, TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
    builder.Finalize(XOnlyPubKey(key_inner));

    CScriptWitness witness;
    //witness.stack.insert(witness.stack.begin(), witData.begin(), witData.end());
    witness.stack.push_back(witVerifyScript);
    auto controlblock = *(builder.GetSpendData().scripts[{witVerifyScript, TAPROOT_LEAF_TAPSCRIPT}].begin());
    witness.stack.push_back(controlblock);

    uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_LNHANCE;
    CScript scriptPubKey = CScript() << OP_1 << ToByteVector(builder.GetOutput());

    CMutableTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = scriptPubKey;
    txFrom.vout[0].nValue = 10000;

    CMutableTransaction txTo;
    txTo.vin.resize(1);
    txTo.vin[0].prevout.n = 0;
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].scriptWitness = witness;

    PrecomputedTransactionData txdata(txTo);

    bool ok = CScriptCheck(txFrom.vout[0], CTransaction(txTo), 0, flags, false, &txdata)();

    BOOST_CHECK(ok);
}

BOOST_AUTO_TEST_SUITE_END()
