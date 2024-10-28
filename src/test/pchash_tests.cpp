// Copyright (c) 2013-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <common/system.h>
#include <random.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

namespace {
    typedef std::vector<unsigned char> valtype;

    // SHA256("PairCommit")
    static const unsigned char pc_tag_hash[32] = {
        0x08, 0x20, 0x7e, 0x7c, 0x41, 0xc4, 0x78, 0x33,
        0xaa, 0x39, 0x74, 0x77, 0xdf, 0x01, 0xc9, 0xde,
        0xb0, 0x26, 0xa8, 0xfe, 0x8d, 0x9b, 0xe5, 0xa9,
        0x8f, 0x4a, 0x36, 0x4f, 0x39, 0x19, 0x93, 0xc9
    };

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
        valtype{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20},
        valtype{0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21}
    );
    BOOST_CHECK_EQUAL(hash1, uint256(test1_expected_result));


    uint256 hash2 = PairCommitHash(
        valtype{0x48, 0x65, 0x6c, 0x6c, 0x6f},
        valtype{0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21}
    );
    BOOST_CHECK_EQUAL(hash2, uint256(test2_expected_result));
}

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_reproduce)
{
    const valtype x1 = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20};
    const valtype x2 = {0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};

    HashWriter ss;
    ss << uint256{pc_tag_hash}
       << uint256{pc_tag_hash}
       << Span<const unsigned char>{x1.data(), x1.size()}
       << Span<const unsigned char>{x2.data(), x2.size()}
       << uint32_t(x1.size())
       << uint32_t(0x01000000)
       << uint32_t(x2.size())
       << uint32_t(0x01000000);

    uint256 check1 = ss.GetSHA256();
    uint256 check2 = PairCommitHash(x1, x2);

    BOOST_CHECK_EQUAL(check1, check2);
}

BOOST_AUTO_TEST_SUITE_END()
