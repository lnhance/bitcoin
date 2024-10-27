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
    struct TestVector {
        std::vector<unsigned char> x1;
        std::vector<unsigned char> x2;
        public: uint256 hash;
        uint256 check_result;

        TestVector(std::string s1, std::string s2)
        {
            x1 = std::vector<unsigned char>(s1.begin(), s1.end());
            x2 = std::vector<unsigned char>(s2.begin(), s2.end());

            hash = PairCommitHash(x1, x2);
        }
    };

    // SHA256("PariCommit")
    static const unsigned char pc_tag_hash[32] = {
        0x08, 0x20, 0x7e, 0x7c, 0x41, 0xc4, 0x78, 0x33,
        0xaa, 0x39, 0x74, 0x77, 0xdf, 0x01, 0xc9, 0xde,
        0xb0, 0x26, 0xa8, 0xfe, 0x8d, 0x9b, 0xe5, 0xa9,
        0x8f, 0x4a, 0x36, 0x4f, 0x39, 0x19, 0x93, 0xc9
    };

    static const unsigned char test1_expected_result[32] = {
        0x9b, 0xb3, 0x05, 0xa2, 0x0c, 0xc1, 0xc7, 0x30, 
        0xd2, 0xbc, 0x71, 0x3b, 0x6f, 0x79, 0x21, 0x1a, 
        0xc8, 0x7f, 0x5d, 0xdb, 0xfd, 0xa7, 0x44, 0xff, 
        0xfc, 0xdb, 0x96, 0xb9, 0xac, 0xb8, 0xc5, 0xfc
    };

    TestVector test1 = TestVector("Hello ", "World!");

    static const unsigned char test2_expected_result[32] = {
        0x4d, 0x82, 0x4b, 0x3c, 0x93, 0xd5, 0x2e, 0x26,
        0x32, 0x67, 0x99, 0x06, 0xe7, 0x89, 0xf1, 0xcc,
        0xb0, 0x39, 0xa9, 0xe8, 0x33, 0x91, 0x90, 0xc2,
        0x66, 0xd4, 0xe7, 0xe1, 0x33, 0x25, 0x9f, 0x50       
    };

    TestVector test2 = TestVector("Hello", " World!");

    void RunTest(const TestVector& test, uint256 expected_result)
    {
        BOOST_CHECK_EQUAL(test.hash, uint256(expected_result));
    }
}

BOOST_FIXTURE_TEST_SUITE(pchash_tests, BasicTestingSetup)

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_from_data)
{
    RunTest(test1, uint256(test1_expected_result));

    RunTest(test2, uint256(test2_expected_result));
}

// Goal: check that PC Hash Function generate correct hash
/*
BOOST_AUTO_TEST_CASE(pchash_reproduce)
{
    std::string s1 = "Hello ";
    std::string s2 = "World!";
    std::vector<unsigned char> x1(s1.begin(), s1.end());
    std::vector<unsigned char> x2(s2.begin(), s2.end());

    HashWriter ss;
    ss << pc_tag_hash
       << pc_tag_hash
       << x1
       << x2
       << uint32_t(6)
       << uint32_t(0x01000000)
       << uint32_t(6)
       << uint32_t(0x01000000);

    uint256 check1 = ss.GetSHA256();

    BOOST_CHECK_EQUAL(test1.hash, check1);
}
*/

BOOST_AUTO_TEST_SUITE_END()
