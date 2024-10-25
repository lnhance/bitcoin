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

//UniValue read_json(const std::string& jsondata);

namespace {
    /* uint32_t hash function using primes 0x3B9ACA07 multiplier and 0x7FFFFFFF modulo
     * expected to change on average ~16 bits in output for a single bit change in input */
    __inline uint32_t uint32_t_hash_x3B9ACA07(const uint32_t& i)
    {
        static const uint64_t p = 0x3B9ACA07;
        static const uint32_t m = 0x7FFFFFFF;

        return (p * i) % m;
    }

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

    static const unsigned char test1_expected_result[32] = {
        0x2c, 0x0f, 0x61, 0x16, 0x38, 0x0d, 0x49, 0xe1,
        0x5c, 0xf3, 0x08, 0x2c, 0x55, 0x25, 0x83, 0xed,
        0x8b, 0xf3, 0x83, 0x41, 0xd9, 0xe1, 0xd3, 0x25,
        0x27, 0xae, 0xe5, 0x68, 0x23, 0x4f, 0xf0, 0x94
    };

    TestVector test1 = TestVector("Hello ", "World!");

    static const unsigned char test2_expected_result[32] = {
        0xc2, 0x14, 0x85, 0xf3, 0x1c, 0x45, 0x9c, 0x61,
        0x29, 0xd8, 0xdd, 0xd6, 0x5e, 0x59, 0x09, 0x40,
        0x61, 0xcb, 0xf9, 0x2c, 0x41, 0xcc, 0x76, 0x48,
        0x7b, 0x77, 0x93, 0x8f, 0x3f, 0x3e, 0x0e, 0xd9        
    };

    TestVector test2 = TestVector("Hello", " World!");

    void RunTest(const TestVector& test, uint256 expected_result)
    {
        BOOST_CHECK_EQUAL(test.hash, uint256(expected_result));
    }
}

BOOST_FIXTURE_TEST_SUITE(pchash_tests, BasicTestingSetup)

// Goal: check that uint32_t_hash_x3B9ACA07 generate expected hashes
BOOST_AUTO_TEST_CASE(hash_x3B9ACA07)
{
    BOOST_CHECK_EQUAL(0x00000000, uint32_t_hash_x3B9ACA07(0));
    BOOST_CHECK_EQUAL(0x3B9ACA07, uint32_t_hash_x3B9ACA07(1));
    BOOST_CHECK_EQUAL(0x7735940E, uint32_t_hash_x3B9ACA07(2));
    BOOST_CHECK_EQUAL(0x32D05E16, uint32_t_hash_x3B9ACA07(3));
    BOOST_CHECK_EQUAL(0x6E6B281D, uint32_t_hash_x3B9ACA07(4));
    BOOST_CHECK_EQUAL(0x2A05F225, uint32_t_hash_x3B9ACA07(5));
    BOOST_CHECK_EQUAL(0x65A0BC2C, uint32_t_hash_x3B9ACA07(6));
    BOOST_CHECK_EQUAL(0x735940EE, uint32_t_hash_x3B9ACA07(32));
    BOOST_CHECK_EQUAL(0x126A5F2A, uint32_t_hash_x3B9ACA07(520));
}

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_from_data)
{
    //UniValue tests = read_json(std::string(json_tests::pchash));

    RunTest(test1, uint256(test1_expected_result));

    RunTest(test2, uint256(test2_expected_result));
}
BOOST_AUTO_TEST_SUITE_END()
