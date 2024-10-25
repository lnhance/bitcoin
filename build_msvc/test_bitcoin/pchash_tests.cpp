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

BOOST_FIXTURE_TEST_SUITE(pchash_tests, BasicTestingSetup)

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_from_data)
{
    //UniValue tests = read_json(std::string(json_tests::pchash));

    std::string s1 = "Hello ";
    std::string s2 = "World!";
    std::vector<unsigned char> x1(s1.begin(), s1.end());
    std::vector<unsigned char> x2(s2.begin(), s2.end());

    uint256 hash = PairCommitHash(x1, x2);

    BOOST_ERROR(HexStr(hash));
}
BOOST_AUTO_TEST_SUITE_END()
