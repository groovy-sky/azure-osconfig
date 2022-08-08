// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <memory>
#include <CommonUtils.h>
#include <Firewall.h>
#include <Mmi.h>
#include <vector>
#include <string>


namespace Tests
{
    // typedef GenericUtility<Rule> Utility;

    // class MockUtility : public Utility
    // {
    // public:
    //     MockUtility() = default;
    //     MockUtility(std::vector<Rule> rules) : Utility(), m_rules(rules) {}
    //     ~MockUtility() = default;

    //     void Add(const std::vector<Rule>& rules)
    //     {
    //         m_rules.insert(m_rules.end(), rules.begin(), rules.end());
    //     }

    //     void Remove(const Rule& rule)
    //     {
    //         m_rules.erase(std::remove(m_rules.begin(), m_rules.end(), rule), m_rules.end());
    //     }

    //     bool Check(const Rule& rule) const
    //     {
    //         return std::find(m_rules.begin(), m_rules.end(), rule) != m_rules.end();
    //     }

    //     std::string Hash() const override
    //     {
    //         return "abc123";
    //     }

    // private:
    //     std::vector<Rule> m_rules;
    // };

    class FirewallTests : public ::testing::Test
    {
    protected:
        // std::shared_ptr<FirewallModule<MockUtility>> m_firewall;

        void SetUp() override {
            // m_firewall = std::make_shared<FirewallModule<MockUtility>>(0);
        }

        void TearDown() override {
            // m_firewall.reset();
        }
    };

    TEST_F(FirewallTests, GetInfo)
    {
        const char* clientName = "test";
        MMI_JSON_STRING payload = nullptr;
        int payloadSizeBytes = 0;

        Firewall::GetInfo(clientName, &payload, &payloadSizeBytes);
        EXPECT_STREQ(payload, Firewall::MODULE_INFO.c_str());
        EXPECT_EQ(payloadSizeBytes, strlen(Firewall::MODULE_INFO.c_str()));
    }

    TEST_F(FirewallTests, GetFingerprint)
    {
        // const char* componentName = "firewall";
        // const char* objectName = "firewallFingerprint";
        // MMI_JSON_STRING payload = nullptr;
        // int payloadSizeBytes = 0;

        // m_firewall->Get(componentName, objectName, &payload, &payloadSizeBytes);
        // EXPECT_STREQ(payload, "");
        // EXPECT_EQ(payloadSizeBytes, 0);
    }

    TEST_F(FirewallTests, GetState)
    {
        // const char* componentName = "firewall";
        // const char* objectName = "firewallState";
        // MMI_JSON_STRING payload = nullptr;
        // int payloadSizeBytes = 0;

        // m_firewall->Get(componentName, objectName, &payload, &payloadSizeBytes);
        // EXPECT_STREQ(payload, "1");
        // EXPECT_EQ(payloadSizeBytes, strlen("1"));
    }
}