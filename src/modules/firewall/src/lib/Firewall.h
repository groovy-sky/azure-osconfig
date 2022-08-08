// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <cstdarg>
#include <memory>
#include <ostream>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <sstream>
#include <string>
#include <vector>

#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>

#define FIREWALL_LOGFILE "/var/log/osconfig_firewall.log"
#define FIREWALL_ROLLEDLOGFILE "/var/log/osconfig_firewall.bak"

class FirewallLog
{
public:
    static OSCONFIG_LOG_HANDLE Get()
    {
        return m_logFirewall;
    }
    static void OpenLog()
    {
        m_logFirewall = ::OpenLog(FIREWALL_LOGFILE, FIREWALL_ROLLEDLOGFILE);
    }
    static void CloseLog()
    {
        ::CloseLog(&m_logFirewall);
    }

private:
    static OSCONFIG_LOG_HANDLE m_logFirewall;
};

std::string Hash(const std::string str);
int Execute(const std::string command, std::string& result);
int Execute(const std::string command);
std::string FormatString(const std::string format, ...);

// TODO: maybe this ???
// template<class RuleT, class PolicyT>
template<class RuleT>
class GenericUtility
{
public:
    typedef RuleT Rule;

    enum class State
    {
        Unknown = 0,
        Enabled,
        Disabled
    };

    struct Policy
    {
        typename RuleT::Target in;
        typename RuleT::Target out;
    };

    // TODO: struct for returning configuration results from Add/Remove

    virtual ~GenericUtility() = default;

    // Inserts a rule
    virtual void Add(const RuleT& rule) = 0;

    // Removes a rule (and all duplicates)
    virtual void Remove(const RuleT& rule) = 0;

    // Sets the default input/output behavior
    virtual int SetDefaultPolicy(const Policy& policy) = 0;
    virtual const Policy GetDefaultPolicy() const = 0;

    // Detects if the utility exists and is enabled
    virtual State Detect() const = 0;

    // Returns a hash of the current Rule set
    virtual std::string Hash() const = 0;

protected:
    // Checks if a rule exists
    virtual bool RuleExists(const RuleT& rule) const = 0;
};

template<class RuleT>
class Iptables : public GenericUtility<RuleT>
{
public:
    typedef typename GenericUtility<RuleT>::State State;
    typedef typename GenericUtility<RuleT>::Policy Policy;

    Iptables() = default;
    ~Iptables() = default;

    void Add(const RuleT& rule) override
    {
        if (!RuleExists(rule))
        {
            const std::string ruleSpec = rule.GetSpecification();
            const std::string command = "iptables -I " + ruleSpec;

            OsConfigLogInfo(FirewallLog::Get(), "[IPTABLES]\n%s", command.c_str());
            // if (0 != ::Execute(command.c_str()))
            // {
            //     OsConfigLogError(FirewallLog::Get(), "Failed to add rule %s", ruleSpec.c_str());
            // }
        }

        // TODO: return an int for result
        // cache a special result type for failures with a message
    }

    void Remove(const RuleT& rule) override
    {
        // TODO: max number of times to try ???
        // while (RuleExists(rule))
        // {
            const std::string ruleSpec = rule.GetSpecification();
            const std::string command = "iptables -D " + ruleSpec;

            OsConfigLogInfo(FirewallLog::Get(), "[IPTABLES]\n%s", command.c_str());

            // TODO: break if error
            // if (0 != ::Execute(command.c_str()))
            // {
            //     OsConfigLogError(FirewallLog::Get(), "Failed to remove rule %s", ruleSpec.c_str());
            // }
        // }

        // TODO: return an int for result
        // cache a special result type for failures with a message
    }

    int SetDefaultPolicy(const Policy& policy) override
    {
        const std::string fmt = "iptables -P %s %s";

        // TODO: ideally some method should be called Target::Something() to generate the policy string
        const std::string in = policy.in == RuleT::Target::Allow ? "ACCEPT" : "DROP";
        const std::string out = policy.out == RuleT::Target::Allow ? "ACCEPT" : "DROP";
        const std::string inPolicy = FormatString(fmt, "INPUT", in);
        const std::string outPolicy = FormatString(fmt, "OUTPUT", out);

        OsConfigLogInfo(FirewallLog::Get(), "[IPTABLES]\n%s", inPolicy.c_str());
        OsConfigLogInfo(FirewallLog::Get(), "[IPTABLES]\n%s", outPolicy.c_str());

        // if (0 != ::Execute(inPolicy.c_str()))
        // {
        //     OsConfigLogError(FirewallLog::Get(), "Failed to set default policies");
        // }

        // if (0 != ::Execute(outPolicy.c_str()))
        // {
        //     OsConfigLogError(FirewallLog::Get(), "Failed to set default policies");
        // }

        // TODO: return non-zero if either/both command(s) failed
        return 0;
    }

    const Policy GetDefaultPolicy() const override
    {
        const std::string fmt = "iptables -L %s -n -v | grep '^Chain %s' | awk '{print $4}'";

        Policy policy;
        std::string inPolicy, outPolicy;

        const std::string inputCommand = ::FormatString(fmt.c_str(), "INPUT", "INPUT");
        const std::string outputCommand = ::FormatString(fmt.c_str(), "OUTPUT", "OUTPUT");

        if (0 == ::Execute(inputCommand, inPolicy))
        {
            policy.in = RuleT::TargetFromString(inPolicy);
        }

        if (0 == ::Execute(outputCommand, outPolicy))
        {
            policy.out = RuleT::TargetFromString(outPolicy);
        }

        return policy;
    }

    State Detect() const override
    {
        State state = State::Unknown;
        std::string result;

        // If the utility is not installed/available, the the state is Disabled
        // If the utility is installed check if there are rules/chain policies in the tables
        // If there are rules/chain policies, the state is Enabled

        if ((0 == ::Execute("iptables -S", result)) && !result.empty())
        {
            state = State::Enabled;
        }
        else
        {
            state = State::Disabled;
        }

        return state;
    }

    std::string Hash() const override
    {
        std::string hash;
        std::string rules;
        const std::string command = "iptables -S";

        if (0 == ::Execute(command.c_str(), rules))
        {
            hash = ::Hash(rules);
        }
        else
        {
            OsConfigLogError(FirewallLog::Get(), "Error retrieving rules specification from iptables");
        }

        return hash;
    }

protected:
    bool RuleExists(const RuleT& rule) const override
    {
        std::string command = "iptables -C " + rule.GetSpecification();
        return (0 == ::Execute(command.c_str()));
    }
};

class GenericRule
{
public:
    enum class Action
    {
        None = 0,
        Add,
        Remove
    };

    enum class Target
    {
        None = 0,
        Allow,
        Deny
    };

    enum class Protocol
    {
        None = 0,
        Any,
        TCP,
        UDP,
        ICMP
    };

    static const char ACTION[];
    static const char TARGET[];
    static const char INBOUND[];
    static const char PROTOCOL[];
    static const char SOURCE[];
    static const char SOURCE_PORT[];
    static const char DESTINATION[];
    static const char DESTINATION_PORT[];

    virtual ~GenericRule() = default;

    virtual Action Parse(const rapidjson::Value& json);
    virtual std::string GetParseError() const;
    virtual bool HasParseError() const;

    virtual bool operator==(const GenericRule& other) const
    {
        return (m_source == other.m_source &&
                m_sourcePort == other.m_sourcePort &&
                m_destination == other.m_destination &&
                m_destinationPort == other.m_destinationPort &&
                m_protocol == other.m_protocol &&
                m_target == other.m_target);
    }

    virtual std::ostream& operator<<(std::ostream& os) const
    {
        os << GetSpecification();
        return os;
    }

    // TODO: this is not scalable, but it's a temporary solution
    static Target TargetFromString(std::string str)
    {
        if (str == "ACCEPT")
        {
            return Target::Allow;
        }
        else if (str == "DROP")
        {
            return Target::Deny;
        }
        else
        {
            return Target::None;
        }
    }

    virtual std::string GetSpecification() const = 0;

protected:
    Target m_target;
    bool m_inbound;
    Protocol m_protocol;
    std::string m_source;
    std::string m_sourcePort;
    std::string m_destination;
    std::string m_destinationPort;

private:
    std::string m_parseError;
};

class Rule : public GenericRule
{
public:
    Rule() = default;
    ~Rule() = default;

    std::string GetSpecification() const override;
};

class FirewallBase
{
public:
    static const std::string MODULE_INFO;
    static const std::string FIREWALL_COMPONENT;

    // Reported properties
    static const std::string FIREWALL_REPORTED_FINGERPRINT;
    static const std::string FIREWALL_REPORTED_STATE;
    static const std::string FIREWALL_REPORTED_DEFAULTS;
    static const std::string FIREWALL_REPORTED_CONFIGURED_STATE;
    static const std::string FIREWALL_REPORTED_CONFIGURED_STATE_DETAILS;

    // Desired properties
    static const std::string FIREWALL_DESIRED_DEFAULTS;
    static const std::string FIREWALL_DESIRED_RULES;

    FirewallBase(unsigned int maxPayloadSizeBytes) : m_maxPayloadSizeBytes(maxPayloadSizeBytes) {}
    virtual ~FirewallBase() = default;

    static int GetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes);

    virtual int Get(const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
    virtual int Set(const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes);

protected:
    virtual int GetState(rapidjson::Writer<rapidjson::StringBuffer>& writer) = 0;
    virtual int GetFingerprint(rapidjson::Writer<rapidjson::StringBuffer>& writer) = 0;
    virtual int GetDefaultPolicy(rapidjson::Writer<rapidjson::StringBuffer>& writer) = 0;
    virtual int GetConfiguredState(rapidjson::Writer<rapidjson::StringBuffer>& writer) = 0;
    virtual int GetConfiguredStateDetails(rapidjson::Writer<rapidjson::StringBuffer>& writer) = 0;

    virtual int SetDefaultPolicy(rapidjson::Document& document) = 0;
    virtual int SetRules(rapidjson::Document& document) = 0;

private:
    unsigned int m_maxPayloadSizeBytes;
    size_t m_lastPayloadHash;
};

template <class Utility>
class FirewallModule : public FirewallBase
{
public:
    FirewallModule(unsigned int maxPayloadSize) : FirewallBase(maxPayloadSize), m_state(ConfiguredState::Unknown), m_stateDetails("") {}
    ~FirewallModule() = default;

protected:
    typedef typename Utility::Policy Policy;
    typedef typename Utility::Rule Rule;
    typedef typename Utility::Rule::Action Action;
    typedef typename Utility::Rule::Target Target;
    typedef typename Utility::State State;

    virtual int GetState(rapidjson::Writer<rapidjson::StringBuffer>& writer) override
    {
        State state = m_utility.Detect();
        int value = static_cast<int>(state);
        writer.Int(value);
        return 0;
    }

    virtual int GetFingerprint(rapidjson::Writer<rapidjson::StringBuffer>& writer) override
    {
        std::string fingerprint = m_utility.Hash();
        writer.String(fingerprint.c_str());
        return fingerprint.empty() ? -1 : 0;
    }

    virtual int GetDefaultPolicy(rapidjson::Writer<rapidjson::StringBuffer>& writer) override
    {
        Policy policy = m_utility.GetDefaultPolicy();

        writer.StartObject();
        writer.Key("in");
        writer.Int(static_cast<int>(policy.in));

        writer.Key("out");
        writer.Int(static_cast<int>(policy.out));
        writer.EndObject();

        return 0;
    }

    virtual int GetConfiguredState(rapidjson::Writer<rapidjson::StringBuffer>& writer) override
    {
        writer.Int(static_cast<int>(m_state));
        return 0;
    }

    virtual int GetConfiguredStateDetails(rapidjson::Writer<rapidjson::StringBuffer>& writer) override
    {
        writer.String(m_stateDetails.c_str());
        return 0;
    }

    virtual int SetDefaultPolicy(rapidjson::Document& document) override
    {
        Policy policy;

        // TODO: move "in" and "out" to static constants in the utility class

        if (document.HasMember("in"))
        {
            if (document["in"].IsInt())
            {
                policy.in = static_cast<Target>(document["in"].GetInt());
            }
            else
            {
                // TODO: error
            }
        }
        else
        {
            // TODO: error
        }

        if (document.HasMember("in"))
        {
            if (document["in"].IsInt())
            {
                policy.in = static_cast<Target>(document["in"].GetInt());
            }
            else
            {
                // TODO: error
            }
        }
        else
        {
            // TODO: error
        }

        // TODO: do not set the default policy if there are parsing errors
        return m_utility.SetDefaultPolicy(policy);
    }

    virtual int SetRules(rapidjson::Document& document) override
    {
        int status = 0;

        if (document.IsArray())
        {
            for (auto& value : document.GetArray())
            {
                Rule rule;
                Action action = rule.Parse(value);

                if (!rule.HasParseError())
                {
                    switch (action)
                    {
                        case Action::Add:
                            m_utility.Add(rule);
                            // TODO: get error and store error in configured state/details
                            break;
                        case Action::Remove:
                            m_utility.Remove(rule);
                            // TODO: get error and store error in configured state/details
                            break;
                        default:
                            OsConfigLogError(FirewallLog::Get(), "Invalid action: %d", static_cast<int>(action));
                            status = EINVAL;
                    }
                }
                else
                {
                    // TODO: cache errors in the configured state/details and return an error
                }
            }
        }
        else
        {
            OsConfigLogError(FirewallLog::Get(), "Rules must be an array of rule specifications");
            status = EINVAL;
        }

        return status;
    }

private:
    Utility m_utility;

    // TODO: this feels awkward here... where can this be moved (to the utility?)
    // if moved to the utility, then there does not need to be a separate type for returning errors on every Add/Delete
    enum class ConfiguredState
    {
        Unknown = 0,
        Success,
        Failure
    };

    ConfiguredState m_state;
    std::string m_stateDetails;
};

typedef FirewallModule<Iptables<Rule>> Firewall;