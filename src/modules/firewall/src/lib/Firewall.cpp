// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Firewall.h"

const std::string FirewallBase::MODULE_INFO = R""""({
    "Name": "Firewall",
    "Description": "Provides functionality to remotely manage firewall rules on device",
    "Manufacturer": "Microsoft",
    "VersionMajor": 2,
    "VersionMinor": 0,
    "VersionInfo": "Nickel",
    "Components": ["Firewall"],
    "Lifetime": 1,
    "UserAccount": 0})"""";

const std::string FirewallBase::FIREWALL_COMPONENT = "Firewall";
const std::string FirewallBase::FIREWALL_REPORTED_FINGERPRINT = "firewallFingerprint";
const std::string FirewallBase::FIREWALL_REPORTED_STATE = "firewallState";
const std::string FirewallBase::FIREWALL_REPORTED_DEFAULTS = "firewallDefaults";
const std::string FirewallBase::FIREWALL_REPORTED_CONFIGURED_STATE = "configuredState";
const std::string FirewallBase::FIREWALL_REPORTED_CONFIGURED_STATE_DETAILS = "configuredStateDetail";
const std::string FirewallBase::FIREWALL_DESIRED_DEFAULTS = "desiredFirewallDefaults";
const std::string FirewallBase::FIREWALL_DESIRED_RULES = "desiredFirewallRules";

const char GenericRule::ACTION[] = "action";
const char GenericRule::TARGET[] = "target";
const char GenericRule::INBOUND[] = "inbound";
const char GenericRule::PROTOCOL[] = "protocol";
const char GenericRule::SOURCE[] = "sourceAddress";
const char GenericRule::SOURCE_PORT[] = "sourcePort";
const char GenericRule::DESTINATION[] = "destinationAddress";
const char GenericRule::DESTINATION_PORT[] = "destinationPort";

OSCONFIG_LOG_HANDLE FirewallLog::m_logFirewall = nullptr;

int FirewallBase::GetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    int status = MMI_OK;

    if (nullptr == clientName)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) client name");
        status = EINVAL;
    }
    else if (nullptr == payload)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) payload");
        status = EINVAL;
    }
    else if (nullptr == payloadSizeBytes)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) payload size");
        status = EINVAL;
    }
    else
    {
        size_t len = strlen(MODULE_INFO.c_str());
        *payload = new (std::nothrow) char[len];

        if (nullptr == *payload)
        {
            OsConfigLogError(FirewallLog::Get(), "Failed to allocate memory for payload");
            status = ENOMEM;
        }
        else
        {
            std::memcpy(*payload, MODULE_INFO.c_str(), len);
            *payloadSizeBytes = len;
        }
    }

    return status;
}

int FirewallBase::Get(const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    int status = MMI_OK;

    if (nullptr == componentName)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) component name");
        status = EINVAL;
    }
    else if (nullptr == objectName)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) object name");
        status = EINVAL;
    }
    else if (nullptr == payload)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) payload");
        status = EINVAL;
    }
    else if (nullptr == payloadSizeBytes)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) payload size");
        status = EINVAL;
    }
    else if (0 != FIREWALL_COMPONENT.compare(componentName))
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid component name: %s", componentName);
        status = EINVAL;
    }
    else
    {
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

        *payloadSizeBytes = 0;
        *payload = nullptr;

        if (0 == FIREWALL_REPORTED_STATE.compare(objectName))
        {
            status = GetState(writer);
        }
        else if (0 == FIREWALL_REPORTED_FINGERPRINT.compare(objectName))
        {
            status = GetFingerprint(writer);
        }
        else if (0 == FIREWALL_REPORTED_DEFAULTS.compare(objectName))
        {
            status = GetDefaultPolicy(writer);
        }
        else if (0 == FIREWALL_REPORTED_CONFIGURED_STATE.compare(objectName))
        {
            status = GetConfiguredState(writer);
        }
        else if (0 == FIREWALL_REPORTED_CONFIGURED_STATE_DETAILS.compare(objectName))
        {
            status = GetConfiguredStateDetails(writer);
        }
        else
        {
            OsConfigLogError(FirewallLog::Get(), "Invalid object name: %s", objectName);
            status = EINVAL;
        }

        // TODO: use max payload size to truncate payload
        if (MMI_OK == status)
        {
            *payloadSizeBytes = buffer.GetSize();
            *payload = new (std::nothrow) char[*payloadSizeBytes];

            if (*payload != nullptr)
            {
                std::fill(*payload, *payload + *payloadSizeBytes, 0);
                std::memcpy(*payload, buffer.GetString(), *payloadSizeBytes);
            }
        }
    }

    return status;
}

int FirewallBase::Set(const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
{
    int status = MMI_OK;

    if (nullptr == componentName)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) component name");
        status = EINVAL;
    }
    else if (nullptr == objectName)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) object name");
        status = EINVAL;
    }
    else if (nullptr == payload)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid (null) payload");
        status = EINVAL;
    }
    else if (0 > payloadSizeBytes)
    {
        OsConfigLogError(FirewallLog::Get(), "Invalid payload size: %d", payloadSizeBytes);
        status = EINVAL;
    }
    else
    {
        std::string payloadJson = std::string(payload, payloadSizeBytes);
        size_t payloadHash = HashString(payloadJson.c_str());

        if (payloadHash != m_lastPayloadHash)
        {
            m_lastPayloadHash = payloadHash;

            if (0 == FIREWALL_COMPONENT.compare(componentName))
            {
                rapidjson::Document document;
                document.Parse(payloadJson.c_str());

                if (!document.HasParseError())
                {
                    if (0 == FIREWALL_DESIRED_RULES.compare(objectName))
                    {
                        status = SetRules(document);
                    }
                    else if (0 == FIREWALL_DESIRED_DEFAULTS.compare(objectName))
                    {
                        status = SetDefaultPolicy(document);
                    }
                    else
                    {
                        OsConfigLogError(FirewallLog::Get(), "Invalid object name: %s", objectName);
                        status = EINVAL;
                    }
                }
                else
                {
                    OsConfigLogError(FirewallLog::Get(), "Failed to parse payload");
                    status = EINVAL;
                }
            }
            else
            {
                OsConfigLogError(FirewallLog::Get(), "Invalid component name: %s", componentName);
                status = EINVAL;
            }
        }
    }

    return status;
}

GenericRule::Action GenericRule::Parse(const rapidjson::Value& rule)
{
    Action action = Action::None;

    // TODO: Store an error message in the rule (HasParseError(), GetParseError())

    if (rule.IsObject())
    {
        if (rule.HasMember(ACTION))
        {
            if (rule[ACTION].IsInt())
            {
                // TODO: check range of enum value
                action = static_cast<Action>(rule[ACTION].GetInt());
            }
            else
            {
                // TODO: store error message
            }
        }
        else
        {
            // TODO: store error message
        }

        if (rule.HasMember(TARGET))
        {
            if (rule[TARGET].IsInt())
            {
                // TODO: check range of enum value
                m_target = static_cast<Target>(rule[TARGET].GetInt());
            }
            else
            {
                // TODO: store error message
            }
        }
        else
        {
            // TODO: store error message
        }

        if (rule.HasMember(INBOUND))
        {
            if (rule[INBOUND].IsBool())
            {
                m_inbound = rule[INBOUND].GetBool();
            }
            else
            {
                // TODO: store error message
            }
        }
        else
        {
            // TODO: store error message
        }

        if (rule.HasMember(PROTOCOL) && rule[PROTOCOL].IsInt())
        {
            // TODO: check range of enum value
            m_protocol = static_cast<Protocol>(rule[PROTOCOL].GetInt());
        }

        if (rule.HasMember(SOURCE) && rule[SOURCE].IsString())
        {
            m_source = rule[SOURCE].GetString();
        }

        if (rule.HasMember(DESTINATION) && rule[DESTINATION].IsString())
        {
            m_destination = rule[DESTINATION].GetString();
        }

        if (rule.HasMember(SOURCE_PORT) && rule[SOURCE_PORT].IsInt())
        {
            m_sourcePort = std::to_string(rule[SOURCE_PORT].GetInt());
        }

        if (rule.HasMember(DESTINATION_PORT) && rule[DESTINATION_PORT].IsInt())
        {
            m_destinationPort = std::to_string(rule[DESTINATION_PORT].GetInt());
        }
    }
    else
    {
        // TODO: store error message
        OsConfigLogError(FirewallLog::Get(), "Rule JSON is not an object");
    }

    return action;
}

std::string GenericRule::GetParseError() const
{
    return m_parseError;
}

bool GenericRule::HasParseError() const
{
    return !m_parseError.empty();
}

std::string Rule::GetSpecification() const
{
    std::stringstream command;

    command << ((m_inbound) ? "INPUT " : "OUTPUT ");

    if (m_protocol != Protocol::Any)
    {
        command << "-p ";
        switch (m_protocol)
        {
            case Protocol::TCP:
                command << "tcp";
                break;
            case Protocol::UDP:
                command << "udp";
                break;
            case Protocol::ICMP:
                command << "icmp";
                break;
            default:
                command << "";
        }
        command << " ";
    }

    if (!m_source.empty())
    {
        command << "-s " << m_source << " ";
    }

    if (!m_sourcePort.empty())
    {
        command << "-sport " << m_sourcePort << " ";
    }

    if (!m_destination.empty())
    {
        command << "-d " << m_destination << " ";
    }

    if (!m_destinationPort.empty())
    {
        command << "-dport " << m_destinationPort << " ";
    }

    command << "-j ";
    switch (m_target)
    {
        case Target::Allow:
            command << "ACCEPT";
            break;
        case Target::Deny:
            command << "DROP";
            break;
        default:
            command << "";
    }

    return command.str();
}

std::string Hash(const std::string str)
{
    char* hash = nullptr;
    std::string command = "echo \"" + str + "\"";
    return (hash = HashCommand(command.c_str(), FirewallLog::Get())) ? hash : "";
}

int Execute(const std::string command, std::string& result)
{
    char* textResult = nullptr;
    int status = ExecuteCommand(nullptr, command.c_str(), false, true, 0, 0, &textResult, nullptr, FirewallLog::Get());
    if (textResult)
    {
        result = textResult;
    }
    return status;
}

int Execute(const std::string command)
{
    return ExecuteCommand(nullptr, command.c_str(), false, true, 0, 0, nullptr, nullptr, FirewallLog::Get());
}

std::string FormatString(const std::string format, ...)
{
    char* buffer = nullptr;
    va_list args;
    va_start(args, format);
    vasprintf(&buffer, format.c_str(), args);
    va_end(args);
    std::string result = buffer;
    free(buffer);
    return result;
}