// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <cstdio>
#include <map>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <string>
#include <vector>

#include <CommonUtils.h>
#include <Logging.h>
#include <Mmi.h>

#define OSQUERY_LOGFILE "/var/log/osconfig_osquery.log"
#define OSQUERY_ROLLEDLOGFILE "/var/log/osconfig_osquery.bak"

class OSQueryLog
{
public:
    static OSCONFIG_LOG_HANDLE Get()
    {
        return m_log;
    }

    static void OpenLog()
    {
        m_log = ::OpenLog(OSQUERY_LOGFILE, OSQUERY_ROLLEDLOGFILE);
    }

    static void CloseLog()
    {
        ::CloseLog(&m_log);
    }

private:
    static OSCONFIG_LOG_HANDLE m_log;
};

class OSQuery
{
public:
    static const std::string m_componentName;

    static const std::string m_info;

    OSQuery(unsigned int maxPayloadSizeBytes);
    virtual ~OSQuery() = default;

    static int GetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
    virtual int Set(const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes);
    virtual int Get(const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
    virtual unsigned int GetMaxPayloadSizeBytes();

private:
    // static int SerializeStringEnumeration(rapidjson::Writer<rapidjson::StringBuffer>& writer, StringEnumeration value);
    // static int SerializeObject(rapidjson::Writer<rapidjson::StringBuffer>& writer, const Object& object);
    // static int SerializeObjectArray(rapidjson::Writer<rapidjson::StringBuffer>& writer, const std::vector<Object>& objectArray);
    // static int DeserializeStringEnumeration(std::string str, StringEnumeration& value);
    // static int DeserializeObject(rapidjson::Document& document, Object& object);
    // static int DeserializeObjectArray(rapidjson::Document& document, std::vector<Object>& objects);
    static int RunCommand(const char *command, std::string &commandOutput);
    static int SerializeJsonPayload(rapidjson::Document &document, MMI_JSON_STRING *payload, int *payloadSizeBytes, unsigned int maxPayloadSizeBytes);
    static int CopyJsonPayload(rapidjson::StringBuffer& buffer, MMI_JSON_STRING* payload, int* payloadSizeBytes);

    // Store desired settings for reporting
    // std::string m_stringValue;
    // int m_integerValue;
    // bool m_booleanValue;
    // Object m_objectValue;
    // std::vector<Object> m_objectArrayValue;

    unsigned int m_maxPayloadSizeBytes;
};
