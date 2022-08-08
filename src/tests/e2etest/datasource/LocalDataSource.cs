// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using NUnit.Framework;
using System;
using System.IO;
using System.Text;

namespace E2eTesting
{
    public class LocalDataSource : AbstractDataSource
    {
        private readonly string _reportedPath = "/etc/osconfig/osconfig_reported.json";
        private readonly string _desiredPath = "/etc/osconfig/osconfig_desired.json";
        
        public override void Initialize()
        {
            if (!File.Exists(_reportedPath))
            {
                Assert.Fail("[LocalDataSource] reported path is missing: ", _reportedPath);
            }
            if (!File.Exists(_desiredPath))
            {
                using (FileStream fs = File.Create(_desiredPath))
                {
                    Byte[] info = new UTF8Encoding(true).GetBytes("{}");
                    fs.Write(info, 0, info.Length);
                }
            }
        }

        public override bool SetDesired<T>(string componentName, string objectName, T value, int maxWaitSeconds)
        {
            JObject local = JObject.Parse(File.ReadAllText(_desiredPath));

            string json = $@"{{
                ""{componentName}"": {{
                    ""{objectName}"": {JsonConvert.SerializeObject(value)}
                    }}
                }}";

            local.Merge(JObject.Parse(json), new JsonMergeSettings
                {
                    MergeArrayHandling = MergeArrayHandling.Union,
                }
            );
            File.WriteAllText(_desiredPath, local.ToString());
            return true;
        }

        public override T GetReported<T>(string componentName, string objectName, Func<T, bool> condition, int maxWaitSeconds)
        {
            JObject local = JObject.Parse(File.ReadAllText(_reportedPath));

            Assert.IsTrue(local.ContainsKey(componentName), "[LocalDataSource] does not contain component: " + componentName);
            if (String.IsNullOrEmpty(objectName))
            {
                while(!condition(local[componentName].ToObject<T>()))
                {
                    System.Threading.Thread.Sleep(1000);
                    local = JObject.Parse(File.ReadAllText(_reportedPath));
                }

                return local[componentName].ToObject<T>();
            }
            else
            {
                Assert.IsTrue(local[componentName].ToObject<JObject>().ContainsKey(objectName));

                while(!condition(local[componentName][objectName].ToObject<T>()))
                {
                    System.Threading.Thread.Sleep(1000);
                    local = JObject.Parse(File.ReadAllText(_reportedPath));
                }

                return local[componentName][objectName].ToObject<T>();
            }
        }
    }
}