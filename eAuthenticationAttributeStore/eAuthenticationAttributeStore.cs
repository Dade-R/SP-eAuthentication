using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.Linq;
using System.Text;
using Microsoft.IdentityServer.ClaimsPolicy.Engine.AttributeStore;
using eAuthentication.eAuthenticationClaimsLibrary;

namespace eAuthentication.eAuthenticationAttributeStore
{
    public class eAuthenticationAttributeStore : IAttributeStore
    {
        private string _sqlConnectionString;
        private bool _logToDB = false;
        private bool _logToEventLog = false;
        private bool _logVerbose = false;
        public IAsyncResult BeginExecuteQuery(string query, string[] parameters, AsyncCallback callback, object state)
        {
            string[][] outputValues = null;

            DataLayer dl = new DataLayer(_sqlConnectionString, _logToDB, _logToEventLog, _logVerbose);

            try
            {
                if (string.IsNullOrEmpty(query))
                {
                    dl.LogMessage("No query string", DataLayer.MessageSeverity.Error, 1002);
                    throw new AttributeStoreQueryFormatException("No query string");
                }

                if (parameters == null)
                {
                    dl.LogMessage("No query parameter", DataLayer.MessageSeverity.Error, 1003);
                    throw new AttributeStoreQueryFormatException("No query parameter");
                }

                if (_logVerbose) dl.LogMessage(string.Format("BeginExecuteQuery: {0}\nParameters: {1}", query, parameters[0]), DataLayer.MessageSeverity.Information, 1);

                // Expect query to start with which type of request we're getting optionally followed by a colon to designate return types
                
                if (query.StartsWith("GetIdentity"))
                {
                    eAuthUser user = dl.GetUser(parameters[0], true, true);

                    if (user != null)
                    {
                        // Expecting query to contain comma seperated list of return claims

                        string[] lookupClaims = query.Split(';')[1].Split(',');

                        outputValues = new string[1][];
                        outputValues[0] = new string[lookupClaims.Count()];

                        int x = 0;
                        foreach (string claimType in lookupClaims)
                        {
                            switch (claimType)
                            {
                                case "isApproved":
                                    outputValues[0][x] = user.isApproved.ToString();
                                    x++;
                                    break;

                                case "isSecurityApproved":
                                    outputValues[0][x] = user.isSecurityApproved.ToString();
                                    x++;
                                    break;

                                case "isTOUAccepted":
                                    outputValues[0][x] = user.isTOUAccepted.ToString();
                                    x++;
                                    break;
                            }
                        }
                    }
                }

                else if (query.StartsWith("LogClaim"))
                {
                    string[] param = parameters[0].Split(new string[] { "::" }, StringSplitOptions.None);
                    string identity = param[0];
                    string claimtype = param[1];
                    string claimvalue = param[2];
                    dl.LogClaim(identity, claimtype, claimvalue);
                }

                else if (query.StartsWith("SetRolesInactive"))
                {
                    eAuthUser user = dl.GetUser(parameters[0], false, false);
                    if (user != null)
                    {
                        dl.SetRolesInactive(user);
                    }
                }
            }
            catch (Exception ex)
            {
                dl.LogMessage("Error in BeginExecuteQuery of AttributeStore", DataLayer.MessageSeverity.Error, 1004, ex);
            }

            TypedAsyncResult<string[][]> asyncResult = new TypedAsyncResult<string[][]>(callback, state);
            asyncResult.Complete(outputValues, true);
            return asyncResult;
        }

        public string[][] EndExecuteQuery(IAsyncResult result)
        {
            return TypedAsyncResult<string[][]>.End(result);
        }

        public void Initialize(Dictionary<string, string> config)
        {
            DataLayer dl = new DataLayer(string.Empty, false, true, false);

            string db = string.Empty;
            string servername = string.Empty;
            string username = string.Empty;
            string password = string.Empty;
            int timeout = 0;

            foreach (string key in config.Keys)
            {
                if (_logVerbose) dl.LogMessage(string.Format("Initalize attribute store key {0} value {1}", key, config[key]), DataLayer.MessageSeverity.Information, 3);
                switch (key)
                {
                    case "SQLDatabase":
                        db = config[key];
                        break;

                    case "SQLServer":
                        servername = config[key];
                        break;

                    case "SQLUser":
                        username = config[key];
                        break;

                    case "SQLPassword":
                        password = config[key];
                        break;

                    case "Timeout":
                        timeout = Convert.ToInt32(config[key]);
                        break;

                    case "LogToDB":
                        _logToDB = Convert.ToBoolean(config[key]);
                        break;

                    case "LogToEventLog":
                        _logToEventLog = Convert.ToBoolean(config[key]);
                        break;

                    case "LogVerbose":
                        _logVerbose = Convert.ToBoolean(config[key]);
                        break;
                }
            }

            System.Data.SqlClient.SqlConnectionStringBuilder builder = new System.Data.SqlClient.SqlConnectionStringBuilder();
            builder["Data Source"] = servername;
            builder["Initial Catalog"] = db;
            if (timeout > 0) builder["Connect Timeout"] = timeout;
            if (!string.IsNullOrEmpty(username))
            {
                builder["User ID"] = username;
                builder["Password"] = password;
            }
            else
            {
                builder["Integrated Security"] = true;
            }
            if (_logVerbose) dl.LogMessage(string.Format("SQL Connection String: {0}", builder.ConnectionString), DataLayer.MessageSeverity.Information, 3);
            _sqlConnectionString = builder.ConnectionString;
        }
    }
}
