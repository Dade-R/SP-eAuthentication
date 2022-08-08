using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using eAuthentication.eAuthenticationClaimsLibrary;

namespace eAuthentication.eAuthenticationQuery
{
    internal class Query
    {
        private string _sqlConnectionString;
        private bool _logToDB = false;
        private bool _logToEventLog = false;
        private bool _logVerbose = false;
        private int _timeout = 0;

        internal void RunQuery()
        {
            Boolean.TryParse(ConfigurationManager.AppSettings["LogToDB"], out _logToDB);
            Boolean.TryParse(ConfigurationManager.AppSettings["LogToEventLog"], out _logToEventLog);
            Boolean.TryParse(ConfigurationManager.AppSettings["LogVerbose"], out _logVerbose);
            int.TryParse(ConfigurationManager.AppSettings["Timeout"], out _timeout);

            System.Data.SqlClient.SqlConnectionStringBuilder builder = new System.Data.SqlClient.SqlConnectionStringBuilder();
            builder["Data Source"] = ConfigurationManager.AppSettings["SQLServer"];
            builder["Initial Catalog"] = ConfigurationManager.AppSettings["SQLDatabase"];
            if (_timeout > 0) builder["Connect Timeout"] = _timeout;
            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings["SQLUser"]))
            {
                builder["User ID"] = ConfigurationManager.AppSettings["SQLUser"];
                builder["Password"] = ConfigurationManager.AppSettings["SQLPassword"];
            }
            else
            {
                builder["Integrated Security"] = true;
            }
            _sqlConnectionString = builder.ConnectionString;
            
            if (_logVerbose)
            {
                Console.WriteLine("Connected to SQL " + _sqlConnectionString);
                Console.WriteLine();
            }
            
            DataLayer dl = new DataLayer(_sqlConnectionString, _logToDB, _logToEventLog, _logVerbose);

            while (true)
            {
                Console.Write("Query: ");
                string query = Console.ReadLine();

                List<eAuthUser> users = dl.LookupUsers(query, DataLayer.QueryType.SearchAllUserFieldsContains);

                foreach (eAuthUser user in users)
                {
                    if (user != null)
                    {
                        Console.WriteLine("Identity: " + user.Identity);

                        List<KeyValuePair<string, string>> properties = dl.GetAllProfileProperties(user);
                        foreach (KeyValuePair<string, string> property in properties)
                        {
                            Console.WriteLine(string.Format("Name: {0}, Value: {1}", property.Key, property.Value));
                        }
                        List<eAuthRole> roles = dl.GetUserRoles(user);
                        foreach (eAuthRole role in roles)
                        {
                            if (role != null) Console.WriteLine(string.Format("ClaimType: {0}, RoleName: {1}", role.ClaimType, role.RoleName));
                        }
                    }

                }
                Console.WriteLine();
            }
        }
    }
}
