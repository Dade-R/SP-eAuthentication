using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Web.ClientServices;
using System.Data.SqlClient;
using Microsoft.Office.Server.UserProfiles;
using Microsoft.SharePoint;
using eAuthentication.eAuthenticationClaimsLibrary;

namespace eAuthentication.eAuthenticationProfileSync
{
    internal class Profile
    {
        private string _sqlConnectionString;
        private bool _logToDB = false;
        private bool _logToEventLog = false;
        private bool _logVerbose = false;
        private int _timeout = 0;

        internal enum UserProperty
        {
            DisplayName,
            EmailAddress,
            FirstName,
            LastName,
            PersonGUID,
            StreetAddress,
            City,
            State,
            ZipCode,
            Country,
            WorkPhone,
            HomePhone,
            Role,
            Default
        }

        internal bool NeedsUpdate(UserProfile profile, string propertyName, string value)
        {
            object profileProperty = profile[propertyName].Value;
            if ((profileProperty == null) || ((!string.IsNullOrEmpty(value)) && (string.Compare(profileProperty.ToString(), value) != 0))) return true;
            else return false;
        }

        internal void Sync()
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

            if (_logVerbose) Console.WriteLine("Connecting to SQL instance: " + _sqlConnectionString);
            
            string eAuthPrefix = ConfigurationManager.AppSettings["eAuthPrefix"];
            string siteURL = ConfigurationManager.AppSettings["SPSite"];
            DataLayer dl = new DataLayer(_sqlConnectionString, _logToDB, _logToEventLog, _logVerbose);
            if (_logVerbose) Console.WriteLine("Connected to SQL Server");
            try
            {
                
                int eAuthUserCount = 0;
                int eAuthUpdateCount = 0;
                SPSite site = new SPSite(siteURL);
                if (site != null)
                {
                    if (_logVerbose) Console.WriteLine("Connected to SharePoint site: {0}", site.Url);
                    SPServiceContext svcContext = SPServiceContext.GetContext(site);
                    if (svcContext != null)
                    {
                        if (_logVerbose) Console.WriteLine("Connected to SharePoint Service Context");
                        UserProfileManager upm = new UserProfileManager(svcContext);
                        if (upm != null)
                        {
                            if (_logVerbose) Console.WriteLine("Connected to SharePoint User Profile Manager");
                            IEnumerator profileEnum = upm.GetEnumerator();
                            if (profileEnum != null)
                            {
                                while (profileEnum.MoveNext())
                                {
                                    UserProfile profile = (UserProfile)profileEnum.Current;
                                    if ((profile != null) && (profile.AccountName.StartsWith(eAuthPrefix)))
                                    {
                                        if (_logVerbose) Console.WriteLine("Processing user identity: {0}", profile.AccountName);
                                        eAuthUserCount++;
                                        string[] acctNameArr = profile.AccountName.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                                        string identity = acctNameArr[acctNameArr.Length - 1].Trim();
                                        eAuthUser eAuthUser = dl.GetUser(identity, false, false);
                                        if (eAuthUser != null)
                                        {
                                            bool updateProfile = false;
                                            List<KeyValuePair<string, string>> eAuthProperties = dl.GetAllProfileProperties(eAuthUser);
                                            foreach (KeyValuePair<string, string> eAuthProperty in eAuthProperties)
                                            {
                                                UserProperty userProperty = UserProperty.Default;
                                                if (Enum.TryParse<UserProperty>(eAuthProperty.Key, true, out userProperty))
                                                {
                                                    switch (userProperty)
                                                    {
                                                        case UserProperty.DisplayName:
                                                            if (NeedsUpdate(profile, "PreferredName", eAuthProperty.Value))
                                                            {
                                                                profile["PreferredName"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.EmailAddress:
                                                            if (NeedsUpdate(profile, "WorkEmail", eAuthProperty.Value))
                                                            {
                                                                profile["WorkEmail"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.FirstName:
                                                            if (NeedsUpdate(profile, "FirstName", eAuthProperty.Value))
                                                            {
                                                                profile["FirstName"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.LastName:
                                                            if (NeedsUpdate(profile, "LastName", eAuthProperty.Value))
                                                            {
                                                                profile["LastName"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.PersonGUID:
                                                            if (NeedsUpdate(profile, "SPS-JobTitle", eAuthUser.EmailAddress))
                                                            {
                                                                profile["SPS-JobTitle"].Value = eAuthUser.EmailAddress;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.StreetAddress:
                                                            if (NeedsUpdate(profile, "SPS-Location", eAuthProperty.Value))
                                                            {
                                                                profile["SPS-Location"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.City:
                                                            if (NeedsUpdate(profile, "Office", eAuthProperty.Value))
                                                            {
                                                                profile["Office"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.State:
                                                            break;
                                                        case UserProperty.ZipCode:
                                                            break;
                                                        case UserProperty.Country:
                                                            break;
                                                        case UserProperty.WorkPhone:
                                                            if (NeedsUpdate(profile, "WorkPhone", eAuthProperty.Value))
                                                            {
                                                                profile["WorkPhone"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.HomePhone:
                                                            if (NeedsUpdate(profile, "HomePhone", eAuthProperty.Value))
                                                            {
                                                                profile["HomePhone"].Value = eAuthProperty.Value;
                                                                updateProfile = true;
                                                            }
                                                            break;
                                                        case UserProperty.Role:
                                                            break;
                                                        case UserProperty.Default:
                                                            break;
                                                    }
                                                }
                                            }
                                            if (updateProfile)
                                            {
                                                if (_logVerbose)
                                                {
                                                    Console.WriteLine("Updating user identity: {0}", profile.AccountName);
                                                    dl.LogMessage(String.Format("Updating user identity: {0}", profile.AccountName), DataLayer.MessageSeverity.Information);
                                                }
                                                eAuthUpdateCount++;
                                                profile.Commit();
                                            }
                                        }
                                        else {
                                            Console.WriteLine("Unable to find user: {0} in database", profile.AccountName);
                                            dl.LogMessage(String.Format("Unable to find user: {0} in database", profile.AccountName), DataLayer.MessageSeverity.Warning);
                                        }
                                    }
                                }
                                Console.WriteLine("Updated {0} profiles out of {1} users", eAuthUpdateCount, eAuthUserCount);
                                if (_logVerbose) dl.LogMessage(String.Format("Updated {0} profiles out of {1} users", eAuthUpdateCount, eAuthUserCount), DataLayer.MessageSeverity.Information);
                            }
                        }
                        else Console.WriteLine("Unable to connect to SharePoint User Profile Manager");
                    }
                    else Console.WriteLine("Unable to connect to SharePoint Service Context");
                }
                else Console.WriteLine("Unable to connect to SharePoint site: {0}", siteURL);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error attempting to sync User Profile data: {0}", ex.Message);
                dl.LogMessage("Error attempting to sync User Profile data", DataLayer.MessageSeverity.Error, 1015, ex);
            }
        }
    }
}
