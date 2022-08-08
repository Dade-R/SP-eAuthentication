using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace eAuthentication.eAuthenticationClaimsLibrary
{
    public class DataLayer
    {
        private string _sqlConnectionString;
        private bool _logToDB;
        private bool _logToEventLog;
        private bool _logVerbose;

        //Enum: used for logging
        public enum MessageSeverity
        {
            Error,
            FailureAudit,
            Information,
            SuccessAudit,
            Warning,
        }

        // Enum: used for looking up users for the LookupUser method
        public enum QueryType
        {
            SearchAllUserFieldsContains = 1,
            SearchDisplayNameContains = 2,
            SearchProfilePropertyValues = 3,
            SearchIdenityContains = 4
        }

        public DataLayer(string sqlConnectionString, bool logToDB, bool logToEventLog, bool logVerbose)
        {
            this._sqlConnectionString = sqlConnectionString;
            this._logToDB = logToDB;
            this._logToEventLog = logToEventLog;
            this._logVerbose = logVerbose;
        }

        public string GetIdentityClaimType()
        {
            try
            {
                string claimType = string.Empty;
                if (_logVerbose) LogMessage("Getting identity ClaimType from database", MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("GetIdentityClaimType", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        // execute the command
                        SqlDataReader rdr = cmd.ExecuteReader();

                        // iterate through results, printing each to console
                        while (rdr.Read())
                        {
                            claimType = Convert.ToString(rdr["ClaimType"]);
                        }
                    }
                }
                return claimType;
            }
            catch (Exception ex)
            {
                LogMessage("Error getting identity ClaimType from database", MessageSeverity.Error, 1006, ex);
            }
            return null;
        }

        public string GetRoleClaimType()
        {
            try
            {
                string claimType = string.Empty;
                if (_logVerbose) LogMessage("Getting role ClaimType from database", MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("GetRoleClaimType", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        SqlDataReader rdr = cmd.ExecuteReader();
                        
                        while (rdr.Read())
                        {
                            claimType = Convert.ToString(rdr["ClaimType"]);
                        }
                    }
                }
                return claimType;
            }
            catch (Exception ex)
            {
                LogMessage("Error getting role ClaimType from database", MessageSeverity.Error, 1007, ex);
            }
            return null;
        }

        public List<string> GetAllRoles()
        {
            try
            {
                List<string> result = new List<string>();
                if (_logVerbose) LogMessage("Getting all roles from database", MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("GetAllRoles", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        SqlDataReader rdr = cmd.ExecuteReader();

                        while (rdr.Read())
                        {
                            result.Add(Convert.ToString(rdr["RoleName"]));
                        }
                    }
                }
                return result;
            }
            catch (Exception ex)
            {
                LogMessage("Error getting all roles from database", MessageSeverity.Error, 1008, ex);
            }
            return null;
        }

        // Gets a user object
        // createIfNotExist will generate a new record in the users table if a match isn't found
        // isLogin will increment the logincount column as well as update the last login date
        public eAuthUser GetUser(string identity, bool createIfNotExist = true, bool isLogin = true)
        {
            eAuthUser user = null;
            try
            {
                if (_logVerbose) LogMessage(string.Format("Getting user for identity: {0}", identity), MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("GetUser", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@Identity", identity);
                        cmd.Parameters.AddWithValue("@isLogin", isLogin);
                        cmd.Parameters.AddWithValue("@createUser", createIfNotExist);
                        // execute the command
                        SqlDataReader rdr = cmd.ExecuteReader();

                        // iterate through results, should only be one
                        while (rdr.Read())
                        {
                            user = new eAuthUser();
                            user.ID = Convert.ToInt32(rdr["ID"]);
                            user.Identity = Convert.ToString(rdr["Identity"]);
                            user.DisplayName = Convert.ToString(rdr["DisplayName"]);
                            user.EmailAddress = Convert.ToString(rdr["EmailAddress"]);
                            user.isApproved = Convert.ToBoolean(rdr["isApproved"]);
                            user.isSecurityApproved = Convert.ToBoolean(rdr["isSecurityApproved"]);
                            user.isTOUAccepted = Convert.ToBoolean(rdr["isTOUAccepted"]);
                            user.createDate = rdr["CreateDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["CreateDate"];
                            user.TOUAcceptedDate = rdr["TOUAcceptedDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["TOUAcceptedDate"];
                            user.lastModifiedDate = rdr["LastModifiedDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["LastModifiedDate"];
                            user.lastLoginDate = rdr["LastLoginDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["LastLoginDate"];
                            user.loginCount = Convert.ToInt32(rdr["LoginCount"]);
                        }
                    }
                }
                return user;
            }
            catch (Exception ex)
            {
                LogMessage(string.Format("Error getting user for identity: {0}", identity), MessageSeverity.Error, 1001, ex);
            }
            return null;
        }

        public List<eAuthRole> GetUserRoles(eAuthUser user)
        {
            List<eAuthRole> roles = new List<eAuthRole>();

            if (user != null)
            {
                eAuthRole role = null;
                try
                {
                    if (_logVerbose) LogMessage(string.Format("Getting roles for user identity: {0}", user.Identity), MessageSeverity.Information, 2);
                    using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                    {
                        cn.Open();
                        using (SqlCommand cmd = new SqlCommand("GetUserRoles", cn))
                        {
                            cmd.CommandType = CommandType.StoredProcedure;
                            cmd.Parameters.AddWithValue("@UserID", user.ID);
                            SqlDataReader rdr = cmd.ExecuteReader();

                            if (rdr.HasRows)
                            {
                                while (rdr.Read())
                                {
                                    role = new eAuthRole();
                                    role.ID = Convert.ToInt32(rdr["ID"]);
                                    role.ClaimType = Convert.ToString(rdr["ClaimType"]);
                                    role.RoleName = Convert.ToString(rdr["RoleName"]);
                                    role.createDate = rdr["CreateDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["CreateDate"];
                                    role.lastModifiedDate = rdr["LastModifiedDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["LastModifiedDate"];
                                    roles.Add(role);
                                }
                            }
                        }
                    }
                    return roles;
                }
                catch (Exception ex)
                {
                    LogMessage(string.Format("Error getting roles for user identity: {0}", user.Identity), MessageSeverity.Error, 1005, ex);
                }
            }
            return null;
        }

        // Accepts the terms of use for a given user
        public eAuthUser AcceptTOU(eAuthUser touUser)
        {
            if (touUser != null)
            {
                eAuthUser user = null;
                try
                {
                    if (_logVerbose) LogMessage(string.Format("Accepting TOU for user identity: {0}", touUser.Identity), MessageSeverity.Information, 2);
                    using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                    {
                        cn.Open();
                        using (SqlCommand cmd = new SqlCommand("AcceptTOU", cn))
                        {
                            cmd.CommandType = CommandType.StoredProcedure;
                            cmd.Parameters.AddWithValue("@UserID", touUser.ID);
                            // execute the command
                            SqlDataReader rdr = cmd.ExecuteReader();

                            // iterate through results, should only be one
                            while (rdr.Read())
                            {
                                user = new eAuthUser();
                                user.ID = Convert.ToInt32(rdr["ID"]);
                                user.Identity = Convert.ToString(rdr["Identity"]);
                                user.isApproved = Convert.ToBoolean(rdr["isApproved"]);
                                user.isSecurityApproved = Convert.ToBoolean(rdr["isSecurityApproved"]);
                                user.isTOUAccepted = Convert.ToBoolean(rdr["isTOUAccepted"]);
                                user.createDate = rdr["CreateDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["CreateDate"];
                                user.TOUAcceptedDate = rdr["TOUAcceptedDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["TOUAcceptedDate"];
                                user.lastModifiedDate = rdr["LastModifiedDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["LastModifiedDate"];
                                user.lastLoginDate = rdr["LastLoginDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["LastLoginDate"];
                                user.loginCount = Convert.ToInt32(rdr["LoginCount"]);
                            }
                        }
                    }
                    return user;
                }
                catch (Exception ex)
                {
                    LogMessage(string.Format("Error accepting TOU for user identity: {0}", touUser.Identity), MessageSeverity.Error, 1009, ex);
                }
            }
            return null;
        }

        // Sets all roles for for a user to inactive
        public bool SetRolesInactive(eAuthUser user)
        {
            bool success = false;

            if (user != null)
            {
                try
                {
                    if (_logVerbose) LogMessage(string.Format("Setting roles inactive for user identity: {0}", user.Identity), MessageSeverity.Information, 2);
                    using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                    {
                        cn.Open();
                        using (SqlCommand cmd = new SqlCommand("SetRolesInactive", cn))
                        {
                            cmd.CommandType = CommandType.StoredProcedure;
                            cmd.Parameters.AddWithValue("@UserID", user.ID);

                            cmd.ExecuteReader();
                            success = true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogMessage(string.Format("Error Setting roles inactive for user identity: {0}", user.Identity), MessageSeverity.Error, 1010, ex);
                }
            }
            return success;
        }

        // Not really used, but allows you to update a few specific columns directly in the DB
        public bool SaveUser(eAuthUser user)
        {
            bool success = false;

            try
            {
                if (_logVerbose) LogMessage(string.Format("Saving user identity: {0}", user.Identity), MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("SaveUser", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@ID", user.ID);
                        cmd.Parameters.AddWithValue("@Identity", user.Identity);
                        cmd.Parameters.AddWithValue("@isApproved", user.isApproved);
                        cmd.Parameters.AddWithValue("@isSecurityApproved", user.isSecurityApproved);
                        cmd.Parameters.AddWithValue("@isTOUAccepted", user.isTOUAccepted);

                        // execute the command
                        cmd.ExecuteNonQuery();
                        success = true;
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage(string.Format("Error saving user identity: {0}", user.Identity), MessageSeverity.Error, 1011, ex);
            }
            return success;
        }

        // Logs incoming claims and maps them back to profile properties if applicable
        public void LogClaim(string identity, string claimType, string claimValue)
        {
            try
            {
                if (_logVerbose) LogMessage(string.Format("Logging claim for identity: {0} with ClaimType: {1} and ClaimValue: {2}", identity, claimType, claimValue), MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();

                    // Call the LogClaim stored procedure to write our message to the DB
                    using (SqlCommand cmd = new SqlCommand("LogClaim", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@Identity", identity);
                        cmd.Parameters.AddWithValue("@ClaimType", claimType);
                        cmd.Parameters.AddWithValue("@ClaimValue", claimValue);

                        cmd.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage(string.Format("Error logging claim for identity: {0} with ClaimType: {1} and ClaimValue {2}", identity, claimType, claimValue), MessageSeverity.Error, 1012, ex);
            }
        }

        // Gets all the profile properties for a given user
        public List<KeyValuePair<string, string>> GetAllProfileProperties(eAuthUser user)
        {
            List<KeyValuePair<string, string>> properties;

            try
            {
                if (_logVerbose) LogMessage(string.Format("Getting user properties for identity: {0}", user.Identity), MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("GetUserProfileProperties", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@UserID", user.ID);

                        // execute the command
                        SqlDataReader rdr = cmd.ExecuteReader();
                        properties = new List<KeyValuePair<string, string>>();

                        // iterate through results, should only be one
                        while (rdr.Read())
                        {
                            properties.Add(new KeyValuePair<string, string>(Convert.ToString(rdr["PropertyName"]), Convert.ToString(rdr["PropertyValue"])));
                        }
                    }
                }
                return properties;
            }
            catch (Exception ex)
            {
                LogMessage(string.Format("Error getting user properties for identity: {0}", user.Identity), MessageSeverity.Error, 1013, ex);
            }
            return null;
        }

        public List<eAuthUser> LookupUsers(string query, QueryType queryType)
        {
            List<eAuthUser> users;
            try
            {
                if (_logVerbose) LogMessage(string.Format("Search for users with query: {0} and queryType: {1}", query, queryType), MessageSeverity.Information, 2);
                using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                {
                    cn.Open();
                    using (SqlCommand cmd = new SqlCommand("LookupUsers", cn))
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.Parameters.AddWithValue("@Query", query.ToLower().Trim());
                        cmd.Parameters.AddWithValue("@QueryType", (int)queryType);

                        // execute the command
                        SqlDataReader rdr = cmd.ExecuteReader();
                        
                        users = new List<eAuthUser>();

                        // iterate through results, should only be one
                        while (rdr.Read())
                        {
                            eAuthUser user = new eAuthUser();
                            user.ID = Convert.ToInt32(rdr["ID"]);
                            user.Identity = Convert.ToString(rdr["Identity"]);
                            user.DisplayName = Convert.ToString(rdr["DisplayName"]);
                            user.EmailAddress = Convert.ToString(rdr["EmailAddress"]);
                            user.isApproved = Convert.ToBoolean(rdr["isApproved"]);
                            user.isSecurityApproved = Convert.ToBoolean(rdr["isSecurityApproved"]);
                            user.isTOUAccepted = Convert.ToBoolean(rdr["isTOUAccepted"]);
                            user.createDate = rdr["CreateDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["CreateDate"];
                            user.TOUAcceptedDate = rdr["TOUAcceptedDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["TOUAcceptedDate"];
                            user.lastModifiedDate = rdr["LastModifiedDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["LastModifiedDate"];
                            user.lastLoginDate = rdr["LastLoginDate"] == DBNull.Value ? (DateTime?)null : (DateTime)rdr["LastLoginDate"];
                            user.loginCount = Convert.ToInt32(rdr["LoginCount"]);
                            users.Add(user);
                        }
                    }
                }
                return users;
            }
            catch (Exception ex)
            {
                LogMessage(string.Format("Error searching for users with query: {0} and queryType: {1}", query, queryType), MessageSeverity.Error, 1014, ex);
            }
            return null;
        }

        public void LogMessage(string message, MessageSeverity sev, int EventID = 0, Exception ex = null)
        {
            string stackTrace = string.Empty;
            string exceptionMessage = string.Empty;
            string innerExceptionMessage = string.Empty;

            if (ex != null)
            {
                if (!string.IsNullOrEmpty(ex.StackTrace))
                    stackTrace = ex.StackTrace.ToString();

                if (!string.IsNullOrEmpty(ex.Message))
                    exceptionMessage = ex.Message;

                if (ex.InnerException != null && !string.IsNullOrEmpty(ex.InnerException.StackTrace))
                    innerExceptionMessage = ex.InnerException.StackTrace;
            }

            if (_logToDB)
            {
                try
                {
                    using (SqlConnection cn = new SqlConnection(_sqlConnectionString))
                    {
                        cn.Open();
                        // Call the LogMessage stored procedure to write our message to the DB
                        using (SqlCommand cmd = new SqlCommand("LogMessage", cn))
                        {
                            cmd.CommandType = CommandType.StoredProcedure;
                            cmd.Parameters.AddWithValue("@Message", message);
                            cmd.Parameters.AddWithValue("@Severity", sev.ToString());
                            cmd.Parameters.AddWithValue("@Server", System.Environment.MachineName);
                            cmd.Parameters.AddWithValue("@EventID", EventID);
                            cmd.Parameters.AddWithValue("@StackTrace", stackTrace);
                            cmd.Parameters.AddWithValue("@ExceptionMessage", exceptionMessage);
                            cmd.Parameters.AddWithValue("@InnerExceptionStackTrace", innerExceptionMessage);

                            cmd.ExecuteReader();
                        }
                    }
                }
                catch (Exception exception)
                {
                    // Do nothing...
                }
            }

            if (_logToEventLog)
            {
                try
                {
                    string eventSource = "eAuth Custom Claims Library";
                    string eventLog = "Application";
                    string eventMessage = string.Format("Message: {0}\n StackTrace: {1}\n ExceptionMessage: {2}\n InnerExceptionMessage: {3}", message, stackTrace, exceptionMessage, innerExceptionMessage);

                    if (!EventLog.SourceExists(eventSource)) EventLog.CreateEventSource(eventSource, eventLog);

                    switch (sev)
                    {
                        case MessageSeverity.Error:
                            EventLog.WriteEntry(eventSource, eventMessage, EventLogEntryType.Error, EventID);
                            break;

                        case MessageSeverity.FailureAudit:
                            EventLog.WriteEntry(eventSource, eventMessage, EventLogEntryType.FailureAudit, EventID);
                            break;

                        case MessageSeverity.Information:
                            EventLog.WriteEntry(eventSource, eventMessage, EventLogEntryType.Information, EventID);
                            break;

                        case MessageSeverity.SuccessAudit:
                            EventLog.WriteEntry(eventSource, eventMessage, EventLogEntryType.SuccessAudit, EventID);
                            break;

                        case MessageSeverity.Warning:
                            EventLog.WriteEntry(eventSource, eventMessage, EventLogEntryType.Warning, EventID);
                            break;
                    }
                }
                catch (Exception exception)
                {
                    // Do nothing...
                }
            }
        }
    }
}
