using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.SharePoint;
using Microsoft.SharePoint.Administration;
using Microsoft.SharePoint.Administration.Claims;
using Microsoft.SharePoint.WebControls;
using eAuthentication.eAuthenticationClaimsLibrary;

namespace eAuthentication.eAuthenticationClaimsProvider
{
    public class eAuthenticationClaimsProvider : SPClaimProvider
    {
        #region Private Properties
        private string _connectionString;
        private bool _logToDB = false;
        private bool _logToEvent = false;
        private bool _logVerbose = false;
        private DataLayer _dl;
        private string _claimValueType;
        private string _identityClaimType;
        private string _roleClaimType;
        #endregion
        #region Constructor
        public eAuthenticationClaimsProvider(string displayName) : base(displayName)
        {

        }
        #endregion
        #region Public Methods
        public override string Name
        {
            get
            {
                return ProviderInternalName;
            }
        }
        public override bool SupportsEntityInformation
        {
            get
            {
                return true;
            }
        }
        public override bool SupportsHierarchy
        {
            get
            {
                return false;
            }
        }
        public override bool SupportsResolve
        {
            get
            {
                return true;
            }
        }
        public override bool SupportsSearch
        {
            get
            {
                return true;
            }
        }
        public string GetIdentityProviderName(Uri context)
        {
            string providername = string.Empty;
            try
            {
                //get the token service manager so we can retrieve the appropriate trusted login provider
                SPSecurityTokenServiceManager sptMgr = SPSecurityTokenServiceManager.Local;
                SPWebApplication webApp = SPWebApplication.Lookup(context);

                foreach (SPUrlZone zone in Enum.GetValues(typeof(SPUrlZone)))
                {
                    SPIisSettings iisSettings = webApp.GetIisSettingsWithFallback(zone);
                    if ((!iisSettings.UseTrustedClaimsAuthenticationProvider) && (!webApp.IsAdministrationWebApplication)) continue;

                    //get the list of authentication providers associated with the zone
                    foreach (SPAuthenticationProvider prov in iisSettings.ClaimsAuthenticationProviders)
                    {
                        //make sure the provider we're looking at is a SAML claims provider
                        if (prov.GetType() == typeof(SPTrustedAuthenticationProvider))
                        {
                            //get the SPTrustedLoginProvider using the DisplayName
                            var lp =
                                from SPTrustedLoginProvider spt in sptMgr.TrustedLoginProviders
                                where spt.DisplayName == prov.DisplayName
                                select spt;
                            //there should only be one match, so retrieve that
                            if ((lp != null) && (lp.Count() > 0))
                            {
                                //get the login provider
                                SPTrustedLoginProvider loginProv = lp.First();
                                providername = loginProv.Name;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _dl.LogMessage("Error looking up trustedidentitytokenissuer", DataLayer.MessageSeverity.Error, 2001, ex);
            }

            if (_logVerbose) _dl.LogMessage(String.Format("Resolving name of trustedidentitytokenissuer to {0}", providername), DataLayer.MessageSeverity.Information);
            return providername;
        }
        public string IdentityClaimType
        {
            get
            {
                if (_identityClaimType != null) return _identityClaimType;
                else
                {
                    if (setupDBConnection()) return IdentityClaimType;
                    else return null;
                }
            }
        }
        public string RoleClaimType
        {
            get
            {
                if (_roleClaimType != null) return _roleClaimType;
                else
                {
                    if (setupDBConnection()) return RoleClaimType;
                    else return null;
                }
            }
        }
        #endregion
        #region Override Methods
        protected override void FillClaimTypes(List<string> claimTypes)
        {
            if ((setupDBConnection()) && (_logVerbose)) _dl.LogMessage("FillClaimTypes called", DataLayer.MessageSeverity.Information);

            if (claimTypes == null) throw new ArgumentNullException("claimTypes");

            if (!setupDBConnection()) return;

            if ((this.IdentityClaimType != null) && (!claimTypes.Contains(this.IdentityClaimType))) claimTypes.Add(this.IdentityClaimType);

            if ((this.RoleClaimType != null) && (!claimTypes.Contains(this.RoleClaimType))) claimTypes.Add(this.RoleClaimType);
        }

        protected override void FillClaimValueTypes(List<string> claimValueTypes)
        {
            if ((setupDBConnection()) && (_logVerbose)) _dl.LogMessage("FillClaimValueTypes called", DataLayer.MessageSeverity.Information);

            if (claimValueTypes == null) throw new ArgumentNullException("claimValueTypes");

            if (!setupDBConnection()) return;

            if (this.IdentityClaimType != null) claimValueTypes.Add(_claimValueType);

            if (this.RoleClaimType != null) claimValueTypes.Add(_claimValueType);
        }

        protected override void FillEntityTypes(List<string> entityTypes)
        {
            if ((setupDBConnection()) && (_logVerbose)) _dl.LogMessage("FillEntityTypes called", DataLayer.MessageSeverity.Information);

            if (entityTypes == null) throw new ArgumentNullException("entityTypes");

            if (!setupDBConnection()) return;

            if (this.IdentityClaimType != null) entityTypes.Add(SPClaimEntityTypes.User);

            if (this.RoleClaimType != null) entityTypes.Add(SPClaimEntityTypes.FormsRole);
        }

        protected override void FillClaimsForEntity(Uri context, SPClaim entity, List<SPClaim> claims)
        {
            if (entity == null) throw new ArgumentNullException("entity");

            if (claims == null) throw new ArgumentNullException("claims");

            if (!setupDBConnection()) return;
            
            SPClaim userIdentityClaim = entity;
            try
            {
                userIdentityClaim = SPClaimProviderManager.DecodeUserIdentifierClaim(entity);
            }
            catch (Exception ex)
            {
                _dl.LogMessage(string.Format("Error decoding user identity claim for user {0}", userIdentityClaim.Value), DataLayer.MessageSeverity.Warning, 2002, ex);
            }

            if (userIdentityClaim.ClaimType == this.IdentityClaimType)
            {
                SPSecurity.RunWithElevatedPrivileges(delegate ()
                {
                    if (_logVerbose) _dl.LogMessage(string.Format("FillClaimsForEntity called with ClaimType: {0} and ValueType: {1} and OriginalIssuer: {2} and Value: {3}",
                        userIdentityClaim.ClaimType, userIdentityClaim.ValueType, userIdentityClaim.OriginalIssuer, userIdentityClaim.Value), DataLayer.MessageSeverity.Information);
                    eAuthUser user = _dl.GetUser(userIdentityClaim.Value, false, false);
                    if (user != null)
                    {
                        List<eAuthRole> roles = _dl.GetUserRoles(user);
                        foreach (eAuthRole role in roles)
                        {
                            if (_logVerbose) _dl.LogMessage(string.Format("Added claim to Identity: {0} with ClaimType: {1} and Value: {2}", userIdentityClaim.Value, role.ClaimType, role.RoleName), DataLayer.MessageSeverity.Information);
                            claims.Add(CreateClaimForSTS(role.ClaimType, role.RoleName));
                        }
                    }
                });
            }
            else
            {
                if (_logVerbose) _dl.LogMessage(string.Format("FillClaimsForEntity called with invalid identity ClaimType: {0} and ClaimValue: {1}", userIdentityClaim.ClaimType, userIdentityClaim.Value), DataLayer.MessageSeverity.Warning, 2003);
            }
        }

        protected override void FillHierarchy(Uri context, string[] entityTypes, string hierarchyNodeID, int numberOfLevels, SPProviderHierarchyTree hierarchy)
        {
            throw new NotImplementedException();
        }

        protected override void FillResolve(Uri context, string[] entityTypes, SPClaim resolveInput, List<PickerEntity> resolved)
        {
            if (!setupDBConnection()) return;

            SPOriginalIssuerType loginType = SPOriginalIssuers.GetIssuerType(resolveInput.OriginalIssuer);
            if ((loginType == SPOriginalIssuerType.TrustedProvider) || (loginType == SPOriginalIssuerType.ClaimProvider))
            {
                if ((!EntityTypesContain(entityTypes, SPClaimEntityTypes.User)) && (!EntityTypesContain(entityTypes, SPClaimEntityTypes.FormsRole))) return;
            }
            
            SPSecurity.RunWithElevatedPrivileges(delegate ()
            {
                if (_logVerbose) _dl.LogMessage(string.Format("FillResolve called with ClaimType: {0} and ClaimValue: {1}", resolveInput.ClaimType, resolveInput.Value), DataLayer.MessageSeverity.Information);

                if (resolveInput.ClaimType == this.IdentityClaimType)
                {
                    eAuthUser user = _dl.GetUser(resolveInput.Value, false, false);
                    if (user != null)
                    {
                        resolved.Add(GetIdentityPickerEntity(user, context));
                    }
                }
                else if (resolveInput.ClaimType == this.RoleClaimType)
                {
                    List<string> roles = _dl.GetAllRoles();
                    var matchedRoles = roles.Where(claim => claim.IndexOf(resolveInput.Value, StringComparison.InvariantCultureIgnoreCase) >= 0).Select(claim => claim);
                    if ((matchedRoles != null) && (matchedRoles.Count() > 0))
                    {
                        foreach (string roleName in matchedRoles)
                        {
                            resolved.Add(GetRolePickerEntity(roleName, context));
                        }
                    }
                }
            });
        }

        protected override void FillResolve(Uri context, string[] entityTypes, string resolveInput, List<PickerEntity> resolved)
        {
            if (!setupDBConnection()) return;

            if ((!EntityTypesContain(entityTypes, SPClaimEntityTypes.User)) && (!EntityTypesContain(entityTypes, SPClaimEntityTypes.FormsRole))) return;

            SPSecurity.RunWithElevatedPrivileges(delegate ()
            {
                if (_logVerbose) _dl.LogMessage(string.Format("FillResolve called with resolveInput: {0}", resolveInput), DataLayer.MessageSeverity.Information);
                List<eAuthUser> users = _dl.LookupUsers(resolveInput, DataLayer.QueryType.SearchAllUserFieldsContains);
                if ((users != null) && (users.Count > 0))
                {
                    foreach (eAuthUser user in users)
                    {
                        if (user != null)
                        {
                            resolved.Add(GetIdentityPickerEntity(user, context));
                        }
                    }
                }
                
                List<string> roles = _dl.GetAllRoles();
                var matchedRoles = roles.Where(claim => claim.IndexOf(resolveInput, StringComparison.InvariantCultureIgnoreCase) >= 0).Select(claim => claim);
                if ((matchedRoles != null) && (matchedRoles.Count() > 0))
                {
                    foreach (string roleName in matchedRoles)
                    {
                        resolved.Add(GetRolePickerEntity(roleName, context));
                    }
                }
            });
        }

        protected override void FillSchema(SPProviderSchema schema)
        {
            if ((setupDBConnection()) && (_logVerbose)) _dl.LogMessage("FillSchema called", DataLayer.MessageSeverity.Information);

            schema.AddSchemaElement(new SPSchemaElement(PeopleEditorEntityDataKeys.DisplayName, "DisplayName", SPSchemaElementType.Both));
            schema.AddSchemaElement(new SPSchemaElement(PeopleEditorEntityDataKeys.Email, "EmailAddress", SPSchemaElementType.Both));
            schema.AddSchemaElement(new SPSchemaElement(PeopleEditorEntityDataKeys.JobTitle, "Identity", SPSchemaElementType.Both));
        }

        protected override void FillSearch(Uri context, string[] entityTypes, string searchPattern, string hierarchyNodeID, int maxCount, SPProviderHierarchyTree searchTree)
        {
            if (!setupDBConnection()) return;

            if ((!EntityTypesContain(entityTypes, SPClaimEntityTypes.User)) && (!EntityTypesContain(entityTypes, SPClaimEntityTypes.FormsRole))) return;
            
            SPSecurity.RunWithElevatedPrivileges(delegate ()
            {
                if (_logVerbose) _dl.LogMessage(string.Format("FillSearch called with searchPattern: {0}", searchPattern), DataLayer.MessageSeverity.Information);
                List<eAuthUser> matchedUsers = _dl.LookupUsers(searchPattern, DataLayer.QueryType.SearchAllUserFieldsContains);
                if ((matchedUsers != null) && (matchedUsers.Count > 0))
                {
                    foreach (eAuthUser user in matchedUsers)
                    {
                        if (user != null)
                        {
                            searchTree.AddEntity(GetIdentityPickerEntity(user, context));
                        }
                    }
                }

                List<string> roles = _dl.GetAllRoles();
                var matchedRoles = roles.Where(claim => claim.IndexOf(searchPattern, StringComparison.InvariantCultureIgnoreCase) >= 0).Select(claim => claim);
                if ((matchedRoles != null) && (matchedRoles.Count() > 0))
                {
                    foreach (string roleName in matchedRoles)
                    {
                        searchTree.AddEntity(GetRolePickerEntity(roleName, context));
                    }
                }
            });
        }
        #endregion
        #region Internal Methods
        internal static string ProviderInternalName
        {
            get
            {
                return "eAuthenticationClaimsProvider";
            }
        }
        internal static string ProviderDisplayName
        {
            get
            {
                return GetFarmProperty("eAuthClaimsProviderName");
            }
        }
        #endregion
        #region Private Methods
        private SPClaim CreateClaimForSTS(string claimType, string claimValue)
        {
            SPClaim result = new SPClaim(claimType, claimValue, _claimValueType, SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, ProviderDisplayName));
            return result;
        }
        private static string GetFarmProperty(string propName)
        {
            string propValue = string.Empty;
            SPFarm farm = SPFarm.Local;
            if (farm.Properties != null && farm.Properties.Count > 0)
            {
                if (farm.Properties.ContainsKey(propName))
                {
                    propValue = farm.Properties[propName].ToString();
                }
            }
            return propValue;
        }
        private PickerEntity GetIdentityPickerEntity(eAuthUser user, Uri context)
        {
            PickerEntity pe = CreatePickerEntity();
            pe.Claim = new SPClaim(this.IdentityClaimType, user.Identity, _claimValueType, SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, GetIdentityProviderName(context)));
            
            if (!string.IsNullOrEmpty(user.EmailAddress)) pe.Description = user.EmailAddress;
            else pe.Description = pe.Claim.Value;

            if (!string.IsNullOrEmpty(user.DisplayName)) pe.DisplayText = user.DisplayName;
            else if (!string.IsNullOrEmpty(user.EmailAddress)) pe.DisplayText = user.EmailAddress;
            else pe.DisplayText = user.Identity;

            pe.EntityData[PeopleEditorEntityDataKeys.DisplayName] = pe.DisplayText;
            pe.EntityData[PeopleEditorEntityDataKeys.Email] = user.EmailAddress;
            pe.EntityData[PeopleEditorEntityDataKeys.JobTitle] = pe.Description;

            pe.EntityType = SPClaimEntityTypes.User;
            pe.IsResolved = true;
            pe.EntityGroupName = "Users";

            if (_logVerbose) _dl.LogMessage(string.Format("XML for PickerEntry: {0}", pe.ToXmlData()), DataLayer.MessageSeverity.Information);

            return pe;
        }
        private PickerEntity GetRolePickerEntity(string roleName, Uri context)
        {
            PickerEntity pe = CreatePickerEntity();
            pe.Claim = new SPClaim(this.RoleClaimType, roleName, _claimValueType, SPOriginalIssuers.Format(SPOriginalIssuerType.TrustedProvider, GetIdentityProviderName(context)));
            pe.Description = "Role";
            pe.DisplayText = roleName;

            pe.EntityData[PeopleEditorEntityDataKeys.DisplayName] = pe.DisplayText;
            pe.EntityData[PeopleEditorEntityDataKeys.Email] = string.Empty;
            pe.EntityData[PeopleEditorEntityDataKeys.JobTitle] = pe.Description;

            pe.EntityType = SPClaimEntityTypes.FormsRole;
            pe.IsResolved = true;
            pe.EntityGroupName = "Roles";

            if (_logVerbose) _dl.LogMessage(string.Format("XML for PickerEntry: {0}", pe.ToXmlData()), DataLayer.MessageSeverity.Information);

            return pe;
        }
        private bool setupDBConnection()
        {
            bool result = false;
            try
            {
                if ((_identityClaimType != null) && (_roleClaimType != null)) return true;

                _connectionString = GetFarmProperty("eAuthConnectionString");
                Boolean.TryParse(GetFarmProperty("eAuthLogToDB"), out _logToDB);
                Boolean.TryParse(GetFarmProperty("eAuthLogToEvent"), out _logToEvent);
                Boolean.TryParse(GetFarmProperty("eAuthLogVerbose"), out _logVerbose);
                _dl = new DataLayer(_connectionString, _logToDB, _logToEvent, _logVerbose);
                _claimValueType = System.Security.Claims.ClaimValueTypes.String;

                SPSecurity.RunWithElevatedPrivileges(delegate ()
                {
                    _identityClaimType = _dl.GetIdentityClaimType();
                    _roleClaimType = _dl.GetRoleClaimType();
                    result = true;
                });
            }
            catch (Exception ex)
            {
                SPDiagnosticsService.Local.WriteTrace(0, new SPDiagnosticsCategory("eAuthentication Claims Provider", TraceSeverity.Unexpected, EventSeverity.Error), TraceSeverity.Unexpected, String.Format("[eAuthentication Claims Provider] Unexpected exception. Error: {0}", ex.Message), null);
            }

            return result;
        }
        #endregion
    }
}
