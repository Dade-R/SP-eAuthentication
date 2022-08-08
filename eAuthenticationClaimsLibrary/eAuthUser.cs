using System;

namespace eAuthentication.eAuthenticationClaimsLibrary
{
    public class eAuthUser
    {
        public int ID;
        public string Identity;
        public string EmailAddress;
        public string DisplayName;
        public bool isApproved;
        public bool isSecurityApproved;
        public bool isTOUAccepted;
        public DateTime? createDate;
        public DateTime? TOUAcceptedDate;
        public DateTime? lastModifiedDate;
        public DateTime? lastLoginDate;
        public int loginCount;
    }
}