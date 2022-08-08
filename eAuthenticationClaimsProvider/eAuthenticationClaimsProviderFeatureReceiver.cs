using Microsoft.SharePoint;
using Microsoft.SharePoint.Administration.Claims;

namespace eAuthentication.eAuthenticationClaimsProvider
{
    public class eAuthenticationClaimsProviderFeatureReceiver : SPClaimProviderFeatureReceiver
    {
        private void ExecBaseFeatureActivated(SPFeatureReceiverProperties properties)
        {
            base.FeatureActivated(properties);
            SPSecurityTokenServiceManager sptMgr = SPSecurityTokenServiceManager.Local;
            SPTrustedLoginProvider spt = sptMgr.TrustedLoginProviders[eAuthenticationClaimsProvider.ProviderDisplayName];
            if (spt != null)
            {
                spt.ClaimProviderName = eAuthenticationClaimsProvider.ProviderInternalName;
                spt.Update();
            }
        }

        public override string ClaimProviderAssembly
        {
            get
            {
                return typeof(eAuthenticationClaimsProvider).Assembly.FullName;
            }
        }

        public override string ClaimProviderDescription
        {
            get
            {
                return "eAuthentication Claims Provider";
            }
        }

        public override string ClaimProviderDisplayName
        {
            get
            {
                return eAuthenticationClaimsProvider.ProviderDisplayName;
            }
        }

        public override string ClaimProviderType
        {
            get
            {
                return typeof(eAuthenticationClaimsProvider).FullName;
            }
        }

        public override bool ClaimProviderUsedByDefault
        {
            get
            {
                return true;
            }
        }

        public override void FeatureActivated(SPFeatureReceiverProperties properties)
        {
            ExecBaseFeatureActivated(properties);
        }
    }
}
