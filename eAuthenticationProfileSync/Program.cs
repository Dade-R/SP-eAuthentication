using System;

namespace eAuthentication.eAuthenticationProfileSync
{
    public class Program
    {
        static void Main(string[] args)
        {
            Profile profile = new Profile();
            profile.Sync();
        }
    }
}