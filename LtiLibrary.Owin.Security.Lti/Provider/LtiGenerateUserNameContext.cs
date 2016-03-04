using System;
using LtiLibrary.Core.Lti1;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace LtiLibrary.Owin.Security.Lti.Provider
{
    public class LtiGenerateUserNameContext : BaseContext
    {
        public LtiGenerateUserNameContext(IOwinContext context, ILtiRequest ltiRequest) : base(context)
        {
            if (ltiRequest == null)
            {
                throw new ArgumentNullException("ltiRequest");
            }
            LtiRequest = ltiRequest;
        }

        /// <summary>
        /// Generate a valid application username using information from an LTI request. The default
        /// ASP.NET application using Microsoft Identity uses an email address as the username. This
        /// code will generate an "anonymous" email address if one is not supplied in the LTI request.
        /// </summary>
        public string GenerateUserName()
        {
            if (string.IsNullOrEmpty(LtiRequest.LisPersonEmailPrimary))
            {
                var username = string.Concat("anon-", LtiRequest.UserId);
                Uri url;
                if (string.IsNullOrEmpty(LtiRequest.ToolConsumerInstanceUrl)
                    || !Uri.TryCreate(LtiRequest.ToolConsumerInstanceUrl, UriKind.Absolute, out url))
                {
                    return string.Concat(username, "@anon-", LtiRequest.ConsumerKey, ".lti");
                }
                else
                {
                    return string.Concat(username, "@", url.Host);
                }
            }
            else
            {
                return LtiRequest.LisPersonEmailPrimary;
            }
        }

        public ILtiRequest LtiRequest { get; private set; }
        public string UserName { get; set; }
    }
}
