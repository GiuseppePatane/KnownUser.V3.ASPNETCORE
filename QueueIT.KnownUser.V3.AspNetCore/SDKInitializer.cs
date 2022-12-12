using Microsoft.AspNetCore.Http;
using QueueIT.KnownUser.V3.AspNetCore.Abstractions;
using QueueIT.KnownUser.V3.AspNetCore.Http;

namespace QueueIT.KnownUser.V3.AspNetCore
{
    public static class SDKInitializer
    {
        public static void SetHttpContext(HttpContext context)
        {
            HttpContextProvider.SetHttpContext(context);
        }

        public static void SetHttpRequest(IHttpRequest httpRequest)
        {
            HttpContextProvider.SetHttpRequest(httpRequest);
        }
    }
}