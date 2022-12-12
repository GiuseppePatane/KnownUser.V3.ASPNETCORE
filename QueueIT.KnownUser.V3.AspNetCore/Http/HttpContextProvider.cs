using System;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;
using QueueIT.KnownUser.V3.AspNetCore.Abstractions;

[assembly: InternalsVisibleTo("QueueIT.KnownUser.V3.AspNetCore.Tests")]
[assembly: InternalsVisibleTo("DynamicProxyGenAssembly2")]
namespace QueueIT.KnownUser.V3.AspNetCore.Http
{
    internal class HttpContextProvider : IHttpContextProvider
    {
        private IHttpRequest _httpRequest;
        public IHttpRequest HttpRequest
        {
            get
            {
                if (_httpRequest == null)
                {
                    throw new Exception("Call SDKInitializer.SetHttpContext to configure SDK");
                }

                return _httpRequest;
            }
        }

        private IHttpResponse _httpResponse;
        public IHttpResponse HttpResponse
        {
            get
            {
                if (_httpResponse == null)
                {
                    throw new Exception("Call SDKInitializer.SetHttpContext to configure SDK");
                }

                return _httpResponse;
            }
        }

        public static IHttpContextProvider Instance { get; } = new HttpContextProvider();

        public static void SetHttpContext(HttpContext context)
        {
            ((HttpContextProvider)Instance)._httpRequest = new HttpRequest(context);
            ((HttpContextProvider)Instance)._httpResponse = new HttpResponse(context);
        }

        public static void SetHttpRequest(IHttpRequest httpRequest)
        {
            ((HttpContextProvider)Instance)._httpRequest = httpRequest;
        }
    }
}
