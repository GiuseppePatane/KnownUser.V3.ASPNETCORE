using QueueIT.KnownUser.V3.AspNetCore.Abstractions;

namespace QueueIT.KnownUser.V3.AspNetCore.Http
{
    internal class HttpContextProviderNew : IHttpContextProvider
    {
        public HttpContextProviderNew(IHttpRequest httpRequest, IHttpResponse httpResponse)
        {
            HttpRequest = httpRequest;
            HttpResponse = httpResponse;
        }

        public IHttpRequest HttpRequest { get; }
        public IHttpResponse HttpResponse { get; }
    }
}