using System;
using System.Collections.Specialized;

namespace QueueIT.KnownUser.V3.AspNetCore.Abstractions
{
    public interface IHttpRequest
    {
        string UserAgent { get; }
        NameValueCollection Headers { get; }
        Uri Url { get; }
        string UserHostAddress { get; }
        string GetCookieValue(string cookieKey);
        string GetRequestBodyAsString();
    }
}