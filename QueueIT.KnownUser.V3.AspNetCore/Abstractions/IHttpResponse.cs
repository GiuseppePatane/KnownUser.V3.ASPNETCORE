using System;

namespace QueueIT.KnownUser.V3.AspNetCore.Abstractions
{
    public interface IHttpResponse
    {
        void SetCookie(string cookieName, string cookieValue, string domain, DateTime expiration, bool isCookieHttpOnly, bool isCookieSecure);
    }
}