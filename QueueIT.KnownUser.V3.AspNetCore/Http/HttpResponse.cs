using System;
using Microsoft.AspNetCore.Http;
using QueueIT.KnownUser.V3.AspNetCore.Abstractions;

namespace QueueIT.KnownUser.V3.AspNetCore.Http
{
    internal class HttpResponse : IHttpResponse
    {
        private HttpContext _context;

        public HttpResponse(HttpContext context)
        {
            _context = context;
        }

        public void SetCookie(string cookieName, string cookieValue, string domain, DateTime expiration, bool isHttpOnly, bool isSecure)
        {
            var cookieOptions = new CookieOptions
            {
                Expires = expiration,
                HttpOnly = isHttpOnly,
                Secure = isSecure,
            };

            if (!string.IsNullOrEmpty(domain))
            {
                cookieOptions.Domain = domain;
            }
            _context.Response.Cookies.Append(cookieName, cookieValue, cookieOptions);
        }
    }
}