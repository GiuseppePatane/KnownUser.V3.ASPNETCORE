using System;
using System.Collections.Specialized;
using Microsoft.AspNetCore.Http;
using QueueIT.KnownUser.V3.AspNetCore.Abstractions;

namespace QueueIT.KnownUser.V3.AspNetCore.Http
{
    public class HttpRequest : IHttpRequest
    {
        private HttpContext _context;

        public HttpRequest(HttpContext context)
        {
            _context = context;
            Headers = new NameValueCollection();
            foreach (var name in _context.Request.Headers.Keys)
            {
                Headers.Add(name, _context.Request.Headers[name]);
            }
            Url = new Uri($"{_context.Request.Scheme}://{_context.Request.Host}{_context.Request.Path}{_context.Request.QueryString}");
         
        }

        public string UserAgent => _context.Request.Headers["User-Agent"].ToString();

        public NameValueCollection Headers { get; }

        public Uri Url { get; }

        public string UserHostAddress => _context.Connection.RemoteIpAddress.ToString();

        public string GetCookieValue(string cookieKey)
        {
            return _context.Request.Cookies[cookieKey];
        }

        public virtual string GetRequestBodyAsString()
        {
            return string.Empty;
        }
    }
}