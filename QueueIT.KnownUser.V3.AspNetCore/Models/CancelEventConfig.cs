namespace QueueIT.KnownUser.V3.AspNetCore.Models
{
    public class CancelEventConfig
    {
        public CancelEventConfig()
        {
            Version = -1;
            ActionName = "unspecified";
        }

        public string EventId { get; set; }
        public string QueueDomain { get; set; }
        public int Version { get; set; }
        public string CookieDomain { get; set; }
        public bool IsCookieHttpOnly { get; set; }
        public bool IsCookieSecure { get; set; }
        public string ActionName { get; set; }

        public override string ToString()
        {
            return $"EventId:{EventId}" +
                   $"&Version:{Version}" +
                   $"&QueueDomain:{QueueDomain}" +
                   $"&CookieDomain:{CookieDomain}" +
                   $"&IsCookieHttpOnly:{IsCookieHttpOnly}" +
                   $"&IsCookieSecure:{IsCookieSecure}" +
                   $"&ActionName:{ActionName}";
        }
    }
}