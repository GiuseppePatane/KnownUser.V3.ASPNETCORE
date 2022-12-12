namespace QueueIT.KnownUser.V3.AspNetCore.Models
{
    public class QueueEventConfig
    {
        public QueueEventConfig()
        {
            Version = -1;
            ActionName = "unspecified";
        }

        public string EventId { get; set; }
        public string LayoutName { get; set; }
        public string Culture { get; set; }
        public string QueueDomain { get; set; }
        public bool ExtendCookieValidity { get; set; }
        public int CookieValidityMinute { get; set; }
        public string CookieDomain { get; set; }
        public bool IsCookieHttpOnly { get; set; }
        public bool IsCookieSecure { get; set; }
        public int Version { get; set; }
        public string ActionName { get; set; }

        public override string ToString()
        {
            return $"EventId:{EventId}" +
                   $"&Version:{Version}" +
                   $"&QueueDomain:{QueueDomain}" +
                   $"&CookieDomain:{CookieDomain}" +
                   $"&IsCookieHttpOnly:{IsCookieHttpOnly}" +
                   $"&IsCookieSecure:{IsCookieSecure}" +
                   $"&ExtendCookieValidity:{ExtendCookieValidity}" +
                   $"&CookieValidityMinute:{CookieValidityMinute}" +
                   $"&LayoutName:{LayoutName}" +
                   $"&Culture:{Culture}" +
                   $"&ActionName:{ActionName}";
        }
    }
}