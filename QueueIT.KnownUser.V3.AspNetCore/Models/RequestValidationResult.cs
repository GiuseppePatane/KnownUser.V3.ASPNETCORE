namespace QueueIT.KnownUser.V3.AspNetCore.Models
{
    public class RequestValidationResult
    {
        public RequestValidationResult(
            string actionType,
            string eventId = null,
            string queueId = null,
            string redirectUrl = null,
            string redirectType = null,
            string actionName = null,
            bool isAjaxResult = false)
        {
            ActionType = actionType;
            EventId = eventId;
            QueueId = queueId;
            RedirectUrl = redirectUrl;
            RedirectType = redirectType;
            ActionName = actionName;
            IsAjaxResult = isAjaxResult;
        }

        public string RedirectUrl { get; }
        public string QueueId { get; }
        public bool DoRedirect
        {
            get
            {
                return !string.IsNullOrEmpty(RedirectUrl);
            }
        }
        public string EventId { get; }
        public string ActionType { get; }
        public string ActionName { get; }
        public string RedirectType { get; }
        public bool IsAjaxResult { get; internal set; }
        public string AjaxQueueRedirectHeaderKey
        {
            get
            {
                return "x-queueit-redirect";
            }
        }
        public string AjaxRedirectUrl
        {
            get
            {
                if (!string.IsNullOrEmpty(RedirectUrl))
                {
                    return System.Uri.EscapeDataString(RedirectUrl);
                }
                return string.Empty;
            }
        }
    }
}
