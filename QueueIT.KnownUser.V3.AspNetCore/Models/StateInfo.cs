namespace QueueIT.KnownUser.V3.AspNetCore.Models
{
    internal class StateInfo
    {
        public bool IsFound { get; }
        public bool IsValid { get; }
        public string QueueId { get; }
        public bool IsStateExtendable => IsValid && !FixedCookieValidityMinutes.HasValue;
        public int? FixedCookieValidityMinutes { get; }
        public string RedirectType { get; }

        public StateInfo(bool isFound, bool isValid, string queueId, int? fixedCookieValidityMinutes, string redirectType)
        {
            IsFound = isFound;
            IsValid = isValid;
            QueueId = queueId;
            FixedCookieValidityMinutes = fixedCookieValidityMinutes;
            RedirectType = redirectType;
        }
    }
}