using QueueIT.KnownUser.V3.AspNetCore.Models;

namespace QueueIT.KnownUser.V3.AspNetCore.Abstractions
{
    public interface IUserInQueueService
    {
        RequestValidationResult ValidateQueueRequest(
            string targetUrl,
            string queueitToken,
            QueueEventConfig config,
            string customerId,
            string secretKey);

        RequestValidationResult ValidateCancelRequest(
            string targetUrl,
            CancelEventConfig config,
            string customerId,
            string secretKey);

        RequestValidationResult GetIgnoreResult(string actionName);

        void ExtendQueueCookie(
            string eventId,
            int cookieValidityMinutes,
            string cookieDomain,
            bool isCookieHttpOnly,
            bool isCookieSecure,
            string secretKey);
    }
}