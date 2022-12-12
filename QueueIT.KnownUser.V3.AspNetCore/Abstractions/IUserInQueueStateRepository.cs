using QueueIT.KnownUser.V3.AspNetCore.Models;

namespace QueueIT.KnownUser.V3.AspNetCore.Abstractions
{
    internal interface IUserInQueueStateRepository
    {
        void Store(
            string eventId,
            string queueId,
            int? fixedCookieValidityMinutes,
            string cookieDomain,
            bool isCookieHttpOnly,
            bool isCookieSecure,
            string redirectType,
            string secretKey);

        StateInfo GetState(
            string eventId,
            int cookieValidityMinutes,
            string secretKey,
            bool validateTime = true);

        void CancelQueueCookie(
            string eventId,
            string cookieDomain,
            bool isCookieHttpOnly,
            bool isCookieSecure);

        void ReissueQueueCookie(
            string eventId,
            int cookieValidityMinutes,
            string cookieDomain,
            bool isCookieHttpOnly,
            bool isCookieSecure,
            string secretKey);
    }
}