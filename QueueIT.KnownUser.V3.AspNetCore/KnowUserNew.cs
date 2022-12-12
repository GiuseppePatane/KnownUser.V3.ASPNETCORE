using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Web;
using Microsoft.AspNetCore.Http;
using QueueIT.KnownUser.V3.AspNetCore.Abstractions;
using QueueIT.KnownUser.V3.AspNetCore.Helpers;
using QueueIT.KnownUser.V3.AspNetCore.Http;
using QueueIT.KnownUser.V3.AspNetCore.IntegrationConfig;
using QueueIT.KnownUser.V3.AspNetCore.Models;
using QueueIT.KnownUser.V3.AspNetCore.Repositories;
using QueueIT.KnownUser.V3.AspNetCore.Services;
using HttpRequest = QueueIT.KnownUser.V3.AspNetCore.Http.HttpRequest;
using HttpResponse = QueueIT.KnownUser.V3.AspNetCore.Http.HttpResponse;

namespace QueueIT.KnownUser.V3.AspNetCore
{
    public class KnownUser
    {
        public const string QueueITTokenKey = "queueittoken";
        public const string QueueITDebugKey = "queueitdebug";
        public const string QueueITAjaxHeaderKey = "x-queueit-ajaxpageurl";

        private IHttpRequest _request;
        private IHttpResponse _response;
        public IUserInQueueService UserInQueueService;


        public RequestValidationResult ResolveQueueRequestByLocalConfig(HttpContext httpContext,
            string targetUrl, string queueitToken, QueueEventConfig queueConfig,
            string customerId, string secretKey)
        {
            var connectorDiagnostics = ConnectorDiagnostics.Verify(customerId, secretKey, queueitToken);

            if (connectorDiagnostics.HasError)
                return connectorDiagnostics.ValidationResult;

            SetContext(httpContext);

            var debugEntries = new Dictionary<string, string>();
            try
            {
                targetUrl = GenerateTargetUrl(targetUrl);
                return ResolveQueueRequestByLocalConfig(targetUrl, queueitToken, queueConfig, customerId, secretKey,
                    debugEntries, connectorDiagnostics.IsEnabled);
            }
            catch (Exception e)
            {
                if (connectorDiagnostics.IsEnabled)
                    debugEntries["Exception"] = e.Message;
                throw;
            }
            finally
            {
                SetDebugCookie(debugEntries);
            }
        }

        public RequestValidationResult ValidateRequestByIntegrationConfig(HttpContext httpContext,
           string currentUrlWithoutQueueITToken, string queueitToken,
           CustomerIntegration customerIntegrationInfo, string customerId, string secretKey)
        {
            var debugEntries = new Dictionary<string, string>();
            var connectorDiagnostics = ConnectorDiagnostics.Verify(customerId, secretKey, queueitToken);

            SetContext(httpContext);
            if (connectorDiagnostics.HasError)
                return connectorDiagnostics.ValidationResult;
            try
            {
                if (connectorDiagnostics.IsEnabled)
                {
                    debugEntries["SdkVersion"] = Services.UserInQueueService.SDK_VERSION;
                    debugEntries["Runtime"] = GetRuntime();
                    debugEntries["ConfigVersion"] = customerIntegrationInfo != null ? customerIntegrationInfo.Version.ToString() : "NULL";
                    debugEntries["PureUrl"] = currentUrlWithoutQueueITToken;
                    debugEntries["QueueitToken"] = queueitToken;
                    debugEntries["OriginalUrl"] = _request.Url.AbsoluteUri;

                    LogExtraRequestDetails(debugEntries);
                }
                if (string.IsNullOrEmpty(currentUrlWithoutQueueITToken))
                    throw new ArgumentException("currentUrlWithoutQueueITToken can not be null or empty.");
                if (customerIntegrationInfo == null)
                    throw new ArgumentException("customerIntegrationInfo can not be null.");

                var configEvaluater = new IntegrationEvaluator();

                var matchedConfig = configEvaluater.GetMatchedIntegrationConfig(
                    customerIntegrationInfo,
                    currentUrlWithoutQueueITToken,
                    _request);

                if (connectorDiagnostics.IsEnabled)
                {
                    debugEntries["MatchedConfig"] = matchedConfig != null ? matchedConfig.Name : "NULL";
                }
                if (matchedConfig == null)
                    return new RequestValidationResult(null);

                switch (matchedConfig.ActionType ?? string.Empty)
                {
                    case ""://backward compatibility
                    case ActionType.QueueAction:
                        {
                            return HandleQueueAction(currentUrlWithoutQueueITToken, queueitToken, customerIntegrationInfo,
                                        customerId, secretKey, debugEntries, matchedConfig, connectorDiagnostics.IsEnabled);
                        }
                    case ActionType.CancelAction:
                        {
                            return HandleCancelAction(currentUrlWithoutQueueITToken, queueitToken, customerIntegrationInfo,
                                        customerId, secretKey, debugEntries, matchedConfig, connectorDiagnostics.IsEnabled);
                        }
                    default:
                        {
                            return HandleIgnoreAction(matchedConfig.Name);
                        }
                }
            }
            catch (Exception e)
            {
                if (connectorDiagnostics.IsEnabled)
                    debugEntries["Exception"] = e.Message;
                throw;
            }
            finally
            {
                SetDebugCookie(debugEntries);
            }
        }

        public RequestValidationResult CancelRequestByLocalConfig(HttpContext httpContext,
            string targetUrl, string queueitToken, CancelEventConfig cancelConfig,
            string customerId, string secretKey)
        {
            var debugEntries = new Dictionary<string, string>();
            var connectorDiagnostics = ConnectorDiagnostics.Verify(customerId, secretKey, queueitToken);
            if (connectorDiagnostics.HasError)
                return connectorDiagnostics.ValidationResult;

            SetContext(httpContext);
            try
            {
                return CancelRequestByLocalConfig(targetUrl, queueitToken, cancelConfig, customerId, secretKey, debugEntries, connectorDiagnostics.IsEnabled);
            }
            catch (Exception e)
            {
                if (connectorDiagnostics.IsEnabled)
                    debugEntries["Exception"] = e.Message;
                throw;
            }
            finally
            {
                SetDebugCookie(debugEntries);
            }
        }

        public void ExtendQueueCookie(
            string eventId,
            int cookieValidityMinute,
            string cookieDomain,
            bool isCookieHttpOnly,
            bool isCookieSecure,
            string secretKey)
        {
            if (string.IsNullOrEmpty(eventId))
                throw new ArgumentException("eventId can not be null or empty.");
            if (cookieValidityMinute <= 0)
                throw new ArgumentException("cookieValidityMinute should be greater than 0.");
            if (string.IsNullOrEmpty(secretKey))
                throw new ArgumentException("secretKey can not be null or empty.");

            var userInQueueService = GetUserInQueueService();
            userInQueueService.ExtendQueueCookie(eventId, cookieValidityMinute, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey);
        }
        private void SetContext(HttpContext httpContext)
        {
            _request = new HttpRequest(httpContext);
            _response = new HttpResponse(httpContext);
        }


        private RequestValidationResult HandleQueueAction(
            string currentUrlWithoutQueueITToken,
            string queueitToken,
            CustomerIntegration customerIntegrationInfo,
            string customerId,
            string secretKey,
            Dictionary<string, string> debugEntries,
            IntegrationConfigModel matchedConfig,
            bool isDebug)
        {
            var targetUrl = "";
            switch (matchedConfig.RedirectLogic)
            {
                case "ForcedTargetUrl":
                case "ForecedTargetUrl":
                    targetUrl = matchedConfig.ForcedTargetUrl;
                    break;
                case "EventTargetUrl":
                    targetUrl = "";
                    break;
                default:
                    targetUrl = GenerateTargetUrl(currentUrlWithoutQueueITToken);
                    break;
            }

            var queueEventConfig = new QueueEventConfig
            {
                QueueDomain = matchedConfig.QueueDomain,
                Culture = matchedConfig.Culture,
                EventId = matchedConfig.EventId,
                ExtendCookieValidity = matchedConfig.ExtendCookieValidity.Value,
                LayoutName = matchedConfig.LayoutName,
                CookieValidityMinute = matchedConfig.CookieValidityMinute.Value,
                CookieDomain = matchedConfig.CookieDomain,
                IsCookieHttpOnly = matchedConfig.IsCookieHttpOnly ?? false,
                IsCookieSecure = matchedConfig.IsCookieSecure ?? false,
                Version = customerIntegrationInfo.Version,
                ActionName = matchedConfig.Name
            };

            return ResolveQueueRequestByLocalConfig(targetUrl, queueitToken, queueEventConfig, customerId, secretKey, debugEntries, isDebug);
        }
        private RequestValidationResult HandleCancelAction(
            string currentUrlWithoutQueueITToken, string queueitToken,
            CustomerIntegration customerIntegrationInfo, string customerId,
            string secretKey, Dictionary<string, string> debugEntries,
            IntegrationConfigModel matchedConfig, bool isDebug)
        {
            var cancelEventConfig = new CancelEventConfig
            {
                QueueDomain = matchedConfig.QueueDomain,
                EventId = matchedConfig.EventId,
                Version = customerIntegrationInfo.Version,
                CookieDomain = matchedConfig.CookieDomain,
                IsCookieHttpOnly = matchedConfig.IsCookieHttpOnly ?? false,
                IsCookieSecure = matchedConfig.IsCookieSecure ?? false,
                ActionName = matchedConfig.Name
            };
            return CancelRequestByLocalConfig(currentUrlWithoutQueueITToken, queueitToken, cancelEventConfig, customerId, secretKey, debugEntries, isDebug);
        }
        private RequestValidationResult CancelRequestByLocalConfig(
          string targetUrl, string queueitToken, CancelEventConfig cancelConfig,
          string customerId, string secretKey, Dictionary<string, string> debugEntries, bool isDebug)
        {
            targetUrl = GenerateTargetUrl(targetUrl);

            if (isDebug)
            {
                debugEntries["SdkVersion"] = Services.UserInQueueService.SDK_VERSION;
                debugEntries["Runtime"] = GetRuntime();
                debugEntries["TargetUrl"] = targetUrl;
                debugEntries["QueueitToken"] = queueitToken;
                debugEntries["CancelConfig"] = cancelConfig != null ? cancelConfig.ToString() : "NULL";
                debugEntries["OriginalUrl"] = _request.Url.AbsoluteUri;
                LogExtraRequestDetails(debugEntries);
            }
            if (string.IsNullOrEmpty(targetUrl))
                throw new ArgumentException("targeturl can not be null or empty.");
            if (string.IsNullOrEmpty(customerId))
                throw new ArgumentException("customerId can not be null or empty.");
            if (string.IsNullOrEmpty(secretKey))
                throw new ArgumentException("secretKey can not be null or empty.");
            if (cancelConfig == null)
                throw new ArgumentException("cancelEventConfig can not be null.");
            if (string.IsNullOrEmpty(cancelConfig.EventId))
                throw new ArgumentException("EventId from cancelEventConfig can not be null or empty.");
            if (string.IsNullOrEmpty(cancelConfig.QueueDomain))
                throw new ArgumentException("QueueDomain from cancelEventConfig can not be null or empty.");

            var userInQueueService = GetUserInQueueService();
            var result = userInQueueService.ValidateCancelRequest(targetUrl, cancelConfig, customerId, secretKey);
            result.IsAjaxResult = IsQueueAjaxCall();
            return result;
        }
        private RequestValidationResult HandleIgnoreAction(string actionName)
        {
            var userInQueueService = GetUserInQueueService();
            var result = userInQueueService.GetIgnoreResult(actionName);
            result.IsAjaxResult = IsQueueAjaxCall();
            return result;
        }

        private RequestValidationResult ResolveQueueRequestByLocalConfig(
            string targetUrl, string queueitToken, QueueEventConfig queueConfig,
            string customerId, string secretKey, Dictionary<string, string> debugEntries, bool isDebug)
        {
            if (isDebug)
            {
                debugEntries["SdkVersion"] = Services.UserInQueueService.SDK_VERSION;
                debugEntries["Runtime"] = GetRuntime();
                debugEntries["TargetUrl"] = targetUrl;
                debugEntries["QueueitToken"] = queueitToken;
                debugEntries["QueueConfig"] = queueConfig != null ? queueConfig.ToString() : "NULL";
                debugEntries["OriginalUrl"] = _request.Url.AbsoluteUri;
                LogExtraRequestDetails(debugEntries);
            }

            if (string.IsNullOrEmpty(customerId))
                throw new ArgumentException("customerId can not be null or empty.");
            if (string.IsNullOrEmpty(secretKey))
                throw new ArgumentException("secretKey can not be null or empty.");
            if (queueConfig == null)
                throw new ArgumentException("eventConfig can not be null.");
            if (string.IsNullOrEmpty(queueConfig.EventId))
                throw new ArgumentException("EventId from eventConfig can not be null or empty.");
            if (string.IsNullOrEmpty(queueConfig.QueueDomain))
                throw new ArgumentException("QueueDomain from eventConfig can not be null or empty.");
            if (queueConfig.CookieValidityMinute <= 0)
                throw new ArgumentException("CookieValidityMinute from eventConfig should be greater than 0.");

            queueitToken = queueitToken ?? string.Empty;

            var userInQueueService = GetUserInQueueService();
            var result =
                userInQueueService.ValidateQueueRequest(targetUrl, queueitToken, queueConfig, customerId, secretKey);
            result.IsAjaxResult = IsQueueAjaxCall();
            return result;
        }

        private void SetDebugCookie(Dictionary<string, string> debugEntries)
        {
            if (!debugEntries.Any())
                return;

            var cookieValue = string.Empty;
            foreach (var nameVal in debugEntries)
                cookieValue += $"{nameVal.Key}={nameVal.Value}|";

            cookieValue = cookieValue.TrimEnd('|');
            _response.SetCookie(QueueITDebugKey, cookieValue, null, DateTime.UtcNow.AddMinutes(20), false, false);
        }

        private string GenerateTargetUrl(string originalTargetUrl)
        {
            return !IsQueueAjaxCall()
                ? originalTargetUrl
                : HttpUtility.UrlDecode(_request.Headers[QueueITAjaxHeaderKey]);
        }

        private bool IsQueueAjaxCall()
        {
            return !string.IsNullOrEmpty(_request.Headers[QueueITAjaxHeaderKey]);
        }

        private void LogExtraRequestDetails(Dictionary<string, string> debugEntries)
        {
            debugEntries["ServerUtcTime"] = DateTime.UtcNow.ToString("o");
            debugEntries["RequestIP"] = _request.UserHostAddress;
            debugEntries["RequestHttpHeader_Via"] = _request.Headers["Via"];
            debugEntries["RequestHttpHeader_Forwarded"] = _request.Headers["Forwarded"];
            debugEntries["RequestHttpHeader_XForwardedFor"] = _request.Headers["X-Forwarded-For"];
            debugEntries["RequestHttpHeader_XForwardedHost"] = _request.Headers["X-Forwarded-Host"];
            debugEntries["RequestHttpHeader_XForwardedProto"] = _request.Headers["X-Forwarded-Proto"];
        }

        private IUserInQueueService GetUserInQueueService()
        {
            if (UserInQueueService == null)
            {
                UserInQueueService = new UserInQueueService(
                    new UserInQueueStateCookieRepository(new HttpContextProviderNew(_request, _response)));

            }
            return UserInQueueService;
        }
        public void SetUserInQueueService(IUserInQueueService userInQueueService)
        {
            if (userInQueueService == null) throw new ArgumentNullException(nameof(userInQueueService));


            UserInQueueService = userInQueueService;

        }


        public  string GetRuntime()
        {
            try
            {
                var asm = Assembly
                    .GetEntryAssembly();

                if (asm == null)
                    return "not-specified";

                var att = asm
                    .GetCustomAttribute<TargetFrameworkAttribute>();

                if (att == null)
                    return "not-specified";

                return att.FrameworkName;
            }
            catch
            {
                return "unknown";
            }
        }
    }
}