using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Web;
using Microsoft.AspNetCore.Http;
using QueueIT.KnownUser.V3.AspNetCore.Abstractions;
using QueueIT.KnownUser.V3.AspNetCore.IntegrationConfig;
using QueueIT.KnownUser.V3.AspNetCore.Models;
using Xunit;

namespace QueueIT.KnownUser.V3.AspNetCore.Tests
{

    public class KnownUserTest
    {
        private IDictionary<string, string> GetCookieData(HttpResponse response)
        {
            var cookieDictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (!response.Headers.Any())
            {
                return cookieDictionary;
            }


            var values = response.Headers["Set-Cookie"].First().TrimEnd(';').Split(';');
            foreach (var parts in values.Select(c => c.Split(new[] { '=' }, 2)))
            {
                var cookieName = parts[0].Trim();

                var cookieValue = parts.Length == 1 ? string.Empty : HttpUtility.UrlDecode(parts[1]);

                cookieDictionary[cookieName] = cookieValue;
            }

            return cookieDictionary;
        }

        public class MockHttpRequest : IHttpRequest
        {
            public MockHttpRequest()
            {
                Headers = new NameValueCollection();
            }

            public NameValueCollection CookiesValue { get; set; } = new();
            public string UserHostAddress { get; set; }
            public NameValueCollection Headers { get; set; }
            public string UserAgent { get; set; }
            public Uri Url { get; set; }
            public string Body { get; set; }

            public string GetCookieValue(string cookieKey)
            {
                return CookiesValue[cookieKey];
            }

            public string GetRequestBodyAsString()
            {
                return Body ?? string.Empty;
            }
        }

        public class MockHttpResponse : IHttpResponse
        {
            public Dictionary<string, Dictionary<string, object>> CookiesValue { get; set; } = new();

            public void SetCookie(string cookieName, string cookieValue, string domain, DateTime expiration,
                bool isHttpOnly, bool isSecure)
            {
                CookiesValue.Add(cookieName,
                    new Dictionary<string, object>
                    {
                        { nameof(cookieName), cookieName },
                        { nameof(cookieValue), cookieValue },
                        { nameof(domain), domain },
                        { nameof(expiration), expiration },
                        { nameof(isHttpOnly), isHttpOnly },
                        { nameof(isSecure), isSecure }
                    }
                );
            }
        }

        internal class HttpContextMock : IHttpContextProvider
        {
            public IHttpRequest HttpRequest { get; set; } = new MockHttpRequest();
            public IHttpResponse HttpResponse { get; set; } = new MockHttpResponse();
        }

        private class UserInQueueServiceMock : IUserInQueueService
        {
            public readonly List<List<string>> validateQueueRequestCalls = new();
            public readonly List<List<string>> extendQueueCookieCalls = new();
            public readonly List<List<string>> cancelRequestCalls = new();
            public readonly List<List<string>> ignoreRequestCalls = new();
            public bool validateQueueRequestRaiseException = false;
            public bool validateCancelRequestRaiseException = false;

            public RequestValidationResult ValidateQueueRequest(string targetUrl, string queueitToken,
                QueueEventConfig config, string customerId, string secretKey)
            {
                var args = new List<string>
                {
                    targetUrl,
                    queueitToken,
                    config.CookieDomain + ":"
                                        + config.LayoutName + ":"
                                        + config.Culture + ":"
                                        + config.EventId + ":"
                                        + config.QueueDomain + ":"
                                        + config.ExtendCookieValidity.ToString().ToLower() + ":"
                                        + config.CookieValidityMinute + ":"
                                        + config.Version + ":"
                                        + config.ActionName,
                    customerId,
                    secretKey
                };
                validateQueueRequestCalls.Add(args);

                if (validateQueueRequestRaiseException)
                    throw new Exception("Exception");

                return new RequestValidationResult("Queue");
            }

            public void ExtendQueueCookie(string eventId, int cookieValidityMinute, string cookieDomain,
                bool isCookieHttpOnly, bool isCookieSecure, string secretKey)
            {
                var args = new List<string>
                {
                    eventId,
                    cookieValidityMinute.ToString(),
                    cookieDomain,
                    isCookieHttpOnly.ToString(),
                    isCookieSecure.ToString(),
                    secretKey
                };
                extendQueueCookieCalls.Add(args);
            }

            public RequestValidationResult ValidateCancelRequest(string targetUrl, CancelEventConfig config,
                string customerId, string secretKey)
            {
                var args = new List<string>
                {
                    targetUrl,
                    config.CookieDomain + ":"
                                        + config.EventId + ":"
                                        + config.QueueDomain + ":"
                                        + config.Version + ":"
                                        + config.ActionName,
                    customerId,
                    secretKey
                };
                cancelRequestCalls.Add(args);

                if (validateCancelRequestRaiseException)
                    throw new Exception("Exception");

                return new RequestValidationResult("Cancel");
            }

            public RequestValidationResult GetIgnoreResult(string actionName)
            {
                ignoreRequestCalls.Add(new List<string> { actionName });
                return new RequestValidationResult("Ignore");
            }
        }

        private void AssertRequestCookieContent(string[] cookieValues, params string[] expectedValues)
        {
            Assert.True(cookieValues.Count(v => v.StartsWith("ServerUtcTime=")) == 1);
            Assert.True(cookieValues.Count(v => v.StartsWith("RequestIP=")) == 1);
            Assert.True(cookieValues.Count(v => v.StartsWith("RequestHttpHeader_Via=")) == 1);
            Assert.True(cookieValues.Count(v => v.StartsWith("RequestHttpHeader_Forwarded=")) == 1);
            Assert.True(cookieValues.Count(v => v.StartsWith("RequestHttpHeader_XForwardedFor=")) == 1);
            Assert.True(cookieValues.Count(v => v.StartsWith("RequestHttpHeader_XForwardedHost=")) == 1);
            Assert.True(cookieValues.Count(v => v.StartsWith("RequestHttpHeader_XForwardedProto=")) == 1);

            Assert.Contains(cookieValues, v => v == $"SdkVersion={expectedValues[0]}");
            Assert.Contains(cookieValues, v => v == $"Runtime={expectedValues[1]}");

            var utcTimeInCookie = cookieValues.FirstOrDefault(v => v.StartsWith("ServerUtcTime"))?.Split('=')[1];
            Assert.True(string.CompareOrdinal(expectedValues[2], utcTimeInCookie) <= 0);
            Assert.True(string.CompareOrdinal(DateTime.UtcNow.ToString("o"), utcTimeInCookie) >= 0);

            Assert.Contains(cookieValues, v => v == $"RequestIP={expectedValues[3]}");
            Assert.Contains(cookieValues, v => v == $"RequestHttpHeader_Via={expectedValues[4]}");
            Assert.Contains(cookieValues, v => v == $"RequestHttpHeader_Forwarded={expectedValues[5]}");
            Assert.Contains(cookieValues, v => v == $"RequestHttpHeader_XForwardedFor={expectedValues[6]}");
            Assert.Contains(cookieValues, v => v == $"RequestHttpHeader_XForwardedHost={expectedValues[7]}");
            Assert.Contains(cookieValues, v => v == $"RequestHttpHeader_XForwardedProto={expectedValues[8]}");
        }

        private KnownUser GetKnowUser(UserInQueueServiceMock userInQueueServiceMock)
        {
            var knowUser = new KnownUser();
            knowUser.SetUserInQueueService(userInQueueServiceMock);
            return knowUser;
        }

        [Fact]
        public void CancelRequestByLocalConfig_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("url")
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var cancelEventConfig = new CancelEventConfig
            {
                CookieDomain = "cookiedomain",
                EventId = "eventid",
                QueueDomain = "queuedomain",
                Version = 1,
                ActionName = "CancelAction"
            };
            // Act
            var result = knowUser.CancelRequestByLocalConfig(httpContextMock, "url", "queueitToken", cancelEventConfig,
                "customerid", "secretekey");

            // Assert
            Assert.Equal("url", mock.cancelRequestCalls[0][0]);
            Assert.Equal("cookiedomain:eventid:queuedomain:1:CancelAction", mock.cancelRequestCalls[0][1]);
            Assert.Equal("customerid", mock.cancelRequestCalls[0][2]);
            Assert.Equal("secretekey", mock.cancelRequestCalls[0][3]);
            Assert.False(result.IsAjaxResult);
        }

        [Fact]
        public void CancelRequestByLocalConfig_AjaxCall_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("url"),
                    Headers = { { "x-queueit-ajaxpageurl", "http%3A%2F%2Furl" } }
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var cancelEventConfig = new CancelEventConfig
            {
                CookieDomain = "cookiedomain",
                EventId = "eventid",
                QueueDomain = "queuedomain",
                Version = 1,
                ActionName = "CancelAction"
            };
            // Act
            var result = knowUser.CancelRequestByLocalConfig(httpContextMock, "url", "queueitToken", cancelEventConfig,
                "customerid", "secretekey");

            // Assert
            Assert.Equal("http://url", mock.cancelRequestCalls[0][0]);
            Assert.Equal("cookiedomain:eventid:queuedomain:1:CancelAction", mock.cancelRequestCalls[0][1]);
            Assert.Equal("customerid", mock.cancelRequestCalls[0][2]);
            Assert.Equal("secretekey", mock.cancelRequestCalls[0][3]);
            Assert.True(result.IsAjaxResult);
        }


        [Fact]
        public void CancelRequestByLocalConfig_NullQueueDomain_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var exceptionWasThrown = false;

            var eventConfig = new CancelEventConfig
            {
                EventId = "eventid",
                CookieDomain = "cookieDomain",
                Version = 12
            };

            // Act
            try
            {
                knowUser.CancelRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", eventConfig,
                    "customerId",
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "QueueDomain from cancelEventConfig can not be null or empty.";
            }

            // Assert
            Assert.True(mock.cancelRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void CancelRequestByLocalConfig_EventIdNull_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var exceptionWasThrown = false;

            var eventConfig = new CancelEventConfig
            {
                CookieDomain = "domain",
                Version = 12
            };

            // Act
            try
            {
                knowUser.CancelRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", eventConfig,
                    "customerId",
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "EventId from cancelEventConfig can not be null or empty.";
            }

            // Assert
            Assert.True(mock.cancelRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void CancelRequestByLocalConfig_CancelEventConfigNull_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.CancelRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", null, "customerId",
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "cancelEventConfig can not be null.";
            }

            // Assert
            Assert.True(mock.cancelRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void CancelRequestByLocalConfig_CustomerIdNull_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.CancelRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken",
                    new CancelEventConfig(),
                    null,
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "customerId can not be null or empty.";
            }

            // Assert
            Assert.True(mock.cancelRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void CancelRequestByLocalConfig_SeceretKeyNull_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.CancelRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken",
                    new CancelEventConfig(),
                    "customerid",
                    null);
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "secretKey can not be null or empty.";
            }

            // Assert
            Assert.True(mock.cancelRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void CancelRequestByLocalConfig_TargetUrl_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.CancelRequestByLocalConfig(httpContextMock, null, "queueitToken", new CancelEventConfig(),
                    "customerid",
                    "secretkey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "targeturl can not be null or empty.";
            }

            // Assert
            Assert.True(mock.cancelRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ExtendQueueCookie_NullEventId_Test()
        {
            // Arrange
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ExtendQueueCookie(null, 0, null, false, false, null);
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "eventId can not be null or empty.";
            }

            // Assert
            Assert.True(mock.extendQueueCookieCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }


        [Fact]
        public void ExtendQueueCookie_InvalidCookieValidityMinutes_Test()
        {
            // Arrange        
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ExtendQueueCookie("eventId", 0, "cookiedomain", false, false, null);
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "cookieValidityMinute should be greater than 0.";
            }

            // Assert
            Assert.True(mock.extendQueueCookieCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ExtendQueueCookie_NullSecretKey_Test()
        {
            // Arrange
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ExtendQueueCookie("eventId", 20, "cookiedomain", false, false, null);
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "secretKey can not be null or empty.";
            }

            // Assert
            Assert.True(mock.extendQueueCookieCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ExtendQueueCookie_Test()
        {
            // Arrange
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            // Act
            knowUser.ExtendQueueCookie("eventId", 20, "cookiedomain", true, true, "secretKey");

            // Assert
            Assert.Equal("eventId", mock.extendQueueCookieCalls[0][0]);
            Assert.Equal("20", mock.extendQueueCookieCalls[0][1]);
            Assert.Equal("cookiedomain", mock.extendQueueCookieCalls[0][2]);
            Assert.True(bool.Parse(mock.extendQueueCookieCalls[0][3]));
            Assert.True(bool.Parse(mock.extendQueueCookieCalls[0][4]));
            Assert.Equal("secretKey", mock.extendQueueCookieCalls[0][5]);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_NullCustomerId_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", null, null,
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "customerId can not be null or empty.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_NullSecretKey_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", null,
                    "customerId",
                    null);
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "secretKey can not be null or empty.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_NullEventConfig_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", null,
                    "customerId",
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "eventConfig can not be null.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ResolveRequestByLocalEventConfigNullEventIdTest()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            var eventConfig = new QueueEventConfig
            {
                CookieDomain = "cookieDomain",
                LayoutName = "layoutName",
                Culture = "culture",
                //eventConfig.EventId = "eventId";
                QueueDomain = "queueDomain",
                ExtendCookieValidity = true,
                CookieValidityMinute = 10,
                Version = 12,
                ActionName = "QueueAction"
            };

            // Act
            try
            {
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", eventConfig,
                    "customerId",
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "EventId from eventConfig can not be null or empty.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ResolveRequestByLocalEventConfig_NullQueueDomain_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var exceptionWasThrown = false;

            var eventConfig = new QueueEventConfig
            {
                CookieDomain = "cookieDomain",
                LayoutName = "layoutName",
                Culture = "culture",
                EventId = "eventId",
                //eventConfig.QueueDomain = "queueDomain";
                ExtendCookieValidity = true,
                CookieValidityMinute = 10,
                Version = 12,
                ActionName = "QueueAction"
            };

            // Act
            try
            {
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", eventConfig,
                    "customerId",
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "QueueDomain from eventConfig can not be null or empty.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_InvalidCookieValidityMinute_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            var eventConfig = new QueueEventConfig
            {
                CookieDomain = "cookieDomain",
                LayoutName = "layoutName",
                Culture = "culture",
                EventId = "eventId",
                QueueDomain = "queueDomain",
                ExtendCookieValidity = true,
                //eventConfig.CookieValidityMinute = 10;
                Version = 12
            };

            // Act
            try
            {
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", eventConfig,
                    "customerId",
                    "secretKey");
            }
            catch (ArgumentException ex)
            {
                exceptionWasThrown = ex.Message == "CookieValidityMinute from eventConfig should be greater than 0.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ResolveRequestByLocalEventConfig_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            var eventConfig = new QueueEventConfig
            {
                CookieDomain = "cookieDomain",
                LayoutName = "layoutName",
                Culture = "culture",
                EventId = "eventId",
                QueueDomain = "queueDomain",
                ExtendCookieValidity = true,
                CookieValidityMinute = 10,
                Version = 12,
                ActionName = "QueueAction"
            };

            // Act
            var result =
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", eventConfig,
                    "customerId",
                    "secretKey");

            // Assert
            Assert.Equal("targetUrl", mock.validateQueueRequestCalls[0][0]);
            Assert.Equal("queueitToken", mock.validateQueueRequestCalls[0][1]);
            Assert.Equal("cookieDomain:layoutName:culture:eventId:queueDomain:true:10:12:QueueAction",
                mock.validateQueueRequestCalls[0][2]);
            Assert.Equal("customerId", mock.validateQueueRequestCalls[0][3]);
            Assert.Equal("secretKey", mock.validateQueueRequestCalls[0][4]);
            Assert.False(result.IsAjaxResult);
        }

        [Fact]
        public void ResolveRequestByLocalEventConfig_AjaxCall_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                    Headers = { { "x-queueit-ajaxpageurl", "http%3A%2F%2Furl" } }
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var eventConfig = new QueueEventConfig
            {
                CookieDomain = "cookieDomain",
                LayoutName = "layoutName",
                Culture = "culture",
                EventId = "eventId",
                QueueDomain = "queueDomain",
                ExtendCookieValidity = true,
                CookieValidityMinute = 10,
                Version = 12,
                ActionName = "QueueAction"
            };
            // Act
            var result =
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken", eventConfig,
                    "customerId",
                    "secretKey");

            // Assert
            Assert.Equal("http://url", mock.validateQueueRequestCalls[0][0]);
            Assert.Equal("queueitToken", mock.validateQueueRequestCalls[0][1]);
            Assert.Equal("cookieDomain:layoutName:culture:eventId:queueDomain:true:10:12:" + eventConfig.ActionName,
                mock.validateQueueRequestCalls[0][2]);
            Assert.Equal("customerId", mock.validateQueueRequestCalls[0][3]);
            Assert.Equal("secretKey", mock.validateQueueRequestCalls[0][4]);
            Assert.True(result.IsAjaxResult);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_EmptyCurrentUrl_Test()
        {
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "", null, null, null, null);
            }
            catch (Exception ex)
            {
                exceptionWasThrown = ex.Message == "currentUrlWithoutQueueITToken can not be null or empty.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_EmptyIntegrationsConfig_Test()
        {
            // Arrange 
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var exceptionWasThrown = false;

            // Act
            try
            {
                knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "currentUrl", "queueitToken", null, null,
                    null);
            }
            catch (Exception ex)
            {
                exceptionWasThrown = ex.Message == "customerIntegrationInfo can not be null.";
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.True(exceptionWasThrown);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_QueueAction()
        {
            // Arrange


            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            TriggerPart triggerPart1 = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerPart triggerPart2 = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "googlebot",
                ValidatorType = "UserAgentValidator",
                IsNegative = false,
                IsIgnoreCase = false
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart1, triggerPart2 }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                //config.ActionType = "Queue";
                EventId = "event1",
                CookieDomain = ".test.com",
                LayoutName = "Christmas Layout by Queue-it",
                Culture = "da-DK",
                ExtendCookieValidity = true,
                CookieValidityMinute = 20,
                Triggers = new[] { trigger },
                QueueDomain = "knownusertest.queue-it.net",
                RedirectLogic = "AllowTParameter",
                ForcedTargetUrl = "",
                ActionType = ActionType.QueueAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };

            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {

                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                    Headers = { { "User-Agent", "googlebot" } }
                }
            };

            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                "queueitToken",
                customerIntegration, "customerId", "secretKey");

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 1);
            Assert.Equal("http://test.com?event1=true", mock.validateQueueRequestCalls[0][0]);
            Assert.Equal("queueitToken", mock.validateQueueRequestCalls[0][1]);
            Assert.Equal(
                ".test.com:Christmas Layout by Queue-it:da-DK:event1:knownusertest.queue-it.net:true:20:3:event1action",
                mock.validateQueueRequestCalls[0][2]);
            Assert.Equal("customerId", mock.validateQueueRequestCalls[0][3]);
            Assert.Equal("secretKey", mock.validateQueueRequestCalls[0][4]);
            Assert.False(result.IsAjaxResult);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_AjaxCall_QueueAction()
        {
            // Arrange
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            TriggerPart triggerPart1 = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerPart triggerPart2 = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "googlebot",
                ValidatorType = "UserAgentValidator",
                IsNegative = false,
                IsIgnoreCase = false
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart1, triggerPart2 }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                //config.ActionType = "Queue";
                EventId = "event1",
                CookieDomain = ".test.com",
                LayoutName = "Christmas Layout by Queue-it",
                Culture = "da-DK",
                ExtendCookieValidity = true,
                CookieValidityMinute = 20,
                Triggers = new[] { trigger },
                QueueDomain = "knownusertest.queue-it.net",
                RedirectLogic = "AllowTParameter",
                ForcedTargetUrl = "",
                ActionType = ActionType.QueueAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };

            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {

                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                    Headers = { { "User-Agent", "googlebot" }, { "x-queueit-ajaxpageurl", "http%3A%2F%2Furl" } }
                }
            };


            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                "queueitToken",
                customerIntegration, "customerId", "secretKey");

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 1);
            Assert.Equal("http://url", mock.validateQueueRequestCalls[0][0]);
            Assert.Equal("queueitToken", mock.validateQueueRequestCalls[0][1]);
            Assert.Equal(
                ".test.com:Christmas Layout by Queue-it:da-DK:event1:knownusertest.queue-it.net:true:20:3:event1action",
                mock.validateQueueRequestCalls[0][2]);
            Assert.Equal("customerId", mock.validateQueueRequestCalls[0][3]);
            Assert.Equal("secretKey", mock.validateQueueRequestCalls[0][4]);
            Assert.True(result.IsAjaxResult);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_NotMatch_Test()
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {

                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = Array.Empty<IntegrationConfigModel>(),
                Version = 3
            };

            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                "queueitToken",
                customerIntegration, "customerId", "secretKey");

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 0);
            Assert.False(result.DoRedirect);
        }

        [Theory]
        [InlineData("ForcedTargetUrl", "http://forcedtargeturl.com")]
        [InlineData("ForecedTargetUrl", "http://forcedtargeturl.com")]
        [InlineData("EventTargetUrl", "")]
        public void ValidateRequestByIntegrationConfig_RedirectLogic_Test(string redirectLogic, string forcedTargetUrl)
        {
            // Arrange
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {

                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            TriggerPart triggerPart = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                //config.ActionType = "Queue";
                EventId = "event1",
                CookieDomain = ".test.com",
                LayoutName = "Christmas Layout by Queue-it",
                Culture = "da-DK",
                ExtendCookieValidity = true,
                CookieValidityMinute = 20,
                Triggers = new[] { trigger },
                QueueDomain = "knownusertest.queue-it.net",
                RedirectLogic = redirectLogic,
                ForcedTargetUrl = forcedTargetUrl,
                ActionType = ActionType.QueueAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };

            // Act
            knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true", "queueitToken",
                customerIntegration,
                "customerId", "secretKey");

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count == 1);
            Assert.Equal(forcedTargetUrl, mock.validateQueueRequestCalls[0][0]);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_IgnoreAction()
        {
            // Arrange
            TriggerPart triggerPart = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                EventId = "eventid",
                CookieDomain = "cookiedomain",
                Triggers = new[] { trigger },
                QueueDomain = "queuedomain",
                ActionType = ActionType.IgnoreAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };

            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {

                    Scheme = "http",
                    Host = new HostString("test.com")
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                "queueitToken",
                customerIntegration, "customerid", "secretkey");

            // Assert
            Assert.True(mock.ignoreRequestCalls.Count() == 1);
            Assert.False(result.IsAjaxResult);
            Assert.True(mock.ignoreRequestCalls[0][0] == config.Name);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_AjaxCall_IgnoreAction()
        {
            // Arrange
            TriggerPart triggerPart = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                EventId = "eventid",
                CookieDomain = "cookiedomain",
                Triggers = new[] { trigger },
                QueueDomain = "queuedomain",
                ActionType = ActionType.IgnoreAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };
            var httpContextMock = new DefaultHttpContext()
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                    Headers = { { "x-queueit-ajaxpageurl", "url" } }
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);



            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                "queueitToken",
                customerIntegration, "customerid", "secretkey");

            // Assert
            Assert.True(mock.ignoreRequestCalls.Count() == 1);
            Assert.True(result.IsAjaxResult);
            Assert.True(mock.ignoreRequestCalls[0][0] == config.Name);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_CancelAction()
        {
            // Arrange
            TriggerPart triggerPart = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                EventId = "eventid",
                CookieDomain = "cookiedomain",
                Triggers = new[] { trigger },
                QueueDomain = "queuedomain",
                ActionType = ActionType.CancelAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };

            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {

                    Scheme = "https",
                    Host = new HostString("targetUrl"),

                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                "queueitToken",
                customerIntegration, "customerid", "secretkey");

            // Assert
            Assert.Equal("http://test.com?event1=true", mock.cancelRequestCalls[0][0]);
            Assert.Equal("cookiedomain:eventid:queuedomain:3:event1action", mock.cancelRequestCalls[0][1]);
            Assert.Equal("customerid", mock.cancelRequestCalls[0][2]);
            Assert.Equal("secretkey", mock.cancelRequestCalls[0][3]);
            Assert.False(result.IsAjaxResult);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_AjaxCall_CancelAction()
        {
            // Arrange
            TriggerPart triggerPart = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                EventId = "eventid",
                CookieDomain = "cookiedomain",
                Triggers = new[] { trigger },
                QueueDomain = "queuedomain",
                ActionType = ActionType.CancelAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };

            var httpContextMock = new DefaultHttpContext()
            {
                Request =
                {
                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                    Headers = { { "x-queueit-ajaxpageurl", "http%3A%2F%2Furl" } }
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                "queueitToken",
                customerIntegration, "customerid", "secretkey");

            // Assert
            Assert.Equal("http://url", mock.cancelRequestCalls[0][0]);
            Assert.Equal("cookiedomain:eventid:queuedomain:3:event1action", mock.cancelRequestCalls[0][1]);
            Assert.Equal("customerid", mock.cancelRequestCalls[0][2]);
            Assert.Equal("secretkey", mock.cancelRequestCalls[0][3]);
            Assert.True(result.IsAjaxResult);
        }


        [Fact]
        public void ValidateRequestByIntegrationConfig_Debug()
        {
            // Arrange 
            var requestIP = "12234";
            var viaHeader = "1.1 example.com";
            var forwardedHeader = "for=192.0.2.60;proto=http;by=203.0.113.43";
            var xForwardedForHeader = "129.78.138.66, 129.78.64.103";
            var xForwardedHostHeader = "en.wikipedia.org:8080";
            var xForwardedProtoHeader = "https";
            var mockResponse = new MockHttpResponse();


            var httpContextMock = new DefaultHttpContext()
            {
                Connection =
                {
                    RemoteIpAddress = new IPAddress(12234)
                },
                Request =
                {
                    Headers =
                    {
                        { "Via", viaHeader },
                        { "Forwarded", forwardedHeader },
                        { "X-Forwarded-For", xForwardedForHeader },
                        { "X-Forwarded-Host", xForwardedHostHeader },
                        { "X-Forwarded-Proto", xForwardedProtoHeader }
                    },

                    Scheme = "http",
                    Host = new HostString("test.com"),
                    QueryString = new QueryString("?event1=true&queueittoken=queueittokenvalue"),
                    // Url = new Uri("http://test.com/?event1=true&queueittoken=queueittokenvalue")
                },
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            TriggerPart triggerPart1 = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new[] { triggerPart1 }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                //config.ActionType = "Queue";
                EventId = "event1",
                CookieDomain = ".test.com",
                IsCookieHttpOnly = false,
                IsCookieSecure = false,
                LayoutName = "Christmas Layout by Queue-it",
                Culture = "da-DK",
                ExtendCookieValidity = true,
                CookieValidityMinute = 20,
                Triggers = new[] { trigger },
                QueueDomain = "knownusertest.queue-it.net",
                RedirectLogic = "AllowTParameter",
                ForcedTargetUrl = ""
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new[] { config },
                Version = 3
            };

            var queueitToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow.AddDays(1), "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var hash,
                "debug");

            var utcTimeBeforeActionWasPerformed = DateTime.UtcNow.ToString("o");

            // Act
            var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                queueitToken,
                customerIntegration, "customerId", "secretKey");

            // Assert

            var cookieValues = GetCookieData(httpContextMock.Response)["queueitdebug"].Split('|');


            Assert.Contains(cookieValues, v => v == "PureUrl=http://test.com?event1=true");
            Assert.Contains(cookieValues, v => v == "ConfigVersion=3");
            Assert.Contains(cookieValues, v => v == "MatchedConfig=event1action");
            Assert.Contains(cookieValues, v => v == $"QueueitToken={queueitToken}");
            Assert.Contains(cookieValues,
                v => v == "OriginalUrl=http://test.com/?event1=true&queueittoken=queueittokenvalue");
            Assert.Contains(cookieValues, v => v == "TargetUrl=http://test.com?event1=true");
            Assert.Contains(cookieValues, v => v == "QueueConfig=" +
                "EventId:event1" +
                "&Version:3" +
                "&QueueDomain:knownusertest.queue-it.net" +
                "&CookieDomain:.test.com" +
                "&IsCookieHttpOnly:False" +
                "&IsCookieSecure:False" +
                "&ExtendCookieValidity:True" +
                "&CookieValidityMinute:20" +
                "&LayoutName:Christmas Layout by Queue-it" +
                "&Culture:da-DK&ActionName:event1action");
            /*
    
                  knowUser.UserInQueueService.
                    AssertRequestCookieContent(cookieValues,
                        knowUser.UserInQueueService., knowUser.GetRuntime(), utcTimeBeforeActionWasPerformed, requestIP,
                        viaHeader, forwardedHeader, xForwardedForHeader, xForwardedHostHeader, xForwardedProtoHeader);
                        */
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_Debug_WithoutMatch()
        {
            // Arrange 
            var requestIP = "80.35.35.34";
            var viaHeader = "1.1 example.com";
            var forwardedHeader = "for=192.0.2.60;proto=http;by=203.0.113.43";
            var xForwardedForHeader = "129.78.138.66, 129.78.64.103";
            var xForwardedHostHeader = "en.wikipedia.org:8080";
            var xForwardedProtoHeader = "https";

            var httpContextMock = new DefaultHttpContext()
            {
                Connection =
                {
                    RemoteIpAddress = new IPAddress(12234)
                },
                Request =
                {
                    Headers =
                    {
                        { "Via", viaHeader },
                        { "Forwarded", forwardedHeader },
                        { "X-Forwarded-For", xForwardedForHeader },
                        { "X-Forwarded-Host", xForwardedHostHeader },
                        { "X-Forwarded-Proto", xForwardedProtoHeader }
                    },

                    Scheme = "http",
                    Host = new HostString("test.com"),
                    QueryString = new QueryString("?event1=true&queueittoken=queueittokenvalue"),
                    // Url = new Uri("http://test.com/?event1=true&queueittoken=queueittokenvalue")
                },
                // HttpResponse = fakeHttpResponse
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new IntegrationConfigModel[] { },
                Version = 10
            };

            var queueitToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow.AddDays(1), "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var hash,
                "debug");

            var utcTimeBeforeActionWasPerformed = DateTime.UtcNow.ToString("o");

            // Act
            var result = knowUser
                .ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                    queueitToken, customerIntegration, "customerId", "secretKey");

            // Assert
            var cookieValues = GetCookieData(httpContextMock.Response)["queueitdebug"].Split('|');
            Assert.Contains(cookieValues, v => v == "PureUrl=http://test.com?event1=true");
            Assert.Contains(cookieValues, v => v == $"QueueitToken={queueitToken}");
            Assert.Contains(cookieValues, v => v == "ConfigVersion=10");
            Assert.Contains(cookieValues,
                v => v == "OriginalUrl=http://test.com/?event1=true&queueittoken=queueittokenvalue");
            Assert.Contains(cookieValues, v => v == "MatchedConfig=NULL");

            /*  AssertRequestCookieContent(cookieValues,
                  UserInQueueService.SDK_VERSION, KnownUser.GetRuntime(), utcTimeBeforeActionWasPerformed, requestIP,
                  viaHeader, forwardedHeader, xForwardedForHeader, xForwardedHostHeader, xForwardedProtoHeader);*/
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_Debug_NullConfig()
        {
            var requestIP = "80.35.35.34";
            var viaHeader = "1.1 example.com";
            var forwardedHeader = "for=192.0.2.60;proto=http;by=203.0.113.43";
            var xForwardedForHeader = "129.78.138.66, 129.78.64.103";
            var xForwardedHostHeader = "en.wikipedia.org:8080";
            var xForwardedProtoHeader = "https";
            var mockResponse = new MockHttpResponse();
            var context = new DefaultHttpContext
            {
                Connection =
                {
                    RemoteIpAddress = new IPAddress(12234)
                },
                Request =
                {
                    Headers =
                    {
                        { "Via", viaHeader },
                        { "Forwarded", forwardedHeader },
                        { "X-Forwarded-For", xForwardedForHeader },
                        { "X-Forwarded-Host", xForwardedHostHeader },
                        { "X-Forwarded-Proto", xForwardedProtoHeader }
                    },
                    Scheme = "http",
                    Host = new HostString("test.com"),
                    QueryString = new QueryString("?event1=true&queueittoken=queueittokenvalue"),
                }
                //HttpResponse = mockResponse
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            var queueitToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow.AddDays(1), "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _,
                "debug");

            var utcTimeBeforeActionWasPerformed = DateTime.UtcNow.ToString("o");

            Assert.Throws<ArgumentException>(() =>
                knowUser.ValidateRequestByIntegrationConfig(context,
                    "http://test.com?event1=true", queueitToken, null, "customerId", "secretKey")
            );

            var cookieValues = HttpUtility.UrlDecode(context.Response.Headers["Set-Cookie"]).Split('|');
            // Assert

            //Assert.Contains(cookieValues, v => v == $"SdkVersion={UserInQueueService.SDK_VERSION}");
            Assert.Contains(cookieValues, v => v == "PureUrl=http://test.com?event1=true");
            Assert.Contains(cookieValues, v => v == "ConfigVersion=NULL");
            Assert.Contains(cookieValues, v => v == $"QueueitToken={queueitToken}");
            Assert.Contains(cookieValues,
                v => v == "OriginalUrl=http://test.com/?event1=true&queueittoken=queueittokenvalue");
            Assert.Contains(cookieValues, v => v.StartsWith("Exception=customerIntegrationInfo can not be null."));

            /*   AssertRequestCookieContent(cookieValues,
                   UserInQueueService.SDK_VERSION, KnownUser.GetRuntime(), utcTimeBeforeActionWasPerformed, requestIP,
                   viaHeader, forwardedHeader, xForwardedForHeader, xForwardedHostHeader, xForwardedProtoHeader);*/
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_Debug_Missing_CustomerId()
        {
            var mockResponse = new MockHttpResponse();
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            CustomerIntegration customerIntegration = new CustomerIntegration();
            var context = new DefaultHttpContext
            {

                Request =
                {

                    Scheme = "http",
                    Host = new HostString("test.com")
                }
            };
            var expiredDebugToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.ValidateRequestByIntegrationConfig(context, "http://test.com?event1=true",
                expiredDebugToken,
                customerIntegration, null, "secretKey");

            Assert.Equal("https://api2.queue-it.net/diagnostics/connector/error/?code=setup", result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_Debug_Missing_Secretkey()
        {
            var context = new DefaultHttpContext
            {

                Request =
                {

                    Scheme = "http",
                    Host = new HostString("test.com")
                }
            };
            var mockResponse = new MockHttpResponse();
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            CustomerIntegration customerIntegration = new CustomerIntegration();

            var expiredDebugToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.ValidateRequestByIntegrationConfig(context, "http://test.com?event1=true",
                expiredDebugToken,
                customerIntegration, "customerid", null);

            Assert.Equal("https://api2.queue-it.net/diagnostics/connector/error/?code=setup", result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_Debug_ExpiredToken()
        {

            var context = new DefaultHttpContext
            {

                Request =
                {

                    Scheme = "http",
                    Host = new HostString("test.com")
                }
            };
            var mockResponse = new MockHttpResponse();
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            CustomerIntegration customerIntegration = new CustomerIntegration();

            var expiredDebugToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.ValidateRequestByIntegrationConfig(context, "http://test.com?event1=true",
                expiredDebugToken,
                customerIntegration, "customerId", "secretKey");

            Assert.Equal("https://customerId.api2.queue-it.net/customerId/diagnostics/connector/error/?code=timestamp",
                result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig_Debug_ModifiedToken()
        {
            var context = new DefaultHttpContext
            {

                Request =
                {

                    Scheme = "http",
                    Host = new HostString("test.com")
                }
            };
            var mockResponse = new MockHttpResponse();
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            CustomerIntegration customerIntegration = new CustomerIntegration();

            var invalidDebugToken = QueueITTokenGenerator.GenerateToken(
                                        DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey",
                                        out var _, "debug")
                                    + "invalid-hash";

            var result = knowUser.ValidateRequestByIntegrationConfig(context, "http://test.com?event1=true",
                invalidDebugToken,
                customerIntegration, "customerId", "secretKey");

            Assert.Equal("https://customerId.api2.queue-it.net/customerId/diagnostics/connector/error/?code=hash",
                result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_Debug()
        {
            // Arrange 
            var fakeHttpResponse = new MockHttpResponse();
            string requestIP = "80.35.35.34";
            string viaHeader = "1.1 example.com";
            string forwardedHeader = "for=192.0.2.60;proto=http;by=203.0.113.43";
            string xForwardedForHeader = "129.78.138.66, 129.78.64.103";
            string xForwardedHostHeader = "en.wikipedia.org:8080";
            string xForwardedProtoHeader = "https";

            var httpContextMock = new DefaultHttpContext
            {

                Connection =
                {
                    RemoteIpAddress = new IPAddress(12234)
                },
                Request =
                {
                    Headers =
                    {
                        { "Via", viaHeader },
                        { "Forwarded", forwardedHeader },
                        { "X-Forwarded-For", xForwardedForHeader },
                        { "X-Forwarded-Host", xForwardedHostHeader },
                        { "X-Forwarded-Proto", xForwardedProtoHeader }
                    },
                    Scheme = "http",
                    Host = new HostString("test.com"),
                    QueryString = new QueryString("?event1=true&queueittoken=queueittokenvalue")
                }
            };

            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            QueueEventConfig eventConfig = new QueueEventConfig
            {
                EventId = "eventId",
                LayoutName = "layoutName",
                Culture = "culture",
                QueueDomain = "queueDomain",
                ExtendCookieValidity = true,
                CookieValidityMinute = 10,
                CookieDomain = "cookieDomain",
                IsCookieHttpOnly = false,
                IsCookieSecure = false,
                Version = 12,
                ActionName = "QueueAction"
            };

            var queueitToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow.AddDays(1), "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var hash,
                "debug");

            var utcTimeBeforeActionWasPerformed = DateTime.UtcNow.ToString("o");

            // Act
            RequestValidationResult result = knowUser.ResolveQueueRequestByLocalConfig(httpContextMock,
                "http://test.com?event1=true", queueitToken, eventConfig, "customerId", "secretKey");

            // Assert
            var cookieValues = GetCookieData(httpContextMock.Response)["queueitdebug"].Split('|');
            Assert.Contains(cookieValues, v => v == $"QueueitToken={queueitToken}");
            Assert.Contains(cookieValues,
                v => v == "OriginalUrl=http://test.com/?event1=true&queueittoken=queueittokenvalue");
            Assert.Contains(cookieValues, v => v == "TargetUrl=http://test.com?event1=true");
            Assert.Contains(cookieValues, v => v == "QueueConfig=" +
                "EventId:eventId" +
                "&Version:12" +
                "&QueueDomain:queueDomain" +
                "&CookieDomain:cookieDomain" +
                "&IsCookieHttpOnly:False" +
                "&IsCookieSecure:False" +
                "&ExtendCookieValidity:True" +
                "&CookieValidityMinute:10" +
                "&LayoutName:layoutName" +
                "&Culture:culture" +
                $"&ActionName:{eventConfig.ActionName}");

            // AssertRequestCookieContent(cookieValues,
            //     UserInQueueService.SDK_VERSION, KnownUser.GetRuntime(), utcTimeBeforeActionWasPerformed, requestIP, viaHeader, forwardedHeader, xForwardedForHeader, xForwardedHostHeader, xForwardedProtoHeader);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_Debug_NullConfig()
        {
            // Arrange 
            var fakeHttpResponse = new MockHttpResponse();
            string requestIP = "80.35.35.34";
            string viaHeader = "1.1 example.com";
            string forwardedHeader = "for=192.0.2.60;proto=http;by=203.0.113.43";
            string xForwardedForHeader = "129.78.138.66, 129.78.64.103";
            string xForwardedHostHeader = "en.wikipedia.org:8080";
            string xForwardedProtoHeader = "https";
            var httpContextMock = new DefaultHttpContext
            {

                Connection =
                {
                    RemoteIpAddress = new IPAddress(12234)
                },
                Request =
                {

                    Headers =
                    {
                        { "Via", viaHeader },
                        { "Forwarded", forwardedHeader },
                        { "X-Forwarded-For", xForwardedForHeader },
                        { "X-Forwarded-Host", xForwardedHostHeader },
                        { "X-Forwarded-Proto", xForwardedProtoHeader }
                    },
                    Scheme = "http",
                    Host = new HostString("test.com"),
                    QueryString = new QueryString("?event1=true&queueittoken=queueittokenvalue")
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var queueitToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow.AddDays(1), "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var hash,
                "debug");

            var utcTimeBeforeActionWasPerformed = DateTime.UtcNow.ToString("o");

            Assert.Throws<ArgumentException>(() =>
                knowUser.ResolveQueueRequestByLocalConfig(httpContextMock,
                    "http://test.com?event1=true", queueitToken, null, "customerId", "secretKey")
            );

            // Assert
            var cookieValues = GetCookieData(httpContextMock.Response)["queueitdebug"].Split('|');
            Assert.Contains(cookieValues, v => v == $"QueueitToken={queueitToken}");
            Assert.Contains(cookieValues,
                v => v == $"OriginalUrl=http://test.com/?event1=true&queueittoken=queueittokenvalue");
            Assert.Contains(cookieValues, v => v == $"QueueConfig=NULL");
            Assert.Contains(cookieValues, v => v == $"Exception=eventConfig can not be null.");

            // AssertRequestCookieContent(cookieValues,
            //     UserInQueueService.SDK_VERSION, KnownUser.GetRuntime(), utcTimeBeforeActionWasPerformed, requestIP, viaHeader, forwardedHeader, xForwardedForHeader, xForwardedHostHeader, xForwardedProtoHeader);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_Debug_Missing_CustomerId()
        {
            var mockResponse = new MockHttpResponse();
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),
                }
            };
            QueueEventConfig eventConfig = new QueueEventConfig();

            var expiredDebugToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "http://test.com?event1=true",
                expiredDebugToken, eventConfig, null, "secretKey");

            Assert.Equal("https://api2.queue-it.net/diagnostics/connector/error/?code=setup", result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_Debug_Missing_SecretKey()
        {
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),
                }
            };
            var mockResponse = new MockHttpResponse();
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            QueueEventConfig eventConfig = new QueueEventConfig();

            var expiredDebugToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "http://test.com?event1=true",
                expiredDebugToken, eventConfig, "customerid", null);

            Assert.Equal("https://api2.queue-it.net/diagnostics/connector/error/?code=setup", result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_Debug_ExpiredToken()
        {
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            QueueEventConfig eventConfig = new QueueEventConfig();

            var expiredDebugToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "http://test.com?event1=true",
                expiredDebugToken, eventConfig, "customerId", "secretKey");

            Assert.Equal("https://customerId.api2.queue-it.net/customerId/diagnostics/connector/error/?code=timestamp",
                result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ResolveQueueRequestByLocalConfig_Debug_ModifiedToken()
        {
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);
            QueueEventConfig eventConfig = new QueueEventConfig();

            var invalidDebugToken = QueueITTokenGenerator.GenerateToken(
                                        DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey",
                                        out var _, "debug")
                                    + "invalid-hash";

            var result = knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "http://test.com?event1=true",
                invalidDebugToken, eventConfig, "customerId", "secretKey");

            Assert.Equal("https://customerId.api2.queue-it.net/customerId/diagnostics/connector/error/?code=hash",
                result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void CancelRequestByLocalConfig_Debug()
        {
            // Arrange 
            var fakeHttpResponse = new MockHttpResponse();
            string requestIP = "80.35.35.34";
            string viaHeader = "1.1 example.com";
            string forwardedHeader = "for=192.0.2.60;proto=http;by=203.0.113.43";
            string xForwardedForHeader = "129.78.138.66, 129.78.64.103";
            string xForwardedHostHeader = "en.wikipedia.org:8080";
            string xForwardedProtoHeader = "https";

            var httpContextMock = new DefaultHttpContext
            {

                Connection =
                {
                    RemoteIpAddress = new IPAddress(12234)
                },
                Request =
                {
                    Headers =
                    {
                        { "Via", viaHeader },
                        { "Forwarded", forwardedHeader },
                        { "X-Forwarded-For", xForwardedForHeader },
                        { "X-Forwarded-Host", xForwardedHostHeader },
                        { "X-Forwarded-Proto", xForwardedProtoHeader }
                    },
                    Scheme = "http",
                    Host = new HostString("test.com"),
                    QueryString = new QueryString("?event1=true&queueittoken=queueittokenvalue")
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            CancelEventConfig eventConfig = new CancelEventConfig
            {
                EventId = "eventId",
                QueueDomain = "queueDomain",
                Version = 12,
                CookieDomain = "cookieDomain",
                IsCookieHttpOnly = false,
                IsCookieSecure = false,
                ActionName = "CancelAction"
            };

            var queueitToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow.AddDays(1), "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var hash,
                "debug");

            var utcTimeBeforeActionWasPerformed = DateTime.UtcNow.ToString("o");

            // Act
            RequestValidationResult result = knowUser.CancelRequestByLocalConfig(httpContextMock,
                "http://test.com?event1=true", queueitToken, eventConfig, "customerId", "secretKey");

            // Assert
            var cookieValues = GetCookieData(httpContextMock.Response)["queueitdebug"].Split('|');
            Assert.Contains(cookieValues, v => v == $"QueueitToken={queueitToken}");
            Assert.Contains(cookieValues,
                v => v == "OriginalUrl=http://test.com/?event1=true&queueittoken=queueittokenvalue");
            Assert.Contains(cookieValues, v => v == "TargetUrl=http://test.com?event1=true");
            Assert.Contains(cookieValues, v => v == "CancelConfig=" +
                "EventId:eventId" +
                "&Version:12" +
                "&QueueDomain:queueDomain" +
                "&CookieDomain:cookieDomain" +
                "&IsCookieHttpOnly:False" +
                "&IsCookieSecure:False" +
                $"&ActionName:{eventConfig.ActionName}");

            /*AssertRequestCookieContent(cookieValues,
                UserInQueueService.SDK_VERSION, KnownUser.GetRuntime(), utcTimeBeforeActionWasPerformed, requestIP, viaHeader, forwardedHeader, xForwardedForHeader, xForwardedHostHeader, xForwardedProtoHeader);*/
        }

        [Fact]
        public void CancelRequestByLocalConfig_Debug_NullConfig()
        {
            // Arrange 
            var fakeHttpResponse = new MockHttpResponse();
            string requestIP = "80.35.35.34";
            string viaHeader = "1.1 example.com";
            string forwardedHeader = "for=192.0.2.60;proto=http;by=203.0.113.43";
            string xForwardedForHeader = "129.78.138.66, 129.78.64.103";
            string xForwardedHostHeader = "en.wikipedia.org:8080";
            string xForwardedProtoHeader = "https";

            var httpContextMock = new DefaultHttpContext
            {
                Connection =
                {
                    RemoteIpAddress = new IPAddress(12234)
                },
                Request =
                {
                    Headers =
                    {
                        { "Via", viaHeader },
                        { "Forwarded", forwardedHeader },
                        { "X-Forwarded-For", xForwardedForHeader },
                        { "X-Forwarded-Host", xForwardedHostHeader },
                        { "X-Forwarded-Proto", xForwardedProtoHeader }
                    },
                    Scheme = "http",
                    Host = new HostString("test.com"),
                    QueryString = new QueryString("?event1=true&queueittoken=queueittokenvalue")
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            var queueitToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow.AddDays(1), "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _,
                "debug");

            var utcTimeBeforeActionWasPerformed = DateTime.UtcNow.ToString("o");

            Assert.Throws<ArgumentException>(() =>
                knowUser.CancelRequestByLocalConfig(httpContextMock, "http://test.com?event1=true", queueitToken, null,
                    "customerId", "secretKey")
            );

            // Assert
            var cookieValues = GetCookieData(httpContextMock.Response)["queueitdebug"].Split('|');
            Assert.Contains(cookieValues, v => v == $"QueueitToken={queueitToken}");
            Assert.Contains(cookieValues,
                v => v == $"OriginalUrl=http://test.com/?event1=true&queueittoken=queueittokenvalue");
            Assert.Contains(cookieValues, v => v == $"CancelConfig=NULL");
            Assert.Contains(cookieValues, v => v == $"Exception=cancelEventConfig can not be null.");

            // AssertRequestCookieContent(cookieValues,
            //     UserInQueueService.SDK_VERSION, KnownUser.GetRuntime(), utcTimeBeforeActionWasPerformed, requestIP, viaHeader, forwardedHeader, xForwardedForHeader, xForwardedHostHeader, xForwardedProtoHeader);
        }

        [Fact]
        public void CancelRequestByLocalConfig_Debug_Missing_CustomerId()
        {
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),

                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            CancelEventConfig eventConfig = new CancelEventConfig();

            var token = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.CancelRequestByLocalConfig(httpContextMock, "http://test.com?event1=true", token,
                eventConfig, null, "secretkey");

            Assert.Equal("https://api2.queue-it.net/diagnostics/connector/error/?code=setup", result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void CancelRequestByLocalConfig_Debug_Missing_SecretKey()
        {
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            CancelEventConfig eventConfig = new CancelEventConfig();

            var token = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.CancelRequestByLocalConfig(httpContextMock, "http://test.com?event1=true", token,
                eventConfig, "customerid", null);

            Assert.Equal("https://api2.queue-it.net/diagnostics/connector/error/?code=setup", result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void CancelRequestByLocalConfig_Debug_ExpiredToken()
        {
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            CancelEventConfig eventConfig = new CancelEventConfig();

            var expiredDebugToken = QueueITTokenGenerator.GenerateToken(
                DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey", out var _, "debug");

            var result = knowUser.CancelRequestByLocalConfig(httpContextMock, "http://test.com?event1=true",
                expiredDebugToken, eventConfig, "customerId", "secretKey");

            Assert.Equal("https://customerId.api2.queue-it.net/customerId/diagnostics/connector/error/?code=timestamp",
                result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void CancelRequestByLocalConfig_Debug_ModifiedToken()
        {
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com")
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            CancelEventConfig eventConfig = new CancelEventConfig();

            var invalidDebugToken = QueueITTokenGenerator.GenerateToken(
                                        DateTime.UtcNow, "event1", Guid.NewGuid().ToString(), true, null, "secretKey",
                                        out var _, "debug")
                                    + "invalid-hash";

            var result = knowUser.CancelRequestByLocalConfig(httpContextMock, "http://test.com?event1=true",
                invalidDebugToken, eventConfig, "customerId", "secretKey");

            Assert.Equal("https://customerId.api2.queue-it.net/customerId/diagnostics/connector/error/?code=hash",
                result.RedirectUrl);
            Assert.Empty(mockResponse.CookiesValue);
        }

        [Fact]
        public void ValidateRequestByIntegrationConfig__Exception_NoDebugToken_NoDebugCookie_test()
        {
            // Arrange


            TriggerPart triggerPart1 = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "event1",
                UrlPart = "PageUrl",
                ValidatorType = "UrlValidator",
                IsNegative = false,
                IsIgnoreCase = true
            };

            TriggerPart triggerPart2 = new TriggerPart
            {
                Operator = "Contains",
                ValueToCompare = "googlebot",
                ValidatorType = "UserAgentValidator",
                IsNegative = false,
                IsIgnoreCase = false
            };

            TriggerModel trigger = new TriggerModel
            {
                LogicalOperator = "And",
                TriggerParts = new TriggerPart[] { triggerPart1, triggerPart2 }
            };

            IntegrationConfigModel config = new IntegrationConfigModel
            {
                Name = "event1action",
                //config.ActionType = "Queue";
                EventId = "event1",
                CookieDomain = ".test.com",
                LayoutName = "Christmas Layout by Queue-it",
                Culture = "da-DK",
                ExtendCookieValidity = true,
                CookieValidityMinute = 20,
                Triggers = new TriggerModel[] { trigger },
                QueueDomain = "knownusertest.queue-it.net",
                RedirectLogic = "AllowTParameter",
                ForcedTargetUrl = "",
                ActionType = ActionType.QueueAction
            };

            CustomerIntegration customerIntegration = new CustomerIntegration
            {
                Integrations = new IntegrationConfigModel[] { config },
                Version = 3
            };
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {
                Request =
                {

                    Scheme = "https",
                    Host = new HostString("targetUrl"),
                    Headers = { { "User-Agent", "googlebot" } }
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);

            mock.validateQueueRequestRaiseException = true;
            // Act
            try
            {
                var result = knowUser.ValidateRequestByIntegrationConfig(httpContextMock, "http://test.com?event1=true",
                    "queueitToken", customerIntegration, "customerId", "secretKey");
            }
            catch (Exception e)
            {
                Assert.True(e.Message == "Exception");
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count > 0);
            Assert.True(mockResponse.CookiesValue.Count == 0);
        }

        [Fact]
        public void ResolveRequestByLocalEventConfig__Exception_NoDebugToken_NoDebugCookie_Test()
        {
            // Arrange
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com"),

                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);



            QueueEventConfig eventConfig = new QueueEventConfig
            {
                CookieDomain = "cookieDomain",
                LayoutName = "layoutName",
                Culture = "culture",
                EventId = "eventId",
                QueueDomain = "queueDomain",
                ExtendCookieValidity = true,
                CookieValidityMinute = 10,
                Version = 12,
                ActionName = "QueueAction"
            };
            mock.validateQueueRequestRaiseException = true;
            // Act

            try
            {
                var result = knowUser.ResolveQueueRequestByLocalConfig(httpContextMock, "targetUrl", "queueitToken",
                    eventConfig, "customerId", "secretKey");
            }
            catch (Exception e)
            {
                Assert.True(e.Message == "Exception");
            }

            // Assert
            Assert.True(mock.validateQueueRequestCalls.Count > 0);
            Assert.True(mockResponse.CookiesValue.Count == 0);
        }

        [Fact]
        public void CancelRequestByLocalConfig_Exception_NoDebugToken_NoDebugCookie_Test()
        {
            // Arrange
            var mockResponse = new MockHttpResponse();
            var httpContextMock = new DefaultHttpContext
            {

                Request =
                {
                    Scheme = "http",
                    Host = new HostString("test.com")
                }
            };
            var mock = new UserInQueueServiceMock();
            var knowUser = GetKnowUser(mock);


            var cancelEventConfig = new CancelEventConfig
            {
                CookieDomain = "cookiedomain", EventId = "eventid", QueueDomain = "queuedomain", Version = 1,
                ActionName = "CancelAction"
            };
            // Act
            mock.validateCancelRequestRaiseException = true;
            try
            {
                var result = knowUser.CancelRequestByLocalConfig(httpContextMock, "url", "queueitToken",
                    cancelEventConfig, "customerid", "secretekey");
            }
            catch (Exception e)
            {
                Assert.True(e.Message == "Exception");
            }


            // Assert
            Assert.True(mock.cancelRequestCalls.Count > 0);
            Assert.True(mockResponse.CookiesValue.Count == 0);

        }
    }

    public class RequestValidationResultTest
    {
        [Fact]
        public void AjaxRedirectUrl_Test()
        {
            var testObject = new RequestValidationResult("Queue", isAjaxResult: true,
                redirectUrl: "http://url/path/?var=hello world");
            Assert.Equal("http%3A%2F%2Furl%2Fpath%2F%3Fvar%3Dhello%20world", testObject.AjaxRedirectUrl,
                ignoreCase: true);
        }
    }
}