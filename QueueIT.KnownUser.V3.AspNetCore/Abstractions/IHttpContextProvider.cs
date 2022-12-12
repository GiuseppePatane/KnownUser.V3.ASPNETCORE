namespace QueueIT.KnownUser.V3.AspNetCore.Abstractions
{
    public interface IHttpContextProvider
    {
        IHttpRequest HttpRequest
        {
            get;
        }
        IHttpResponse HttpResponse
        {
            get;
        }
    }
}