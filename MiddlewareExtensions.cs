namespace Erfa.GatewayApi
{
    public static class MiddlewareExtensions
    {
        public static IApplicationBuilder UseCustomOcelotAuthorizationHandler(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<OcelotJwtMiddleware>();
        }
    }
}
