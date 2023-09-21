using Ocelot.Authorization;
using Ocelot.Configuration;
using Ocelot.DownstreamRouteFinder.UrlMatcher;
using Ocelot.Logging;
using Ocelot.Middleware;
using Ocelot.Responses;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.RegularExpressions;


namespace Erfa.GatewayApi
{
    public class OcelotJwtMiddleware : OcelotMiddleware
    {
        private readonly RequestDelegate _next;


        private readonly IScopesAuthorizer _scopesAuthorizer;

        public OcelotJwtMiddleware(RequestDelegate next, IScopesAuthorizer scopesAuthorizer, IOcelotLoggerFactory loggerFactory)
            : base(loggerFactory.CreateLogger<OcelotJwtMiddleware>())
        {
            _next = next;
            _scopesAuthorizer = scopesAuthorizer;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            DownstreamRoute downstreamRoute = httpContext.Items.DownstreamRoute();
            if (!IsOptionsHttpMethod(httpContext) && IsAuthenticatedRoute(downstreamRoute))
            {
                base.Logger.LogInformation("route is authenticated scopes must be checked");
                Response<bool> response = _scopesAuthorizer.Authorize(httpContext.User, downstreamRoute.AuthenticationOptions.AllowedScopes);
                if (response.IsError)
                {
                    base.Logger.LogWarning("error authorizing user scopes");
                    httpContext.Items.UpsertErrors(response.Errors);
                    return;
                }
                if (IsAuthorized(response))
                {
                    base.Logger.LogInformation("user scopes is authorized calling next authorization checks");
                }
                else
                {
                    base.Logger.LogWarning("user scopes is not authorized setting pipeline error");
                    httpContext.Items.SetError(new UnauthorizedError(httpContext.User.Identity!.Name + " unable to access " + downstreamRoute.UpstreamPathTemplate.OriginalValue));
                }
            }
            if (!IsOptionsHttpMethod(httpContext) && IsAuthorizedRoute(downstreamRoute))
            {
                base.Logger.LogInformation("route is authorized");
                Response<bool> response2 = Authorize(httpContext.User, downstreamRoute.RouteClaimsRequirement, httpContext.Items.TemplatePlaceholderNameAndValues());
                if (response2.IsError)
                {
                    base.Logger.LogWarning("Error whilst authorizing " + httpContext.User.Identity!.Name + ". Setting pipeline error");
                    httpContext.Items.UpsertErrors(response2.Errors);
                }
                else if (IsAuthorized(response2))
                {
                    base.Logger.LogInformation(httpContext.User.Identity!.Name + " has succesfully been authorized for " + downstreamRoute.UpstreamPathTemplate.OriginalValue + ".");
                    await _next(httpContext);
                }
                else
                {
                    base.Logger.LogWarning(httpContext.User.Identity!.Name + " is not authorized to access " + downstreamRoute.UpstreamPathTemplate.OriginalValue + ". Setting pipeline error");
                    httpContext.Items.SetError(new UnauthorizedError(httpContext.User.Identity!.Name + " is not authorized to access " + downstreamRoute.UpstreamPathTemplate.OriginalValue));
                }
            }
            else
            {
                base.Logger.LogInformation(downstreamRoute.DownstreamPathTemplate.Value + " route does not require user to be authorized");
                await _next(httpContext);
            }
        }

        private static bool IsAuthorized(Response<bool> authorized)
        {
            return authorized.Data;
        }

        private static bool IsAuthenticatedRoute(DownstreamRoute route)
        {
            return route.IsAuthenticated;
        }

        private static bool IsAuthorizedRoute(DownstreamRoute route)
        {
            return route.IsAuthorized;
        }

        private static bool IsOptionsHttpMethod(HttpContext httpContext)
        {
            return httpContext.Request.Method.ToUpper() == "OPTIONS";
        }


        private Response<List<string>> GetValuesByClaimType(IEnumerable<Claim> claims, string claimType)
        {
            return new OkResponse<List<string>>((from x in claims
                                                 where x.Type == claimType
                                                 select x.Value).ToList());
        }


        private Response<bool> Authorize(ClaimsPrincipal claimsPrincipal, Dictionary<string, string> routeClaimsRequirement, List<PlaceholderNameAndValue> urlPathPlaceholderNameAndValues)
        {
            foreach (KeyValuePair<string, string> item in routeClaimsRequirement)
            {
                Response<List<string>> valuesByClaimType = GetValuesByClaimType(claimsPrincipal.Claims, item.Key);
                if (valuesByClaimType.IsError)
                {
                    return new ErrorResponse<bool>(valuesByClaimType.Errors);
                }
                if (valuesByClaimType.Data != null)
                {
                    string[] valuses = item.Value.Split(',');
                    var matching = false;
                    List<string> variableNames = new List<string>();
                    foreach (var value in valuses)
                    {
                        Match match = Regex.Match(value, "^{(?<variable>.+)}$");
                        if (match.Success)
                        {
                            matching = true;
                            variableNames.Add(value);
                        }
                    }

                    if (matching)
                    {
                        string variableName = string.Join(",", variableNames);
                        PlaceholderNameAndValue[] array = urlPathPlaceholderNameAndValues.Where((PlaceholderNameAndValue p) => p.Name.Equals(variableName)).Take(2).ToArray();
                        if (array.Length != 1)
                        {
                            if (array.Length == 0)
                            {
                                return new ErrorResponse<bool>(new ClaimValueNotAuthorizedError("config error: requires variable claim value: " + variableName + " placeholders does not contain that variable: " + string.Join(", ", urlPathPlaceholderNameAndValues.Select((PlaceholderNameAndValue p) => p.Name))));
                            }
                            return new ErrorResponse<bool>(new ClaimValueNotAuthorizedError("config error: requires variable claim value: " + item.Value + " but placeholders are ambiguous: " + string.Join(", ", from p in urlPathPlaceholderNameAndValues
                                                                                                                                                                                                                   where p.Name.Equals(variableName)
                                                                                                                                                                                                                   select p.Value)));
                        }
                        string value = array[0].Value;
                        if (!valuesByClaimType.Data.Contains(value))
                        {
                            DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(64, 3);
                            defaultInterpolatedStringHandler.AppendLiteral("dynamic claim value for ");
                            defaultInterpolatedStringHandler.AppendFormatted(variableName);
                            defaultInterpolatedStringHandler.AppendLiteral(" of ");
                            defaultInterpolatedStringHandler.AppendFormatted(string.Join(", ", valuesByClaimType.Data));
                            defaultInterpolatedStringHandler.AppendLiteral(" is not the same as required value: ");
                            defaultInterpolatedStringHandler.AppendFormatted(value);
                            return new ErrorResponse<bool>(new ClaimValueNotAuthorizedError(defaultInterpolatedStringHandler.ToStringAndClear()));
                        }
                    }
                    else if (!valuesByClaimType.Data.Contains(item.Value))
                    {
                        DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(60, 3);
                        defaultInterpolatedStringHandler.AppendLiteral("claim value: ");
                        defaultInterpolatedStringHandler.AppendFormatted(string.Join(", ", valuesByClaimType.Data));
                        defaultInterpolatedStringHandler.AppendLiteral(" is not the same as required value: ");
                        defaultInterpolatedStringHandler.AppendFormatted(item.Value);
                        defaultInterpolatedStringHandler.AppendLiteral(" for type: ");
                        defaultInterpolatedStringHandler.AppendFormatted(item.Key);
                        return new ErrorResponse<bool>(new ClaimValueNotAuthorizedError(defaultInterpolatedStringHandler.ToStringAndClear()));
                    }
                    continue;
                }
                return new ErrorResponse<bool>(new UserDoesNotHaveClaimError("user does not have claim " + item.Key));
            }
            return new OkResponse<bool>(data: true);
        }



    }

}
