using Ocelot.Authorization;
using Ocelot.Configuration;
using Ocelot.DownstreamRouteFinder.UrlMatcher;
using Ocelot.Middleware;
using Ocelot.Responses;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Erfa.GatewayApi
{
    public class OcelotAuthorizationMiddleware
    {
        private readonly Func<Task> _next;
        private readonly ILogger<OcelotAuthorizationMiddleware> _logger;

        public OcelotAuthorizationMiddleware(Func<Task> next, ILogger<OcelotAuthorizationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }
        public async Task Invoke(HttpContext httpContext)
        {
            DownstreamRoute downstreamRoute = (DownstreamRoute)httpContext.Items["DownstreamRoute"];

            if (!IsOptionsHttpMethod(httpContext) && IsAuthenticatedRoute(downstreamRoute))
            {
                _logger.LogInformation
                ("route is authenticated scopes must be checked");
                Response<bool> response = Authorize(httpContext.User, downstreamRoute.AuthenticationOptions.AllowedScopes);
                if (response.IsError)
                {
                    _logger.LogWarning
                    ("error authorizing user scopes");
                    httpContext.Items.UpsertErrors(response.Errors);
                    return;
                }
                if (IsAuthorized(response))
                {
                    _logger.LogInformation
                    ("user scopes is authorized calling next authorization checks");
                }
                else
                {
                    _logger.LogWarning
                    ("user scopes is not authorized setting pipeline error");
                    httpContext.Items.SetError(new UnauthorizedError(httpContext.User.Identity!.Name + " unable to access " + downstreamRoute.UpstreamPathTemplate.OriginalValue));
                }
            }

            if (!IsOptionsHttpMethod(httpContext) && IsAuthorizedRoute(downstreamRoute))
            {
                _logger.LogInformation
                ("route is authorized");
                Response<bool> response2 = Authorize(httpContext.User, downstreamRoute.RouteClaimsRequirement, httpContext.Items.TemplatePlaceholderNameAndValues());
                if (response2.IsError)
                {
                    _logger.LogWarning
                    ("Error whilst authorizing " + httpContext.User.Identity!.Name + ". Setting pipeline error");
                    httpContext.Items.UpsertErrors(response2.Errors);
                }
                else if (IsAuthorized(response2))
                {
                    _logger.LogInformation
                    (httpContext.User.Identity!.Name + " has succesfully been authorized for " + downstreamRoute.UpstreamPathTemplate.OriginalValue + ".");
                    await _next();
                }
                else
                {
                    _logger.LogWarning
                    (httpContext.User.Identity!.Name + " is not authorized to access " + downstreamRoute.UpstreamPathTemplate.OriginalValue + ". Setting pipeline error");
                    httpContext.Items.SetError(new UnauthorizedError(httpContext.User.Identity!.Name + " is not authorized to access " + downstreamRoute.UpstreamPathTemplate.OriginalValue));
                }
            }
            else
            {
                _logger.LogInformation
                (downstreamRoute.DownstreamPathTemplate.Value + " route does not require user to be authorized");
                await _next();
            }
        }

        private bool IsAuthorized(Response<bool> authorized)
        {
            var x = authorized.Data;
            return x;
        }

        private bool IsAuthenticatedRoute(DownstreamRoute route)
        {
            var v = route.IsAuthenticated;
            return v;
        }

        private bool IsAuthorizedRoute(DownstreamRoute route)
        {
            return route.IsAuthorized;
        }

        private bool IsOptionsHttpMethod(HttpContext httpContext)
        {
            return httpContext.Request.Method.ToUpper() == "OPTIONS";
        }


        private Response<List<string>> GetValuesByClaimType(IEnumerable<Claim> claims, string claimType)
        {
            var c = (from x in claims
                     where x.Type == claimType
                     select x.Value).ToList();
            return new OkResponse<List<string>>(c);
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
                    string[] allowedRoles = item.Value.Split(',');
                    var matching = false;
                    List<string> variableNames = new List<string>();

                    foreach (var value in valuesByClaimType.Data)
                    {
                        foreach (var allowedRole in allowedRoles)
                        {
                            if (allowedRole.ToUpper().Equals(value.ToUpper()))
                            {
                                matching = true;
                                variableNames.Add(value);
                            }
                        }
                    }

                    if (matching)
                    {
                        continue;
                    }
                }
                return new ErrorResponse<bool>(new UserDoesNotHaveClaimError("user does not have claim " + item.Key));
            }
            return new OkResponse<bool>(data: true);
        }

        private Response<bool> Authorize(ClaimsPrincipal claimsPrincipal, List<string> routeAllowedScopes)
        {
            if (routeAllowedScopes == null || routeAllowedScopes.Count == 0)
            {
                return new OkResponse<bool>(data: true);
            }
            Response<List<string>> valuesByClaimType = GetValuesByClaimType(claimsPrincipal.Claims, "scope");
            if (valuesByClaimType.IsError)
            {
                return new ErrorResponse<bool>(valuesByClaimType.Errors);
            }
            List<string> data = valuesByClaimType.Data;
            if (!routeAllowedScopes.Intersect(data).Any())
            {
                DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(55, 2);
                defaultInterpolatedStringHandler.AppendLiteral("no one user scope: '");
                defaultInterpolatedStringHandler.AppendFormatted(string.Join(',', data));
                defaultInterpolatedStringHandler.AppendLiteral("' match with some allowed scope: '");
                defaultInterpolatedStringHandler.AppendFormatted(string.Join(',', routeAllowedScopes));
                defaultInterpolatedStringHandler.AppendLiteral("'");
                return new ErrorResponse<bool>(new ScopeNotAuthorizedError(defaultInterpolatedStringHandler.ToStringAndClear()));
            }
            return new OkResponse<bool>(data: true);
        }
    }
}
