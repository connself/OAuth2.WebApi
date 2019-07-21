using Microsoft.Owin.Security.OAuth;
using System.Web.Http;

namespace OAuth2.WebApi
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API 配置和服务

            config.SuppressDefaultHostAuthentication();
            //Configure Web API to use only bearer token authentication.
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // allow a client to call you without specifying an api version
            // since we haven't configured it otherwise, the assumed api version will be 1.0
            config.AddApiVersioning(o =>
            {
                o.AssumeDefaultVersionWhenUnspecified = true;
                o.ReportApiVersions = true;
                o.DefaultApiVersion = new Microsoft.Web.Http.ApiVersion(1, 0);
            });

            // added to the web api configuration in the application setup
            var constraintResolver = new System.Web.Http.Routing.DefaultInlineConstraintResolver()
            {
                ConstraintMap =
                {
                    ["apiVersion"] = typeof( Microsoft.Web.Http.Routing.ApiVersionRouteConstraint )
                }
            };

            // Web API 路由
            config.MapHttpAttributeRoutes(constraintResolver);

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{action}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
