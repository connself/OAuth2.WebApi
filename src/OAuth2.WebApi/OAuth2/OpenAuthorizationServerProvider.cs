using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace OAuth2.WebApi.OAuth2
{
    //authorization_code
    //1	ValidateClientRedirectUri
    //2	ValidateAuthorizeRequest
    //3	AuthorizeEndpoint
    //4	ValidateClientAuthentication

    //client_credentials
    //1	ValidateClientAuthentication
    //2	GrantClientCredentials

    //password
    //1	ValidateClientAuthentication
    //2	GrantResourceOwnerCredentials

    //implicit
    //1	ValidateClientRedirectUri
    //2	ValidateAuthorizeRequest
    //3	AuthorizeEndpoint

    public class OpenAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// 验证 client 信息
        /// </summary>
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //验证 client 信息
            string clientId;
            string clientSecret;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            string grant_type = context.Parameters.Get(Constants.Parameters.GrantType);
            if (grant_type == Constants.GrantTypes.ClientCredentials)
            {
                if (string.IsNullOrEmpty(clientId))
                {
                    context.SetError("invalid_client", "client is not valid");
                    return;
                }
                if (string.IsNullOrEmpty(clientSecret))
                {
                    context.SetError("invalid_client", "clientSecret is not valid");
                    return;
                }
                if (clientId != "jmai" || clientSecret != "9ICvhE0Yr3T3gg3trm4zWo8XLvakcCu4i9R2l1m_3xh")
                {
                    context.SetError("invalid_client", "client or clientSecret is not valid");
                    return;
                }
            }
            context.Validated();
        }

        /// <summary>
        /// 生成 access_token（client credentials 授权方式 - 客户端模式）
        /// 和用户无关，一般用于应用程序和 api 之间的交互场景，比如落网开放出 api，供第三方开发者进行调用数据等
        /// </summary>
        public override async Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            var OAuthIdentity = new ClaimsIdentity(new GenericIdentity(
                context.ClientId, OAuthDefaults.AuthenticationType),
                context.Scope.Select(x => new Claim("urn:oauth:scope", x))
                );

            OAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, context.ClientId));
            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { "aud", context.ClientId }
                });
            var ticket = new AuthenticationTicket(OAuthIdentity, props);
            context.Validated(ticket);
        }

        /// <summary>
        /// 生成 access_token（resource owner password credentials 授权方式 - 密码模式）
        /// 和用户账户相关，一般用于第三方登录
        /// </summary>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            if (string.IsNullOrEmpty(context.UserName))
            {
                context.SetError("invalid_username", "username is not valid");
                return;
            }
            if (string.IsNullOrEmpty(context.Password))
            {
                context.SetError("invalid_password", "password is not valid");
                return;
            }

            if (context.UserName != "jmai" || context.Password != "123")
            {
                context.SetError("invalid_identity", "username or password is not valid");
                return;
            }


            var OAuthIdentity = new ClaimsIdentity(context.Options.AuthenticationType);
            OAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { "aud", context.ClientId }
                });


            var ticket = new AuthenticationTicket(OAuthIdentity, props);
            context.Validated(ticket);
        }

        /// <summary>
        /// 生成 authorization_code（authorization code 授权方式）、生成 access_token （implicit 授权模式）
        /// 引入 authorization_code，可以增加系统的安全性，和客户端应用场景差不多，但一般用于 Server 端
        /// 简化模式（implicit）：无需 Server 端的介入，前端可以直接完成，一般用于前端操作
        /// </summary>
        public override async Task AuthorizeEndpoint(OAuthAuthorizeEndpointContext context)
        {
            if (context.AuthorizeRequest.IsImplicitGrantType)
            {
                //implicit 授权方式
                var identity = new ClaimsIdentity("Bearer");
                context.OwinContext.Authentication.SignIn(identity);
                context.RequestCompleted();
            }
            else if (context.AuthorizeRequest.IsAuthorizationCodeGrantType)
            {
                //authorization code 授权方式
                var redirectUri = context.Request.Query["redirect_uri"];
                var clientId = context.Request.Query["client_id"];
                var identity = new ClaimsIdentity(new GenericIdentity(
                    clientId, OAuthDefaults.AuthenticationType));

                var authorizeCodeContext = new AuthenticationTokenCreateContext(
                    context.OwinContext,
                    context.Options.AuthorizationCodeFormat,
                    new AuthenticationTicket(
                        identity,
                        new AuthenticationProperties(new Dictionary<string, string>
                        {
                            {"client_id", clientId},
                            {"redirect_uri", redirectUri}
                        })
                        {
                            IssuedUtc = DateTimeOffset.UtcNow,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(context.Options.AuthorizationCodeExpireTimeSpan)
                        }));

                await context.Options.AuthorizationCodeProvider.CreateAsync(authorizeCodeContext);
                context.Response.Redirect(redirectUri + "?code=" + Uri.EscapeDataString(authorizeCodeContext.Token));
                context.RequestCompleted();
            }
        }

        /// <summary>
        /// 验证 authorization_code 的请求
        /// </summary>
        public override Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            if (context.AuthorizeRequest.IsAuthorizationCodeGrantType || context.AuthorizeRequest.IsImplicitGrantType)
            {
                context.Validated();
            }
            else
            {
                context.Rejected();
            }

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// 验证 redirect_uri
        /// </summary>
        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            context.Validated(context.RedirectUri);
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// 验证 access_token 的请求
        /// </summary>
        public override Task ValidateTokenRequest(OAuthValidateTokenRequestContext context)
        {
            if (context.TokenRequest.IsAuthorizationCodeGrantType || context.TokenRequest.IsClientCredentialsGrantType || context.TokenRequest.IsRefreshTokenGrantType || context.TokenRequest.IsResourceOwnerPasswordCredentialsGrantType)
            {
                context.Validated();
            }
            else
            {
                context.Rejected();
            }

            return Task.FromResult<object>(null);
        }
    }
}