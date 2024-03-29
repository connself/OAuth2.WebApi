﻿using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Web.Http;

[assembly: OwinStartup(typeof(OAuth2.WebApi.Startup))]
namespace OAuth2.WebApi
{
    /// <summary>
    /// Startup
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Configuration
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration configuration = new HttpConfiguration();
            WebApiConfig.Register(configuration);
            SwaggerConfig.Register(configuration);

            ConfigCors(app);

            ConfigAuth(app);

            //这一行代码必须放在ConfiureOAuth(app)之后
            app.UseWebApi(configuration);
        }

        /// <summary>
        /// ConfigCors
        /// </summary>
        /// <param name="app"></param>
        public void ConfigCors(IAppBuilder app)
        {
            app.UseCors(CorsOptions.AllowAll);
        }

        /// <summary>
        /// ConfigAuth
        /// </summary>
        /// <param name="app"></param>
        public void ConfigAuth(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions option = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true, //允许客户端使用http协议请求
                TokenEndpointPath = new PathString("/oauth2/token"), //获取 access_token 授权服务请求地址
                AuthorizeEndpointPath = new PathString("/oauth2/authorize"), //获取 authorization_code 认证服务请求地址
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(1), //access_token 过期时间
                Provider = new OAuth2.OpenAuthorizationServerProvider(), //access_token 相关授权服务
                AuthorizationCodeProvider = new OAuth2.OpenAuthorizationCodeProvider(), //authorization_code 认证服务
                RefreshTokenProvider = new OAuth2.OpenRefreshTokenProvider(), //refresh_token 授权服务
                AccessTokenFormat = new OAuth2.OpenJwtFormat() //定义token信息格式
            };
            app.UseOAuthAuthorizationServer(option);
            //表示 token_type 使用 bearer 方式
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions()
            {
                //从url中获取token，兼容hearder方式
                Provider = new OAuth2.QueryStringOAuthBearerProvider("access_token"),
                AccessTokenFormat = new OAuth2.OpenJwtFormat()  //定义token信息格式
            });

        }
    }
}