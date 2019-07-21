using OAuth2.WebApi.Swagger;
using Swashbuckle.Application;
using Swashbuckle.Swagger;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web.Http;
using System.Web.Http.Description;
using System.Web.Http.Filters;

namespace OAuth2.WebApi
{
    public class SwaggerConfig
    {
        /// <summary>
        /// ����Swagger
        /// </summary>
        /// <param name="config"></param>
        public static void Register(HttpConfiguration config)
        {
            // add the versioned IApiExplorer and capture the strongly-typed implementation (e.g. VersionedApiExplorer vs IApiExplorer)
            // note: the specified format code will format the version as "'v'major[.minor][-status]"
            var versionedApiExplorer = config.AddVersionedApiExplorer(
                options =>
                {
                    options.GroupNameFormat = "'v'VVV";

                    // note: this option is only necessary when versioning by url segment. the SubstitutionFormat
                    // can also be used to control the format of the API version in route templates
                    options.SubstituteApiVersionInUrl = true;
                });

            var thisAssembly = typeof(WebApiConfig).Assembly;

            config.EnableSwagger(
                "docs/{apiVersion}/swagger",
                c =>
                {
                    //build a swagger document and endpoint for each discovered API version
                    c.MultipleApiVersions(
                        ResolveAreasSupportByRouteConstraint,
                        info =>
                        {
                            foreach (var group in versionedApiExplorer.ApiDescriptions)
                            {
                                var description = "";

                                if (group.IsDeprecated)
                                {
                                    description += " This API version has been deprecated.";
                                }

                                info.Version(group.Name, $"API v{group.ApiVersion}")
                                    .Description(description)
                                    .TermsOfService("GEOMCH");
                            }
                        });

                    //����token������ͷ��
                    c.ApiKey("Authorization").Description("token Ψһֵ").In("header").Name("token");

                    c.GroupActionsBy(apiDesc => apiDesc.ActionDescriptor.ControllerDescriptor.ControllerName);
                    //xml�����ĵ�
                    c.IncludeXmlComments(XmlCommentsFilePath);

                    c.CustomProvider((defaultProvider) => new SwaggerCacheProvider(defaultProvider, XmlCommentsFilePath));

                    // add a custom operation filter which sets default values
                    c.OperationFilter<SwaggerDefaultValues>();

                })
                .EnableSwaggerUi("docs/{*assetPath}", c =>
                {
                    c.DocumentTitle("WebApi Document");
                    //������Դ�ļ������ռ��ǣ��ļ�������Ŀ�������ռ�.�ļ���·.�ļ���
                    c.InjectStylesheet(thisAssembly, "OAuth2.WebApi.Swagger.theme-custom.css");
                    c.InjectJavaScript(thisAssembly, "OAuth2.WebApi.Swagger.swagger_cn.js");//����js
                    c.EnableApiKeySupport("Authorization", "header");
                    c.EnableDiscoveryUrlSelector();
                });
        }

        /// <summary>
        /// ResolveAreasSupportByRouteConstraint
        /// </summary>
        /// <param name="apiDescription"></param>
        /// <param name="targetApiVersion"></param>
        /// <returns></returns>
        static bool ResolveAreasSupportByRouteConstraint(ApiDescription apiDescription, string targetApiVersion)
        {
            return apiDescription.GetGroupName() == targetApiVersion;
        }

        /// <summary>
        /// XmlCommentsFilePath
        /// </summary>
        static string XmlCommentsFilePath
        {
            get
            {
                var fileName = typeof(WebApiConfig).GetTypeInfo().Assembly.GetName().Name + ".xml";
                return Path.Combine(ContentRootPath, fileName);
            }
        }

        /// <summary>
        /// ContentRootPath
        /// </summary>
        public static string ContentRootPath
        {
            get
            {
                var app = AppDomain.CurrentDomain;

                if (string.IsNullOrEmpty(app.RelativeSearchPath))
                {
                    return app.BaseDirectory;
                }

                return app.RelativeSearchPath;
            }
        }
    }

    /// <summary>
    /// swagger ���� AUTH ѡ��
    /// </summary>
    public class OAuth2HeaderFilter : IOperationFilter
    {
        /// <summary>
        /// Ӧ��
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="schemaRegistry"></param>
        /// <param name="apiDescription"></param>
        public void Apply(Operation operation, SchemaRegistry schemaRegistry, ApiDescription apiDescription)

        {
            if (operation.parameters == null)
                operation.parameters = new List<Parameter>();
            var filterPipeline = apiDescription.ActionDescriptor.GetFilterPipeline(); //�ж��Ƿ����Ȩ�޹�����
            var isAuthorized = filterPipeline.Select(filterInfo => filterInfo.Instance).Any(filter => filter is IAuthorizationFilter); //�ж��Ƿ������������� 
            var allowAnonymous = apiDescription.ActionDescriptor.GetCustomAttributes<AllowAnonymousAttribute>().Any();
            if (isAuthorized && !allowAnonymous)
            {
                operation.parameters.Add(new Parameter { name = "Authorization", @in = "header", description = "��ȫ", required = false, type = "string" });
            }
        }
    }
}
