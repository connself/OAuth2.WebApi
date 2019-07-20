using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace OAuth2.WebApi.Controllers
{
    /// <summary>
    /// 测试API
    /// </summary>
    [Authorize]
    public class TestController : ApiController
    {

        /// <summary>
        /// 不验证授权
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpGet]
        public string GetAllowAnonymous()
        {
            return "测试AllowAnonymous GET数据";
        }

        /// <summary>
        /// 授权GET
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        public string GetSimple()
        {
            return "测试GET数据";
        }

        /// <summary>
        /// 授权POST
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public string PostSimple()
        {
            return "测试Post数据";
        }
    }
}
