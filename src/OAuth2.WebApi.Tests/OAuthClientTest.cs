using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Net;
using System.Web.Http;
using System.Threading;

namespace OAuth2.WebApi.Tests
{
    [TestClass]
    public class OAuthClientTest
    {
        private const string HOST_ADDRESS = "http://localhost:10009";
        private static HttpClient _httpClient;

        public OAuthClientTest()
        {
            _httpClient = new HttpClient();
            _httpClient.BaseAddress = new Uri(HOST_ADDRESS);
        }
        [TestMethod]
        public async Task OAuth_ClientCredentials_Test()
        {
            var tokenResponse = GetToken("client_credentials").Result; //获取 access_token
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);

            var response = await _httpClient.GetAsync($"/api/test/GetSimple");
            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(response.StatusCode);
                var exceptionMessage = (await response.Content.ReadAsAsync<HttpError>()).ExceptionMessage;
                Console.WriteLine(exceptionMessage);
            }
            Console.WriteLine(await response.Content.ReadAsStringAsync());
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);

            Thread.Sleep(10000);

            var tokenResponseTwo = GetToken("refresh_token", tokenResponse.RefreshToken).Result;
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponseTwo.AccessToken);
            var responseTwo = await _httpClient.GetAsync($"/api/test/GetSimple");
            Assert.AreEqual(HttpStatusCode.OK, responseTwo.StatusCode);
        }

        private static async Task<TokenResponse> GetToken(string grantType, string refreshToken = null, string userName = null, string password = null, string authorizationCode = null)
        {
            var clientId = "jmai";
            var clientSecret = "9ICvhE0Yr3T3gg3trm4zWo8XLvakcCu4i9R2l1m_3xh";
            var parameters = new Dictionary<string, string>();
            parameters.Add("grant_type", grantType);

            if (!string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(password))
            {
                parameters.Add("username", userName);
                parameters.Add("password", password);
            }
            if (!string.IsNullOrEmpty(authorizationCode))
            {
                parameters.Add("code", authorizationCode);
                parameters.Add("redirect_uri", "http://localhost:8001/api/authorization_code"); //和获取 authorization_code 的 redirect_uri 必须一致，不然会报错
            }
            if (!string.IsNullOrEmpty(refreshToken))
            {
                parameters.Add("refresh_token", refreshToken);
            }

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.ASCII.GetBytes(clientId + ":" + clientSecret)));

            var response = await _httpClient.PostAsync("oauth2/token", new FormUrlEncodedContent(parameters));
            var responseValue = await response.Content.ReadAsStringAsync();
            if (response.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine(response.StatusCode);
                Console.WriteLine((await response.Content.ReadAsAsync<HttpError>()).ExceptionMessage);
                return null;
            }
            return await response.Content.ReadAsAsync<TokenResponse>();
        }
    }
}
