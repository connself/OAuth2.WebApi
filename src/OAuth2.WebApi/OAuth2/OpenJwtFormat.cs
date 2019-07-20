using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace OAuth2.WebApi.OAuth2
{
    public class OpenJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly string _issuer = "12";
        private readonly string _audience = "12";
        private readonly string Base64Secret = "IxrAjDoa2FqElO7IhrSrUJELhUckePEPVpaePlS_Xaw";

        public OpenJwtFormat()
        {
        }


        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            //string audienceId = data.Properties.Dictionary.ContainsKey(AudiencePropertyKey) ?
            //    data.Properties.Dictionary[AudiencePropertyKey] : null;
            //if (string.IsNullOrWhiteSpace(audienceId))
            //    throw new InvalidOperationException("AuthenticationTicket.Properties does not include audience");

            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(Base64Secret));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;
            var token = new JwtSecurityToken(_issuer, _audience, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingCredentials);
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);
            return jwt;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(protectedText))
                {
                    throw new ArgumentNullException("protectedText");
                }

                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

                var token = handler.ReadToken(protectedText) as JwtSecurityToken;

                if (token == null)
                {
                    throw new ArgumentOutOfRangeException("protectedText", "Invalid Jwt");
                }

                var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(Base64Secret));
                var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

                TokenValidationParameters validationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = _issuer,
                    ValidAudience = _audience,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    LifetimeValidator = LifetimeValidator,
                    IssuerSigningKey = securityKey
                };

                SecurityToken validatedToken = null;
                var principal = handler.ValidateToken(protectedText, validationParameters, out validatedToken);
                var identity = principal.Identities;

                return new AuthenticationTicket(identity.First(), new AuthenticationProperties());
            }
            catch
            {
                return null;
            }
        }

        public bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (expires != null)
            {
                if (DateTime.UtcNow < expires) return true;
            }
            return false;
        }
    }
}