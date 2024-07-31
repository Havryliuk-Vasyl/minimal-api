namespace FlamerService.Authorization
{
    public class JWTSettings
    {
        public string SecretKey { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }

        public JWTSettings(string secretKey, string issuer, string audience)
        {
            SecretKey = secretKey;
            Issuer = issuer;
            Audience = audience;
        }
    }
}
