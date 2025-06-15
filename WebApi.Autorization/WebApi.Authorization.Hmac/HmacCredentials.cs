using System.Security.Cryptography;

namespace WebApi.Authorization.Hmac;

public class HmacCredentials : CoreCredentials
{
    public string Id { get; set; }

    public HMAC Hmac1 { get; set; }

    public HMAC Hmac2 { get; set; }
}
