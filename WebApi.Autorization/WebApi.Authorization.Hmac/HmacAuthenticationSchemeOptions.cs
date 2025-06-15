using Microsoft.AspNetCore.Authentication;

namespace WebApi.Authorization.Hmac;

public class HmacAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public const string HawkScheme = Scheme.Hawk;

    public const string HmacCustomScheme = Scheme.HmacCustom;

    public HmacAuthenticationSchemeOptions() { }

    public uint ClockSkewSeconds { get; set; } = 1800;
}
