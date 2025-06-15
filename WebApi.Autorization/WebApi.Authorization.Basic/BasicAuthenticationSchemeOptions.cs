using Microsoft.AspNetCore.Authentication;

namespace WebApi.Authorization;

public class BasicAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public const string SchemeName = Scheme.Basic;

    public uint ClockSkewSeconds { get; set; }

    public BasicAuthenticationSchemeOptions()
    {
        ClockSkewSeconds = 1800;
    }
}
