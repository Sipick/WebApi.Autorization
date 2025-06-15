using System.Security.Claims;
using System.Text.Encodings.Web;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using WebApi.Authorization.Basic.ArtefactContainer;
using WebApi.Authorization.Basic.Providers.Interfaces;

namespace WebApi.Authorization.Basic.Handler;

public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationSchemeOptions>
{
    private readonly IBasicAuthCredentialProvider _authCredentialProvider;
    private readonly BasicArtefactContainerParser _artefactContainerParser;

    public BasicAuthenticationHandler(
        IBasicAuthCredentialProvider authCredentialProvider,
        IOptionsMonitor<BasicAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
        _authCredentialProvider = authCredentialProvider;
        _artefactContainerParser = new BasicArtefactContainerParser();
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            if (!_artefactContainerParser.TryParse(Request.Headers, out var artefactContainer))
            {
                return AuthenticateResult.Fail("Invalid Authorization Header or Scheme");
            }

            var basicCredentials = await _authCredentialProvider.GetCredentialAsync(artefactContainer);

            if (artefactContainer.Username != basicCredentials.Username || artefactContainer.Password != basicCredentials.Password)
            {
                return AuthenticateResult.Fail("Invalid Username or Password");
            }

            var identity = new ClaimsIdentity(basicCredentials.Claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        catch
        {
            return AuthenticateResult.Fail("Invalid Authorization Header");
        }
    }
}
