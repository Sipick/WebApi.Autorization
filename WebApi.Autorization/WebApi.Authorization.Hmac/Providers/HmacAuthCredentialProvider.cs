using WebApi.Authorization.Hmac;
using WebApi.Authorization.Hmac.ArtefactContainer;
using WebApi.Authorization.Hmac.Providers.Interfaces;

namespace WebApi.Authorization.Basic.Providers;

public class HmacAuthCredentialProvider : IHmacAuthCredentialProvider
{
    private readonly IEnumerable<IHmacCoreClaimsProvider> _hmacCoreClaimsProviders;

    public HmacAuthCredentialProvider(IEnumerable<IHmacCoreClaimsProvider> hmacCoreClaimsProviders)
    {
        _hmacCoreClaimsProviders = hmacCoreClaimsProviders;
    }

    public async Task<HmacCredentials> GetCredentialAsync(HmacArtefactContainer artefactContainer)
    {
        var credentials = await RetrieveCredentialsAsync(artefactContainer);

        foreach (var provider in _hmacCoreClaimsProviders)
        {
            var claims = await provider.GetClaimsAsync(artefactContainer);
            if (credentials == null)
            {
                continue;
            }

            credentials.Claims.AddRange(claims);
        }

        return credentials ?? new HmacCredentials();
    }

    protected virtual Task<HmacCredentials> RetrieveCredentialsAsync(HmacArtefactContainer artefactContainer)
    {
        return Task.FromResult(new HmacCredentials());
    }
}
