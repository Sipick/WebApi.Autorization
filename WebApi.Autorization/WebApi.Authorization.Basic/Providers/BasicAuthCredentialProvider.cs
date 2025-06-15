using WebApi.Authorization.Basic.ArtefactContainer;
using WebApi.Authorization.Basic.Providers.Interfaces;

namespace WebApi.Authorization.Basic.Providers;

public class BasicAuthCredentialProvider : IBasicAuthCredentialProvider
{
    private readonly IEnumerable<IBasicCoreClaimsProvider> _basicCoreClaimsProviders;

    public BasicAuthCredentialProvider(IEnumerable<IBasicCoreClaimsProvider> basicCoreClaimsProviders)
    {
        _basicCoreClaimsProviders = basicCoreClaimsProviders;
    }

    public async Task<BasicCredentials> GetCredentialAsync(BasicArtefactContainer artefactContainer)
    {
        var credentials = await RetrieveCredentialsAsync(artefactContainer);

        foreach (var provider in _basicCoreClaimsProviders)
        {
            var claims = await provider.GetClaimsAsync(artefactContainer);
            if (credentials == null)
            {
                continue;
            }

            credentials.Claims.AddRange(claims);
        }

        return credentials ?? new BasicCredentials();
    }

    protected virtual Task<BasicCredentials> RetrieveCredentialsAsync(BasicArtefactContainer artefactContainer)
    {
        return Task.FromResult(new BasicCredentials());
    }
}
