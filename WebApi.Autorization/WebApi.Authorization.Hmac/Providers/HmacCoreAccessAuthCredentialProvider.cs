using WebApi.Authorization.Hmac;
using WebApi.Authorization.Hmac.ArtefactContainer;
using WebApi.Authorization.Hmac.Providers.Interfaces;

namespace WebApi.Authorization.Basic.Providers;

public class HmacCoreAccessAuthCredentialProvider : HmacAuthCredentialProvider, IHmacAuthCredentialProvider
{
    private readonly IHmacDataSourceProvider _hmacDataSourceProvider;
    private readonly IEnumerable<IHmacCoreClaimsProvider> _hmacCoreClaimsProviders;

    public HmacCoreAccessAuthCredentialProvider(IHmacDataSourceProvider hmacDataSourceProvider, IEnumerable<IHmacCoreClaimsProvider> hmacCoreClaimsProviders)
        : base(hmacCoreClaimsProviders)
    {
        _hmacDataSourceProvider = hmacDataSourceProvider;
        _hmacCoreClaimsProviders = hmacCoreClaimsProviders;
    }

    protected override async Task<HmacCredentials> RetrieveCredentialsAsync(HmacArtefactContainer artefactContainer)
    {
        return await _hmacDataSourceProvider.GetCredentialAsync(artefactContainer);
    }
}
