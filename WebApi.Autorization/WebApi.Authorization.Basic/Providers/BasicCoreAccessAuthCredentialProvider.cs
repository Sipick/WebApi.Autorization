using WebApi.Authorization.Basic.ArtefactContainer;
using WebApi.Authorization.Basic.Providers.Interfaces;

namespace WebApi.Authorization.Basic.Providers;

public class BasicCoreAccessAuthCredentialProvider : BasicAuthCredentialProvider, IBasicAuthCredentialProvider
{
    private readonly IBasicDataSourceProvider _basicDataSourceProvider;

    public BasicCoreAccessAuthCredentialProvider(IBasicDataSourceProvider basicDataSourceProvider, IEnumerable<IBasicCoreClaimsProvider> basicCoreClaimsProviders)
        : base(basicCoreClaimsProviders)
    {
        _basicDataSourceProvider = basicDataSourceProvider;
    }

    protected override async Task<BasicCredentials> RetrieveCredentialsAsync(BasicArtefactContainer artefactContainer)
    {
        return await _basicDataSourceProvider.GetCredentialAsync(artefactContainer);
    }
}
