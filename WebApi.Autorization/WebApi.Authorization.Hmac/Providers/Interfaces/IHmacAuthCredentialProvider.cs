using WebApi.Authorization.Hmac.ArtefactContainer;

namespace WebApi.Authorization.Hmac.Providers.Interfaces;

public interface IHmacAuthCredentialProvider
{
    Task<HmacCredentials> GetCredentialAsync(HmacArtefactContainer artefactContainer);
}
