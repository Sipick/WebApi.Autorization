using WebApi.Authorization.Basic.ArtefactContainer;

namespace WebApi.Authorization.Basic.Providers.Interfaces
{
    public interface IBasicAuthCredentialProvider
    {
        Task<BasicCredentials> GetCredentialAsync(BasicArtefactContainer artefactContainer);
    }
}