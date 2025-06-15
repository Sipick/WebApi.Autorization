using WebApi.Authorization.Hmac.ArtefactContainer;
using WebApi.Authorization.Services;

namespace WebApi.Authorization.Hmac.Providers.Interfaces;

public interface IHmacDataSourceProvider : IDataSourceProvider<HmacArtefactContainer, HmacCredentials> { }
