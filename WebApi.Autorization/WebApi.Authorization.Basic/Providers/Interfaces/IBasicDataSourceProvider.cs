using WebApi.Authorization.Basic.ArtefactContainer;
using WebApi.Authorization.Services;

namespace WebApi.Authorization.Basic.Providers.Interfaces;

public interface IBasicDataSourceProvider : IDataSourceProvider<BasicArtefactContainer, BasicCredentials> { }
