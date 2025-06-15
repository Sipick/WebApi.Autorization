using System.Net.Http.Headers;

using Microsoft.AspNetCore.Http;

namespace WebApi.Authorization.Basic.ArtefactContainer;

internal class BasicArtefactContainerParser : Artefact.ArtefactContainerParser<BasicArtefactContainer>
{
    public override bool TryParse(IHeaderDictionary headers, out BasicArtefactContainer artefactContainer)
    {
        artefactContainer = null;

        if (!TryParseToAuthenticationHeaderValue(headers, out AuthenticationHeaderValue authHeader))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(authHeader.Parameter) ||
            !authHeader.Scheme.Equals(BasicAuthenticationSchemeOptions.SchemeName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        //var base64Credentials = authHeader.Parameter.Substring(6).Trim();
        var credentials = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter ?? string.Empty)).Split(':', 2);
        if (credentials.Length != 2)
        {
            return false;
        }

        artefactContainer = new BasicArtefactContainer
        {
            Username = credentials[0],
            Password = credentials[1],
            Scheme = authHeader.Scheme,
            AuthenticationHeaderValue = authHeader
        };

        return true;
    }
}