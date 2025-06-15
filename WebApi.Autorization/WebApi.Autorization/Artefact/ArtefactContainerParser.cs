using System.Net.Http.Headers;

using Microsoft.AspNetCore.Http;

namespace WebApi.Authorization.Artefact;

public abstract class ArtefactContainerParser<T> where T : ArtefactContainer
{
    protected virtual bool TryParseToAuthenticationHeaderValue(IHeaderDictionary headers, out AuthenticationHeaderValue authenticationHeader)
    {
        authenticationHeader = null;

        if (!headers.ContainsKey("Authorization") || !AuthenticationHeaderValue.TryParse(headers["Authorization"], out authenticationHeader))
        {
            return false;
        }

        return true;
    }

    public abstract bool TryParse(IHeaderDictionary headers, out T artefactContainer);
}