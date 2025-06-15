using System.Net.Http.Headers;
using System.Text.RegularExpressions;

using Microsoft.AspNetCore.Http;

using WebApi.Authorization.Artefact;

namespace WebApi.Authorization.Hmac.ArtefactContainer;

internal class HmacArtefactContainerParser : ArtefactContainerParser<HmacArtefactContainer>
{
    public override bool TryParse(IHeaderDictionary headers, out HmacArtefactContainer artefactContainer)
    {
        artefactContainer = null;

        if (!TryParseToAuthenticationHeaderValue(headers, out AuthenticationHeaderValue authHeader))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(authHeader.Parameter) ||
            !authHeader.Scheme.Equals(HmacAuthenticationSchemeOptions.HawkScheme, StringComparison.OrdinalIgnoreCase) ||
            !authHeader.Scheme.Equals(HmacAuthenticationSchemeOptions.HmacCustomScheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var tempArtefactContainer = new HmacArtefactContainer
        {
            Scheme = authHeader.Scheme,
            AuthenticationHeaderValue = authHeader
        };

        var keysToBeProcessed = new HashSet<string>
        {
            "id",
            "ts",
            "nonce",
            "ext",
            "mac",
            "hash",
            "tsm"
        };

        var unparsed = Regex.Replace(authHeader.Parameter, "(\\w+)=\"([^\"\\\\]*)\"\\s*(?:,\\s*|$)",
            match =>
            {
                string key = match.Groups[1].Value.Trim();
                string str = match.Groups[2].Value.Trim();
                if (!Regex.Match(str, "^[ \\w\\!#\\$%&'\\(\\)\\*\\+,\\-\\.\\/\\:;<\\=>\\?@\\[\\]\\^`\\{\\|\\}~]+$")
                        .Success || !keysToBeProcessed.Any(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase)))
                {
                    return str;
                }

                switch (key)
                {
                    case "id":
                        tempArtefactContainer.Id = str;
                        break;
                    case "ts":
                        if (!ulong.TryParse(str, out ulong result1))
                        {
                            return str;
                        }

                        tempArtefactContainer.Timestamp = result1;
                        break;
                    case "nonce":
                        tempArtefactContainer.Nonce = str;
                        break;
                    case "ext":
                        tempArtefactContainer.ApplicationSpecificData = str;
                        break;
                    case "mac":
                        tempArtefactContainer.Mac = Convert.FromBase64String(str);
                        break;
                    case "hash":
                        tempArtefactContainer.PayloadHash = Convert.FromBase64String(str);
                        break;
                }

                keysToBeProcessed.Remove(key);
                return string.Empty;
            });

        if (!string.IsNullOrEmpty(unparsed) || !tempArtefactContainer.IsValid)
        {
            return false;
        }

        artefactContainer = tempArtefactContainer;
        return true;
    }
}
