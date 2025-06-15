using System.Globalization;
using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

using WebApi.Authorization.Hmac.ArtefactContainer;

namespace WebApi.Authorization.Hmac;

internal class HmacNormalizedRequest
{
    private readonly HmacArtefactContainer _Artifacts;
    private readonly string _Method;
    private readonly string _Path;
    // Hawk Parameter
    private readonly string _HostName;
    private readonly string _Port;
    private readonly string _Scheme;

    internal HmacNormalizedRequest(HttpRequest request, HmacArtefactContainer artifacts, string scheme)
    {
        var req = request.GetEncodedPathAndQuery();
        // We have special characters, which are not correctly received by ASP.NET core...
        // so we need to encode them again to have the same path...
        req = req.Replace("+", Uri.EscapeDataString("+"));
        req = req.Replace("(", Uri.EscapeDataString("("));
        req = req.Replace(")", Uri.EscapeDataString(")"));

        _Artifacts = artifacts;

        // Hawk Parameter _port + _hostName

        // Customization to get it to work with Azure Applicationgateway
        if (request.Headers.ContainsKey("X-FORWARDED-PORT"))
        {
            _Port = request.Headers["X-FORWARDED-PORT"];
        }
        else
        {
            _Port = request.Host.Port.ToString();
        }

        // Fallback for IIS. The IIS set the Host.port only if this in the URL
        if (String.IsNullOrEmpty(_Port))
        {
            if (request.IsHttps)
            {
                _Port = "443";
            }
            else
            {
                _Port = "80";
            }
        }


        // Customization to get it to work with Azure Applicationgateway
        if (request.Headers.ContainsKey("X-ORIGINAL-HOST"))
        {
            _HostName = request.Headers["X-ORIGINAL-HOST"];
        }
        else
        {
            _HostName = request.Host.Host;
        }

        _Scheme = scheme;
        _Method = request.Method.ToUpper(CultureInfo.InvariantCulture);
        _Path = req;
    }

    internal HmacNormalizedRequest(HttpRequestMessage request, HmacArtefactContainer artifacts, string scheme)
    {
        _Artifacts = artifacts;
        _Method = request.Method.ToString().ToUpper(CultureInfo.InvariantCulture);
        _Path = request.RequestUri.PathAndQuery;
        _Scheme = scheme;
    }

    public override string ToString()
    {
        if (_Scheme.Equals(HmacAuthenticationSchemeOptions.HmacCustomScheme, StringComparison.OrdinalIgnoreCase))
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendNewLine(_PreambleHc)
                .AppendNewLine(_Artifacts.Timestamp.ToString(CultureInfo.InvariantCulture))
                .AppendNewLine(_Artifacts.Nonce)
                .AppendNewLine(_Method)
                .AppendNewLine(_Path)
                .AppendNewLine(_Artifacts.PayloadHash == null ? null : Convert.ToBase64String(_Artifacts.PayloadHash))
                .AppendNewLine(_Artifacts.ApplicationSpecificData);
            return builder.ToString();
        }
        else
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendNewLine(_PreambleHawk)
                .AppendNewLine(_Artifacts.Timestamp.ToString(CultureInfo.InvariantCulture))
                .AppendNewLine(_Artifacts.Nonce)
                .AppendNewLine(_Method)
                .AppendNewLine(_Path)

                // Hawk Parameter
                .AppendNewLine(_HostName)
                .AppendNewLine(_Port)

                .AppendNewLine(_Artifacts.PayloadHash == null ? null : Convert.ToBase64String(_Artifacts.PayloadHash))
                .AppendNewLine(_Artifacts.ApplicationSpecificData);
            return builder.ToString();
        }
    }

    internal byte[] ToBytes()
    {
        return Encoding.UTF8.GetBytes(ToString());
    }

    private const string _PreambleHc = "hc.1.header";

    private const string _PreambleHawk = "hawk.1.header";
}
