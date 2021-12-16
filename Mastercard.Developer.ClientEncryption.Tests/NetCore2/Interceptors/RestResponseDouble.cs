using System;
using System.Collections.Generic;
using System.Net;
using RestSharp;
using IRestRequest = RestSharp.IRestRequest;
using IRestResponse = RestSharp.IRestResponse;
using Parameter = RestSharp.Parameter;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Interceptors
{
    internal class RestResponseDouble : IRestResponse
    {
        public IRestRequest Request { get; set; } = null;
        public Uri ResponseUri { get; set; } = null;
        public string Server { get; set; }
        public byte[] RawBytes { get; set; } = null;
        public string ContentType { get; set; } = null;
        public long ContentLength { get; set; }
        public string ContentEncoding { get; set; }
        public IList<RestResponseCookie> Cookies { get; } = null;
        public IList<Parameter> Headers { get; }
        public ResponseStatus ResponseStatus { get; set; }
        public string ErrorMessage { get; set; }
        public Exception ErrorException { get; set; }
        public Version ProtocolVersion { get; set; }
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
        public bool IsSuccessful => true;

        public string StatusDescription { get; set; } = null;

        private Lazy<string> _content;

        public RestResponseDouble(IList<Parameter> headers, string content)
        {
            Headers = headers;
            Content = content;
        }

        public string Content
        {
            get => _content.Value;
            set => _content = new Lazy<string>(() => value);
        }
    }
}
