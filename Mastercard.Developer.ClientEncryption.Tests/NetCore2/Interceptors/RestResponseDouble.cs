using System;
using System.Collections.Generic;
using System.Net;
using RestSharp;
using RestRequest = RestSharp.RestRequest;
using RestResponse = RestSharp.RestResponse;

namespace Mastercard.Developer.ClientEncryption.Tests.NetCore.Interceptors
{
    internal class RestResponseDouble : RestResponse
    {
        public new RestRequest Request { get; set; } = null;
        public new Uri ResponseUri { get; set; } = null;
        public new string Server { get; set; }
        public new byte[] RawBytes { get; set; } = null;
        public new string ContentType { get; set; } = null;
        public new long ContentLength { get; set; }
        public new string ContentEncoding { get; set; }
        public new IList<HeaderParameter> Headers { get; }
        public new ResponseStatus ResponseStatus { get; set; }
        public new string ErrorMessage { get; set; }
        public new Exception ErrorException { get; set; }
        public Version ProtocolVersion { get; set; }
        public new HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
        public new bool IsSuccessful => true;

        public new string StatusDescription { get; set; } = null;

        private Lazy<string> _content;

        public RestResponseDouble(IList<HeaderParameter> headers, string content)
        {
            Headers = headers;
            Content = content;
            base.Headers = (IReadOnlyCollection<HeaderParameter>)headers;
            base.Content = content;
        }

        public new string Content
        {
            get => _content.Value;
            set => _content = new Lazy<string>(() => value);
        }
    }
}
