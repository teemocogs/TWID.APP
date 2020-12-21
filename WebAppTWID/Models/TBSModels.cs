using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;

namespace WebAppTWID.Models
{
    public class TBSModels
    {
        public string tbs = "TBS";
        public string tbsEncoding = "NONE";
        public string hashAlgorithm = "SHA256";
        public string withCardSN = "true";
        public string pin = string.Empty;
        public string nonce = string.Empty;
        public string func = "MakeSignature";
        public string signatureType = "PKCS7";
    }

    public class MyWebClient : WebClient
    {
        protected override WebRequest GetWebRequest(Uri uri)
        {
            WebRequest WR = base.GetWebRequest(uri);
            WR.Timeout = 30 * 1000;
            return WR;
        }
    }
}