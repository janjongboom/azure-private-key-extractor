using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Mvc.Ajax;
using PrivateKeyExtractor.Models;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using System.Text;
using System.IO;

namespace PrivateKeyExtractor
{	
	public class HomeController : Controller
	{
		[AcceptVerbs(HttpVerbs.Post)]
		public ActionResult Index(ExtractRequestModel model) {
			
			var cert = model.ManagementCertificate;
			var c = new X509Certificate2(Convert.FromBase64String(cert));
			var prv = c.PrivateKey;
			
			RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
     		RSA.FromXmlString(prv.ToXmlString(true));
			
			var prvKey  = DotNetUtilities.GetRsaKeyPair(RSA);
			
			return Json(new {
				privateKey = GimmeKey(prvKey.Private)
			});
		}
		
		[AcceptVerbs(HttpVerbs.Get)]
		public ActionResult Index() {
			return Content("Welcome. To get the public key from an Azure Management Certificate, post it to '/' with POST value 'ManagementCertificate=X'");
		}
		
		private static string GimmeKey(AsymmetricKeyParameter key) {
			var sb = new StringBuilder();
			using (var prvSw = new StringWriter(sb)) {
				var pmw = new Org.BouncyCastle.OpenSsl.PemWriter(prvSw);
				pmw.WriteObject(key);
			}
			return sb.ToString();
		}
	}
}

