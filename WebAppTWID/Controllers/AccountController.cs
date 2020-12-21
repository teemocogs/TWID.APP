using DBHelper;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using NLog;
using System;
using System.Collections.Specialized;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using WebAppTWID.Models;

namespace WebAppTWID.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        #region ApplicationSetting

        private ApplicationUserManager _userManager;
        private ApplicationRoleManager _roleManager;

        public AccountController()
        {
        }

        public AccountController(ApplicationUserManager userManager, ApplicationRoleManager roleManager)
        {
            UserManager = userManager;
            RoleManager = roleManager;
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        public ApplicationRoleManager RoleManager
        {
            get
            {
                return _roleManager ?? HttpContext.GetOwinContext().Get<ApplicationRoleManager>();
            }
            private set
            {
                _roleManager = value;
            }
        }
        #endregion ApplicationSetting

        #region 登入、註冊
        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            //Validate Google recaptcha here
            var response = Request["g-recaptcha-response"];

            //if ((Session["CheckCode"] != null) && (string.IsNullOrEmpty(model.VerifyCode) == false))
            if (string.IsNullOrEmpty(response))
            {
                ModelState.AddModelError("", "登入嘗試失試。");
                return View(model);
            }
#if  !DEBUG
            string secretKey = "";
            var client = new System.Net.WebClient();
            var resultStr = client.DownloadString(string.Format("https://www.google.com/recaptcha/api/siteverify?secret={0}&response={1}", secretKey, response));
            var obj = Newtonsoft.Json.Linq.JObject.Parse(resultStr);
            var status = (bool)obj.SelectToken("success");

            if (status == false)
            {
                ModelState.AddModelError("", "登入嘗試失試。");
                return View(model);
            }
#endif
            ApplicationUser user = UserManager.FindByEmail(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "登入嘗試失試。");
                return View(model);
            }

            await SignInAsync(user, model.RememberMe);

            string ipAddress = string.Empty;
            if (!String.IsNullOrEmpty(System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"]))
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"];
            else
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];

            return RedirectToLocal(returnUrl);

        }


        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.PTTID, Email = model.Email };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await SignInAsync(user, isPersistent: false); //, rememberBrowser: false

                    // 如需如何進行帳戶確認及密碼重設的詳細資訊，請前往 https://go.microsoft.com/fwlink/?LinkID=320771
                    // 傳送包含此連結的電子郵件
                    string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    await UserManager.SendEmailAsync(user.Id, "驗證您的Email帳戶", "請按一下此連結驗證您的帳戶 <a href=\"" + callbackUrl + "\">這裏</a>");

                    //角色名稱
                    var roleName = "Member"; // (model.PTTID != "某ID") ?  "Member" :

                    //判斷角色是否存在
                    if (RoleManager.RoleExists(roleName) == false)
                    {
                        //角色不存在,建立角色
                        var role = new Microsoft.AspNet.Identity.EntityFramework.IdentityRole(roleName);
                        await RoleManager.CreateAsync(role);
                    }
                    //將使用者加入該角色
                    await UserManager.AddToRoleAsync(user.Id, roleName);

                    string ipAddress = string.Empty;
                    if (!String.IsNullOrEmpty(System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"]))
                        ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"];
                    else
                        ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];

                    //發送專屬序號
                    await Task.Run(() => SendBase5UserId(model.PTTID, user.Id, ipAddress));



                    return RedirectToAction("Index", "Home");
                }
                AddErrors(result);
            }

            // 如果執行到這裡，發生某項失敗，則重新顯示表單
            return View(model);
        }
        #endregion 登入、註冊

        #region 刪除站台帳號
        //
        // POST: /Account/DeleteAccount
        [Authorize]
        [ActionFilter.ActionLog(Description = "刪除站台帳號")]
        public ActionResult DeleteAccount()
        {
            try
            {
                using (TWIDAPPEntities DBObj = new TWIDAPPEntities())
                {
                    var VIDs = DBObj.Verification.Where(x => x.PTTID == User.Identity.Name).ToList();
                    if (VIDs != null)
                    {
                        DBObj.Verification.RemoveRange(VIDs);
                        DBObj.SaveChanges();
                    }

                    ApplicationDbContext context = new ApplicationDbContext();
                    var user = context.Users.Find(User.Identity.GetUserId());
                    if (user != null)
                    {
                        context.Users.Remove(user);
                        context.SaveChanges();
                    }
                }
            }
            catch (Exception ex)
            {
                string meg = $"/Account/DeleteAccount";
                logger.Debug(meg);
                logger.Debug($"[Exception]{ex.Message}.{ex.InnerException.Message}");
                logger.Debug(ex.StackTrace);
            }
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }
        #endregion 刪除站台帳號

        #region 原生
        //
        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            try
            {
                var result = await UserManager.ConfirmEmailAsync(userId, code);
                return View(result.Succeeded ? "ConfirmEmail" : "Error");
            }
            catch (Exception ex)
            {
                string meg = $"/Account/ConfirmEmail?userId={userId}&code={code}";
                logger.Debug(meg);
                logger.Debug($"[Exception]{ex.Message}.{ex.InnerException.Message}");
                logger.Debug(ex.StackTrace);
            }
            return View("Error");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // 不顯示使用者不存在或未受確認
                    return View("ForgotPasswordConfirmation");
                }

                // 如需如何進行帳戶確認及密碼重設的詳細資訊，請前往 https://go.microsoft.com/fwlink/?LinkID=320771
                // 傳送包含此連結的電子郵件
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
                // await UserManager.SendEmailAsync(user.Id, "重設密碼", "請按 <a href=\"" + callbackUrl + "\">這裏</a> 重設密碼");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // 如果執行到這裡，發生某項失敗，則重新顯示表單
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // 不顯示使用者不存在
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // 要求重新導向至外部登入提供者
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }


        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

            }

            base.Dispose(disposing);
        }

        #endregion 原生

        #region Helper
        // 新增外部登入時用來當做 XSRF 保護
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, await user.GenerateUserIdentityAsync(UserManager));
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion


        #region 驗證信相關：Email
        [Authorize]
        public ActionResult EmailVerify()
        {
            var manager = HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            var user = manager.FindByName(User.Identity.Name);
            ViewBag.EmailConfirmed = user.EmailConfirmed;
            return View();
        }

        [HttpPost]
        [Authorize]
        [ActionFilter.ActionLog(Description = "發送Email驗證信至Email")]
        public async System.Threading.Tasks.Task<ActionResult> BeaconEmail()
        {
            string UserGID = User.Identity.GetUserId();
            string code = await UserManager.GenerateEmailConfirmationTokenAsync(UserGID);
            var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = UserGID, code = code }, protocol: Request.Url.Scheme);
            await UserManager.SendEmailAsync(UserGID, "驗證您的Email帳戶", "請按一下此連結驗證您的帳戶 <a href=\"" + callbackUrl + "\">這裏</a>");
            return RedirectToAction("Index", "home");
        }
        #endregion 驗證信相關：Email

        #region 驗證信相關：PTTID
        [HttpPost]
        [Authorize]
        [ActionFilter.ActionLog(Description = "發送PTTID驗證信至站內")]
        public async System.Threading.Tasks.Task<ActionResult> BeaconPTTID()
        {
            string UserGID = User.Identity.GetUserId();
            string PTTID = User.Identity.Name;

            string ipAddress = string.Empty;
            if (!String.IsNullOrEmpty(System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"]))
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"];
            else
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];

            await System.Threading.Tasks.Task.Run(() => SendBase5UserId(PTTID, UserGID, ipAddress));
            return RedirectToAction("Index", "home");
        }

        /// <summary>
        /// Send Base5 UserId for verify check PTTID.
        /// </summary>
        /// <param name="PTTID"></param>
        /// <param name="UserGID"></param>
        /// <param name="ipAddress"></param>
        /// <param name="CreateDate"></param>
        /// <param name="ModifyDate"></param>
        private async void SendBase5UserId(string PTTID, string UserGID, string ipAddress)
        {
            string PTTMail = string.Format("{0}.bbs@ptt.cc", PTTID);

            string strUserID = UserGID.Replace("-", "").ToUpper();
            int iUserIDlen = strUserID.Length - 3;
            Random random = new Random();
            int iIndex = random.Next(0, iUserIDlen);
            string Base5 = string.Format("{0}{1}", strUserID.Substring(iIndex, 3), iIndex.ToString("00"));

            IdentityMessage IM = new IdentityMessage();
            IM.Subject = "TWID.app PTTID Verification code";
            IM.Body = Base5;
            IM.Destination = PTTMail;

            try
            {
                EmailService ES = new EmailService();
                await ES.SendAsyncBodyANSI(IM);

                using (TWIDAPPEntities DBObj = new TWIDAPPEntities())
                {
                    bool isNewPTTID = false;
                    //0"PTTID" 
                    Verification VID = DBObj.Verification.Where(x => (x.PTTID == PTTID) && (x.VerifyType == 0)).FirstOrDefault();

                    if (VID == null)
                    {
                        VID = new Verification();
                        VID.PTTID = PTTID;
                        VID.CreateDate = DateTime.Now;
                        VID.CreateDateIP = ipAddress;
                        VID.VerifyType = 0;
                        isNewPTTID = true;

                    }
                    VID.Base5 = Base5;

                    if (isNewPTTID)
                    {
                        DBObj.Verification.Add(VID);
                    }
                    else
                    {
                        DBObj.Entry(VID).State = EntityState.Modified;
                    }
                    DBObj.SaveChanges();


                }

            }
            catch (Exception ex)
            {
                string meg = $"/Account/SendBase5UserId";
                logger.Debug(meg);
                logger.Debug($"[Exception]{ex.Message}.{ex.InnerException.Message}");
                logger.Debug(ex.StackTrace);
            }
        }

        [Authorize]
        public ActionResult PTTIDVerify()
        {
            bool isConfirmed = false;
            using (TWIDAPPEntities DBObj = new TWIDAPPEntities())
            {
                //0"PTTID" 
                Verification VID = DBObj.Verification.Where(x => (x.PTTID == User.Identity.Name) && (x.VerifyType == 0)).FirstOrDefault();
                if (VID != null)
                {
                    isConfirmed = VID.IsConfirmed;
                }
            }
            ViewBag.isPTTIDConfirmed = isConfirmed;
            return View();
        }

        [HttpPost]
        [Authorize]
        public ActionResult CheckBase5UserId(string code = "")
        {
            if (code.Length != 5) return RedirectToAction("Index", "home");
            string UserGID = User.Identity.GetUserId();
            string strUserID = UserGID.Replace("-", "").ToUpper();
            string Base3 = code.Substring(0, 3).ToUpper();

            string ipAddress = string.Empty;
            if (!String.IsNullOrEmpty(System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"]))
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"];
            else
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];

            try
            {
                using (TWIDAPPEntities DBObj = new TWIDAPPEntities())
                {
                    //0"PTTID" 
                    Verification VID = DBObj.Verification.Where(x => (x.PTTID == User.Identity.Name) && (x.VerifyType == 0)).FirstOrDefault();

                    if ((VID == null) || (VID.Base5.IndexOf(Base3) != 0))
                    {
                        return RedirectToAction("Index", "home");
                    }
                    VID.IsConfirmed = true;
                    VID.AvailableDate = DateTime.Now.AddYears(1);
                    VID.ModifyDate = DateTime.Now;
                    VID.ModifyDateIP = ipAddress;
                    DBObj.Entry(VID).State = EntityState.Modified;

                    var ID = DBObj.AspNetUsers.Where(x => x.UserName == User.Identity.Name).FirstOrDefault();
                    ID.VerifyType0 = true;
                    DBObj.Entry(ID).State = EntityState.Modified;

                    DBObj.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                string meg = $"/Account/CheckBase5UserId";
                logger.Debug(meg);
                logger.Debug($"[Exception]{ex.Message}.{ex.InnerException.Message}");
                logger.Debug(ex.StackTrace);
            }
            return RedirectToAction("Index", "home");
        }
        #endregion 驗證信相關：PTTID

        #region 驗證信相關：自然人
        //MOICAConfirmed
        [HttpPost]
        [Authorize]
        [ActionFilter.ActionLog(Description = "發送MOICA驗證信至站內")]
        public async System.Threading.Tasks.Task<ActionResult> BeaconMOICA()
        {
            string UserGID = User.Identity.GetUserId();
            string PTTID = User.Identity.Name;

            string ipAddress = string.Empty;
            if (!String.IsNullOrEmpty(System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"]))
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"];
            else
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];

            await System.Threading.Tasks.Task.Run(() => SendNonce(PTTID, UserGID, ipAddress, null, DateTime.Now));
            return RedirectToAction("Index", "home");
        }

        /// <summary>
        /// Send Nonce for verify check MOICA.
        /// </summary>
        /// <param name="PTTID"></param>
        /// <param name="UserGID"></param>
        /// <param name="ipAddress"></param>
        /// <param name="CreateDate"></param>
        /// <param name="ModifyDate"></param>
        private async void SendNonce(string PTTID, string UserGID, string ipAddress, DateTime? CreateDate, DateTime? ModifyDate)
        {
            string PTTMail = string.Format("{0}.bbs@ptt.cc", PTTID);

            string strUserID = UserGID.Replace("-", "").ToUpper();
            int iUserIDlen = strUserID.Length - 3;
            Random random = new Random();
            int iIndex = random.Next(0, iUserIDlen);
            string Base5 = string.Format("{0}{1}", strUserID.Substring(iIndex, 3), iIndex.ToString("00"));

            IdentityMessage IM = new IdentityMessage();
            IM.Subject = "TWID.app MOICA Verification code";
            IM.Body = Base5;
            IM.Destination = PTTMail;

            try
            {
                EmailService ES = new EmailService();
                await ES.SendAsyncBodyANSI(IM);

                using (TWIDAPPEntities DBObj = new TWIDAPPEntities())
                {
                    bool isNewPTTID = false;

                    Verification VID = DBObj.Verification.Where(x => (x.PTTID == PTTID) && (x.VerifyType == 1)).FirstOrDefault();

                    if (VID == null)
                    {
                        VID = new Verification();
                        VID.PTTID = PTTID;
                        VID.VerifyType = 1; //1"MOICA"
                        isNewPTTID = true;
                        VID.CreateDate = DateTime.Now;
                        VID.CreateDateIP = ipAddress;
                        VID.AvailableDate = DateTime.Now.AddYears(1);
                    }

                    if (ModifyDate.HasValue) VID.ModifyDate = ModifyDate.Value;

                    VID.Base5 = Base5;

                    if (isNewPTTID)
                    {
                        DBObj.Verification.Add(VID);
                    }
                    else
                    {
                        DBObj.Entry(VID).State = EntityState.Modified;
                    }
                    DBObj.SaveChanges();


                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        [Authorize]
        public ActionResult PKCS7Verify()
        {
            bool isConfirmed = false;
            using (TWIDAPPEntities DBObj = new TWIDAPPEntities())
            {
                //1"MOICA"
                Verification VID = DBObj.Verification.Where(x => (x.PTTID == User.Identity.Name) && (x.VerifyType == 1)).FirstOrDefault();
                if (VID != null)
                {
                    isConfirmed = VID.IsConfirmed;
                }
            }
            ViewBag.isMOICAConfirmed = isConfirmed;
            return View();
        }

        [HttpPost]
        [Authorize]
        public ActionResult PKCS7Verify(string b64SignedData = "", string digitalSignature = "")
        {

            if (string.IsNullOrEmpty(b64SignedData) || string.IsNullOrEmpty(digitalSignature))
                return RedirectToAction("Index", "home");

            string UserGID = User.Identity.GetUserId();
            string strUserID = UserGID.Replace("-", "").ToUpper();
            string Nonce = string.Empty;

            string ipAddress = string.Empty;
            if (!String.IsNullOrEmpty(System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"]))
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"];
            else
                ipAddress = System.Web.HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];

            try
            {
                using (TWIDAPPEntities DBObj = new TWIDAPPEntities())
                {
                    //1"MOICA"   VID.VerifyType = 1;
                    Verification VID = DBObj.Verification.Where(x => (x.PTTID == User.Identity.Name) && (x.VerifyType == 1)).FirstOrDefault();

                    if ((VID == null))
                    {
                        return RedirectToAction("Index", "home");
                    }
                    Nonce = $"Nonce:{VID.Base5}";

                    string url = "https://gpkiapi.nat.gov.tw/PKCS7Verify/VerifyPKCS7.jsp";

                    MyWebClient client = new MyWebClient();
                    client.Encoding = Encoding.UTF8; // 設定Webclient.Encoding

                    string html = "未知";

                    // 指定 WebClient 編碼
                    client.Encoding = Encoding.UTF8;
                    // 指定 WebClient 的 Content-Type header
                    client.Headers.Add(HttpRequestHeader.ContentType, "application/x-www-form-urlencoded");

                    //要傳送的資料內容(依字串表示)   
                    NameValueCollection nc = new NameValueCollection();
                    nc["b64SignedData"] = b64SignedData;
                    // 執行 post 動作
                    var result = client.UploadValues(url, nc);
                    html = Encoding.GetEncoding("UTF-8").GetString(result);

                    if (html.IndexOf(Nonce) == -1)
                    {
                        return RedirectToAction("Index", "home");
                    }

                    VID.IsConfirmed = true;
                    VID.AvailableDate = DateTime.Now.AddYears(1);
                    VID.ModifyDate = DateTime.Now;
                    VID.ModifyDateIP = ipAddress;

                    DBObj.Entry(VID).State = EntityState.Modified;

                    var ID = DBObj.AspNetUsers.Where(x => x.UserName == User.Identity.Name).FirstOrDefault();
                    ID.VerifyType1 = true;
                    DBObj.Entry(ID).State = EntityState.Modified;


                    string Subject = string.Empty;
                    string SerialNumber = string.Empty;
                    int iCN = 0;
                    int iC = 0;
                    int iCNtoC = 0;

                    foreach (var s in html.Split('\n'))
                    {
                        if (s.IndexOf("Subject:") > -1)
                        {
                            iCN = s.IndexOf("CN=") + 3;
                            iC = s.IndexOf("C=");
                            iCNtoC = iC - iCN;
                            if (iCNtoC > 0)
                                Subject = s.Substring(iCN, iCNtoC).TrimEnd().TrimEnd(',');
                        }
                        if (s.IndexOf("Card Number:") > -1)
                        {
                            string[] CN = s.Split(':');

                            if (CN.Length > 1)
                                SerialNumber = CN[1].Replace("<br/>", "");
                        }
                    }

                    MOICASN mSN = DBObj.MOICASN.Where(x => x.SN == SerialNumber).FirstOrDefault();

                    if ((mSN != null) || string.IsNullOrEmpty(SerialNumber))
                    {
                        return RedirectToAction("Index", "home");
                    }
                    mSN = new MOICASN();
                    mSN.no = Guid.NewGuid();
                    mSN.SN = SerialNumber;
                    DBObj.MOICASN.Add(mSN);

                    string HMACSHA256 = SHA256Hash($"{Subject}|{digitalSignature}");
                    MOICASHA256 mSHA = DBObj.MOICASHA256.Where(x => x.HMACSHA256 == HMACSHA256).FirstOrDefault();

                    if ((mSHA != null))
                    {
                        return RedirectToAction("Index", "home");
                    }
                    mSHA = new MOICASHA256();
                    mSHA.no = Guid.NewGuid();
                    mSHA.HMACSHA256 = HMACSHA256;
                    DBObj.MOICASHA256.Add(mSHA);

                    DBObj.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return RedirectToAction("Index", "home");
        }

        private static string SHA256Hash(string text)
        {
            UnicodeEncoding UE = new UnicodeEncoding();
            byte[] hashValue;
            byte[] message = UE.GetBytes(text);

            SHA256Managed hashString = new SHA256Managed();

            StringBuilder builder = new StringBuilder();
            hashValue = hashString.ComputeHash(message);
            foreach (byte x in hashValue)
            {
                builder.Append(x.ToString("X2"));
            }
            return builder.ToString();
        }


        #endregion 驗證信相關：自然人


    }
}