using System;
using System.Collections.Generic;
using System.Data.Entity.Validation;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace WebAppTWID
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }


        protected void Application_Error(object sender, EventArgs e)
        {
            ElmahEntityValidationException();
        }

        #region Elmah

        private void ElmahEntityValidationException()
        {
            var dbEntityValidationException = Server.GetLastError() as DbEntityValidationException;

            if (dbEntityValidationException != null)
            {
                var errors = new List<string>();
                foreach (var entityError in dbEntityValidationException.EntityValidationErrors)
                {
                    errors.AddRange(entityError.ValidationErrors.Select(e2 => string.Join("Validation Error :: ", e2.PropertyName, " : ", e2.ErrorMessage)));
                }
                var error = string.Join("\r\n", errors);
                var betterException = new Exception(error, dbEntityValidationException);

                Elmah.ErrorSignal.FromCurrentContext().Raise(betterException);
            }
        }
        // elmah : 自訂郵件的錯誤過瀘
        void ErrorMail_Filtering(object sender, Elmah.ExceptionFilterEventArgs e)
        {
            var exception = e.Exception.GetBaseException();
            if (e.Exception is HttpException)
            {
                var httpException = (HttpException)e.Exception;
                // 加入排除寄送 Email 的狀態與例外
                if (httpException != null && httpException.GetHttpCode() == 404)
                {
                    e.Dismiss();
                }
                if (HttpContext.Current.Request.UserAgent.Contains("bot"))
                {
                    e.Dismiss();
                }
            }
            if (exception is System.IO.FileNotFoundException ||
                    exception is HttpRequestValidationException ||
                    exception is HttpException)
            {
                e.Dismiss();
            }

        }
        // elmah : 自訂郵件標題
        void ErrorMail_Mailling(object sender, Elmah.ErrorMailEventArgs e)
        {
            var exception = e.Error.Exception;
            // 加入自訂主題與成員
            if (exception is NotImplementedException)
            {
                e.Mail.Priority = System.Net.Mail.MailPriority.High;
                e.Mail.Subject = "偷懶未實作 Action被執行了";
                //e.Mail.CC.Add("xxx@hotmmail.com");
            }
        }
        #endregion

    }
}
