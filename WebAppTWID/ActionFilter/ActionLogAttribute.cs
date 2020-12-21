using DBHelper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebAppTWID.ActionFilter
{
    public class ActionLogAttribute : ActionFilterAttribute
    {
        public string Description { get; set; }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (filterContext.HttpContext.User != null)
            {
                using (DBHelper.TWIDAPPEntities db = new DBHelper.TWIDAPPEntities())
                {
                    string desc = Description;
                    if (filterContext.ActionParameters.Count > 0)
                        desc = string.Format(Description, filterContext.ActionParameters.Values.ToArray());

                    ActionLog log = new ActionLog()
                    {
                        UserName = filterContext.HttpContext.User.Identity.Name ?? "",
                        Action = filterContext.RouteData.Values["controller"] + "." + filterContext.RouteData.Values["action"],
                        ClientIP = filterContext.HttpContext.Request.UserHostAddress,
                        Description = desc,
                        CreateTime = DateTime.Now
                    };


                    try
                    {
                        db.ActionLog.Add(log);
                        db.SaveChanges();
                    }
                    catch (System.Data.Entity.Validation.DbEntityValidationException dbEx)
                    {
                        var errors = new List<string>();
                        foreach (var entityError in dbEx.EntityValidationErrors)
                        {
                            errors.AddRange(entityError.ValidationErrors.Select(e2 => string.Join("Validation Error :: ", e2.PropertyName, " : ", e2.ErrorMessage)));
                        }
                        var error = string.Join("\r\n", errors);
                        var betterException = new Exception(error, dbEx);
                        Elmah.ErrorSignal.FromCurrentContext().Raise(betterException);
                    }
                }
            }
        }


    }
}
