using DBHelper;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using PagedList;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebAppTWID.Controllers
{
    [Authorize]
    public class DeckController : Controller
    {
        TWIDAPPEntities DBObj = new TWIDAPPEntities();

        // GET: Deck
        [ActionFilter.ActionLog(Description = "我的認證表列")]
        public ActionResult Index()
        {
            var manager = HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            var user = manager.FindByName(User.Identity.Name);
            ViewBag.EmailConfirmed = user.EmailConfirmed;

            ViewBag.isPTTIDConfirmed = user.VerifyType0;
            ViewBag.isMOICAConfirmed = user.VerifyType1;

            return View();
        }

        [AllowAnonymous]
        public ActionResult Error()
        {
            //string xx = "";
            throw new NotImplementedException();
        }


        public ActionResult Users()
        {
            var Users = DBObj.AspNetUsers.OrderBy(s => s.Id);
            return View(Users.ToPagedList(1, 15));
        }

        public ActionResult List(int page = 1)
        {
            var Users = DBObj.AspNetUsers.OrderBy(s => s.Id);
            return View(Users.ToPagedList(page, 15));
        }
    }
}