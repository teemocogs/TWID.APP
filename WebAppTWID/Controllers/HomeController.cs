using DBHelper;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace WebAppTWID.Controllers
{
    public class HomeController : Controller
    {
        TWIDAPPEntities DBObj = new TWIDAPPEntities();

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "社群是否可以接受一個實驗性的服務？";

            return View();
        }

        public ActionResult Contact()
        {
            return View();
        }


    }
}