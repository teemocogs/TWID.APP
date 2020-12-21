using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebAppTWID.Controllers
{
    public class ErrorController : Controller
    {
        // GET: Error
        public ActionResult Index()
        {
            return new EmptyResult();
        }

        public ActionResult Error()
        {
            return new EmptyResult();
        }

        public ActionResult NotFound()
        {
            return new EmptyResult();
        }
    }
}