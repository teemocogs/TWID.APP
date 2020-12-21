using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WebAppTWID.Startup))]
namespace WebAppTWID
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
