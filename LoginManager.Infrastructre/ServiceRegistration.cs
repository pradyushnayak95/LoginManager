using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LoginManager.Infrastructre
{
    public static class ServiceRegistration
    {
        public static void AddInfrastructureServices(this IServiceCollection services)
        {
            // Register all your infrastructure-related services
            //services.AddScoped<IYourRepository, YourRepository>();
            // Add other services as needed
        }
    }
}
