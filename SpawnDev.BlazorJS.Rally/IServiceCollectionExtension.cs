using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// Adds extension methods to IServiceCollection
    /// </summary>
    public static class IServiceCollectionExtension
    {
        /// <summary>
        /// Adds DeviceIdentityService and RallyService
        /// </summary>
        /// <param name="_this"></param>
        /// <param name="configureCallback"></param>
        /// <returns></returns>
        public static IServiceCollection AddRallySingleton(this IServiceCollection _this, Action<RallyService>? configureCallback = null)
        {
            _this.TryAddSingleton<DeviceIdentityService>();
            _this.TryAddSingleton<RallyService>(sp =>
            {
                var RallyService = ActivatorUtilities.CreateInstance<RallyService>(sp);
                configureCallback?.Invoke(RallyService);
                return RallyService;
            });
            return _this;
        }
        /// <summary>
        /// Adds DeviceIdentityService and RallyService
        /// </summary>
        /// <param name="_this"></param>
        /// <param name="configureCallback"></param>
        /// <returns></returns>
        public static IServiceCollection AddRallyScoped(this IServiceCollection _this, Action<RallyService>? configureCallback = null)
        {
            _this.TryAddScoped<DeviceIdentityService>();
            _this.TryAddScoped<RallyService>(sp =>
            {
                var RallyService = ActivatorUtilities.CreateInstance<RallyService>(sp);
                configureCallback?.Invoke(RallyService);
                return RallyService;
            });
            return _this;
        }
    }
}
