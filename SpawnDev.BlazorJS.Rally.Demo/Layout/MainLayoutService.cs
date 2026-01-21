using System.Reflection;

namespace SpawnDev.BlazorJS.Rally.Demo.Layout
{
    public class MainLayoutService
    {
        public string DefaultTitle { get; set; } = AppDomain.CurrentDomain.FriendlyName;
        public string Title
        {
            get => string.IsNullOrEmpty(_Title) ? DefaultTitle : _Title;
            set
            {
                if (_Title == value) return;
                _Title = value;
                OnTitleChanged?.Invoke();
            }
        }
        string _Title { get; set; } = "";
        public delegate void AfterRender(MainLayout mainLayout, bool firstRender);
        public event AfterRender OnAfterRender = default!;
        public event Action OnTitleChanged = default!;
        public void TriggerOnAfterRender(MainLayout mainLayout, bool firstRender)
        {
            OnAfterRender?.Invoke(mainLayout, firstRender);
        }
    }
}
