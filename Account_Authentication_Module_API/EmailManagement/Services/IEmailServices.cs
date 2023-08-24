namespace Account_Authentication_Module_API.EmailManagement.Services
{
    public interface IEmailServices
    {
        void SendEmail(Message message, string title);
    }
}
