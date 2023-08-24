using MailKit.Net.Smtp;
using MimeKit;

namespace Account_Authentication_Module_API.EmailManagement.Services
{
    public class EmailServices : IEmailServices
    {
        private readonly EmailConfigration _emailConfigration;

        public EmailServices(EmailConfigration emailConfigration) => _emailConfigration = emailConfigration;
        public void SendEmail(Message message, string title)
        {
            var emailMessage = CreateEmailMessage(message, title);
            Send(emailMessage);
        }

        private MimeMessage CreateEmailMessage(Message message, string title)
        {
            MimeMessage emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress(title, _emailConfigration.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = message.Content };
            return emailMessage;
        }

        private void Send(MimeMessage message)
        {
            using var client = new SmtpClient();
            try
            {
                client.Connect(_emailConfigration.SmtpServer, _emailConfigration.Port);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_emailConfigration.Username, _emailConfigration.Password);
                client.Send(message);
            }
            catch
            {
                throw;
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
            }
        }
    }
}
