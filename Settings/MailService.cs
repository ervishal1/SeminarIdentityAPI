using Identity1.Settings.MailSetting;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Identity1.Settings
{
    public interface IMailService
    {
        Task SendEmailAsync(MailRequest mailRequest);
        string readFile();
    }

    public class MailService : IMailService
    {
        private readonly MailSettings _mailSettings;
        private ILogger _logger;
        public MailService(IOptions<MailSettings> mailSettings)
        {
            _mailSettings = mailSettings.Value;
           
        }

        public async Task SendEmailAsync(MailRequest mailRequest)
        {
            try
            {
            var email = new MimeMessage();
            email.Sender = MailboxAddress.Parse(_mailSettings.Mail);
            email.To.Add(MailboxAddress.Parse(mailRequest.ToEmail));
            email.Subject = mailRequest.Subject;
            var builder = new BodyBuilder();
            if (mailRequest.Attachments != null)
            {
                byte[] fileBytes;
                foreach (var file in mailRequest.Attachments)
                {
                    if (file.Length > 0)
                    {
                        using (var ms = new MemoryStream())
                        {
                            file.CopyTo(ms);
                            fileBytes = ms.ToArray();
                        }
                        builder.Attachments.Add(file.FileName, fileBytes, ContentType.Parse(file.ContentType));
                    }
                }
            }
            builder.HtmlBody = mailRequest.Body;
            email.Body = builder.ToMessageBody();
            using var smtp = new SmtpClient();
            smtp.Connect(_mailSettings.Host, _mailSettings.Port, SecureSocketOptions.StartTls);
            smtp.Authenticate(_mailSettings.Mail, _mailSettings.Password);
            await smtp.SendAsync(email);
            smtp.Disconnect(true);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public string readFile()
        {
            string line = string.Empty;
            FileStream fileStream = new FileStream(Path.Combine("template","temp.txt"), FileMode.Open);
            using (StreamReader reader = new StreamReader(fileStream))
            {
                line = reader.ReadToEnd();
            }
            return line;
        }
    }
}
