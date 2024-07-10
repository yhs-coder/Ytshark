#include <stdio.h>

#include "mail.h"

int main() {
    std::string from = "15360969181@163.com";
    std::string password = "YIQGLSLBJEISXEHS";
    // std::string to = "yhs_mail@126.com";
    std::string to = "2807580004@qq.com";
    // std::string to = "13822054195@163.com";
    // std::string to = "c.j.r277246@qq.com";
    // std::string subject = "略略略";
    std::string subject = "加密邮件";
    // std::string message = "听说收到这封信的女孩子，生活开心又幸运";
    std::string message = "测试使用加密端口发送";
    SmtpBase* base;
    // SmtpEmail mail("smtp.163.com", "25");
    // base = &mail;
    // int ret = base->send_email(from, password, to, subject, message);
    // if (ret != 0) {
    //     base->get_last_error();
    // }
    // c.j.r277246@qq.com
    SslSmtpEmail ssl_mail("smtp.163.com", "465");
    base = &ssl_mail;
    int ret = base->send_email(from, password, to, subject, message);
    if (ret != 0) {
        base->get_last_error();
    }
    return 0;
}