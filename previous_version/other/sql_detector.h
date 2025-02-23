#ifndef __SQL_INJECTION_H__
#define __SQL_INJECTION_H__
#include <iostream>
#include <memory>
#include <regex>
#include <vector>

#include "mail.h"

struct AlertMail {
    AlertMail()
        : from("15360969181@163.com"), password("YIQGLSLBJEISXEHS"), to("yhs_mail@126.com"), subject("服务器警告！") {
        message = "";
    }
    std::string from;      // 发送者邮箱
    std::string password;  // 授权码
    std::string to;        // 接收者邮箱
    std::string subject;   // 邮件标题
    std::string message;   // 邮件内容
};

// SQL注入检测接口
class SqlInjection {
public:
    virtual ~SqlInjection() = default;
    virtual bool detect(const std::string& data) const = 0;
    virtual void send_alert() = 0;
};

// SQL注入安全检测规则
class SqlInjectionRule : public SqlInjection {
private:
    std::regex _injection_pattern;
    std::unique_ptr<SmtpBase> _base;

public:
    SqlInjectionRule()
        : _injection_pattern(
              "(?:\\bUNION\\b|\\bSELECT\\b|\\bWHERE\\b|\\bORDER BY\\b|\\bAND\\b|\\bOR\\b)|"
              "(?:\\%7C%7C|\\%26%26|\\%23|\\%2D%2D|\\%2D\\+\\+)|"
              "(--|#|--+|#+)|"  // 注释符号
              "(?:\\bUPDATEXML\\(|\\bEXTRACT\\(|\\bCONCAT\\(|\\bGROUP_CONCAT\\()|"
              "(\\bIF\\(|\\bDATABASE\\(|\\bUSER\\(|\\bSYSTEM_USER\\))",
              std::regex_constants::icase) {}

    bool detect(const std::string& data) const override {
        // return std::regex_search(data, _injection_pattern, std::regex_constants::match_flag_type(std::regex_constants::icase));
        return std::regex_search(data, _injection_pattern);
        // std::smatch result;
        // bool flag = std::regex_search(data, result, _injection_pattern);
        // std::cout << "flag: " << flag << std::endl;
        // for (int i = 0; i < result.size(); i++)
        //     std::cout << result.str() << "\t";
        // return flag;
    }
    void send_alert() {
        AlertMail test_mail;
        test_mail.message = "服务器遭受sql攻击！！！请尽快处理！！！";
        _base = std::make_unique<SslSmtpEmail>("smtp.163.com", "465");
        _base->send_email(test_mail.from, test_mail.password, test_mail.to, test_mail.subject, test_mail.message);
        sleep(10);
        exit(-1);
    }
};

// SQL注入检测器
class SqlInjectionDetector {
private:
    std::unique_ptr<SqlInjectionRule> _rule;
    std::unique_ptr<SmtpBase> _base;

public:
    SqlInjectionDetector()
        : _rule(std::make_unique<SqlInjectionRule>()), _base() {}

    void detect_sql_injection(const std::string& data) {
        if (_rule->detect(data)) {
            std::cout << "Potential SQL Injection Detected !" << std::endl;
            _rule->send_alert();
            //_base = std::make_unique<SslSmtpEmail>("smtp.163.com", "465");
            // _rule->send_alert();
            // _base->send_email(_rule->mail.from, _rule->mail.password, _rule->mail.to, _rule->mail.subject, _rule->mail.message);
            // sleep(10);
            // exit(-1);
        }
    }
};
#endif