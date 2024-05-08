#include <iostream>
#include <regex>
#include <string>

class XSSInjectionRule {
private:
    std::regex xssPattern;

public:
    XSSInjectionRule()
        : xssPattern(
              // 检测<script>标签,包括url编码 "(?:<script[^>]*>.*?</script>)|"
              "(?:(%3C|<)script(%3E|>).*(%3C|<)(%2F|/)(script)(%3E|>))|"
              // 检测内联事件处理器，如 onclick、onerror 等
              "(?:<[^>]*(\\s*(on[a-z]+=(\"[^\"]*\"|'[^']*'|[^'\">\\s]+)))+>)|"
              // 检测url编码的内联事件处理器
              "(?:%3C[^%3E]*(%20*(on[a-z]+=(%22[^%22]*%22|%27[^%27]*%27|[^%27%22%3E%20]+)))+%20*%3E)|"
              // 检测伪协议，javascript伪协议: data伪协议:
              "(?:(javascript|data)[:\"'][^:<>\"']*)|"
              // 检测url编码的伪协议
              "(?:(javascript|data):[^:<>%22%27]*)"
              // 检测base64编码的数据URI
              "(?:base64,\\s*[a-zA-Z0-9+/]+(=|==)*)|"
              // 检测HTML实体，检测编码绕过情况
              "(?:&#[xXu]?[0-9a-fA-F]+;)|",
              // 检测混合大小写的javascript
              std::regex_constants::icase | std::regex_constants::ECMAScript) {}

    bool detect(const std::string& data) const {
        return std::regex_search(data, xssPattern);
    }
};

class XSSInjectionDetector {
private:
    XSSInjectionRule rule;

public:
    bool detectXSSInjection(const std::string& data) {
        return rule.detect(data);
    }
};