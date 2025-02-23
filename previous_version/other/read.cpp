#include <mysql.h>

#include <iostream>
#include <string>

class SecurityEventStorage {
private:
    MYSQL* _con;  // MySQL连接对象

    // 私有构造函数，初始化时建立数据库连接
    SecurityEventStorage(const std::string& db, const std::string& user,
                         const std::string& password, const std::string& host,
                         unsigned int port) {
        con = mysql_init(nullptr);

        if (_con == nullptr) {
            std::cerr << "mysql_init() failed" << std::endl;
            return;
        }

        if (!mysql_real_connect(_con, host.c_str(), user.c_str(), password.c_str(),
                                db.c_str(), port, nullptr, 0)) {
            std::cerr << "mysql_real_connect() failed: " << mysql_error(_con) << std::endl;
            mysql_close(_con);
            _con = nullptr;
        }
    }

public:
    // 获取类实例的静态方法，实现单例模式
    static SecurityEventStorage& get_instance(const std::string& db,
                                              const std::string& user,
                                              const std::string& password,
                                              const std::string& host,
                                              unsigned int port) {
        static SecurityEventStorage instance(db, user, password, host, port);
        return instance;
    }
    // 插入安全事件到数据库的方法
    bool insertEvent(const std::string& event, const std::string& src_ip,
                     const std::string& src_port, const std::string& dest_port,
                     const std::string& attack_type) {
        if (_con == nullptr) {
            std::cerr << "Database connection is not established." << std::endl;
            return false;
        }
        std::string query =
            "INSERT INTO security_events (event, src_ip, src_port, dest_port, attack_type) "
            "VALUES ('" +
            event + "', '" + src_ip + "', '" + src_port + "', '" + dest_port + "', '" + attack_type + "')";

        if (mysql_query(_con, query.c_str())) {
            std::cerr << "mysql_query() failed: " << mysql_error(con) << std::endl;
            return false;
        }
        return true;
    }

    // 防止拷贝和赋值操作，确保单例模式
    SecurityEventStorage(const SecurityEventStorage&) = delete;
    SecurityEventStorage& operator=(const SecurityEventStorage&) = delete;

    // 析构函数，关闭数据库连接
    ~SecurityEventStorage() {
        if (_con != nullptr) {
            mysql_close(con);
        }
    }
};

// 主函数，程序入口点
int main() {
    // 数据库连接参数
    std::string db = "your_db";
    std::string user = "your_user";
    std::string password = "your_pass";
    std::string host = "localhost";
    unsigned int port = 3306;

    // 获取SecurityEventStorage类的单例对象
    SecurityEventStorage& storage = SecurityEventStorage::get_instance(db, user, password, host, port);

    // 插入一个安全事件，检查返回值确定是否成功
    if (!storage.insertEvent("SQL Injection Attempt", "192.168.1.1", "54321", "80", "SQL Injection")) {
        return -1;  // 如果插入失败，退出程序
    }

    return 0;  // 插入成功，正常退出程序
}