Nacos 打包与加密配置使用指南
一、Nacos 打包命令
1. 快速打包（跳过测试 / 检查，提升打包速度）
   mvn -Dmaven.test.skip=true -Dcheckstyle.skip=true -Dpmd.skip=true -Drat.skip=true -Prelease-nacos clean install
2. 产物获取路径
   打包完成后，Nacos 可运行产物存放路径：
   /nacos-source/distribution/target
   二、Nacos 加密配置使用（数据库密码加密）
1. 核心前提
   加密功能依赖 jasypt.encryptor.password 配置项（必填加密密钥），密钥需自定义且严格保密；
   加密后的密文必须包裹在 ENC(密文) 格式中，否则 Nacos 无法识别解密。
2. 加密配置示例（application.properties）
   properties
# 数据库连接配置（加密后）
db.url.0=jdbc:mysql://127.0.0.1:3306/szr-config?characterEncoding=utf8&connectTimeout=1000&socketTimeout=3000&autoReconnect=true&useUnicode=true&useSSL=false&serverTimezone=Asia/Shanghai
db.user.0=ENC(xYnPVbQ/RpDDA5ftj22oZc5/k4V+db+6i3O+pK/2AWoM8pZdns1Fk+ABK6zD52Pn)
db.password.0=ENC(H5CXMys1NXTP3t4gTqj/RQnIwj5EBrxNmhrfWXIBLoEZb3Max9TJl833mMN1cWQL)

# 加密密钥（必填，建议定期更换）
jasypt.encryptor.password=nacos@jasypt#2026!ChangeIt
3. 加密工具类（生成密文）
   Nacos 内置加密工具类，可用于生成数据库账号 / 密码的密文：

   sys/src/main/java/com/alibaba/nacos/sys/utils/JasyptEncryptorMain.java
   使用方式（示例）
   编译该工具类后，执行 main 方法；
   输入加密密钥（与 jasypt.encryptor.password 一致）和需要加密的明文（如数据库密码）；
   复制生成的密文，包裹 ENC() 后填入配置文件。
   三、注意事项
   加密密钥 jasypt.encryptor.password 切勿泄露，建议通过启动参数传入（而非直接写在配置文件）：
   bash
   运行
