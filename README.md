# CodeqlNote
记录学习Codeql的笔记，国内资料真的挺少。随便记的，比较乱。学完之后再整理







# codeql

这东西本质就是写各种过滤条件、各种数据流跟踪，就和写sql语句一样玩。里面的谓词就是把各种过滤条件封装成方法。



# 生成数据库

创建索引代码数据库

```
codeql database create <database> --language=<language-identifier>
```
language对应关系如下


| Language              | Identity   |
| --------------------- | ---------- |
| C/C++                 | cpp        |
| C#                    | csharp     |
| Go                    | go         |
| Java                  | java       |
| javascript/Typescript | javascript |
| Python                | python     |



1、生成代码扫描数据库

```
codeql database create D:\codeqldb/javasec --language=java  --command="mvn clean install --file pom.xml -Dmaven.test.skip=true" --source-root=./javasec
```

注：source-root 为源码路径，默认为当前目录,可不指定

一些常用命令

```
 跳过测试，构建
 --command="mvn clean install --file pom.xml -Dmaven.test.skip=true"
 无论项目结果如何,构建从不失败
 --command="mvn -fn clean install --file pom.xml -Dmaven.test.skip=true"
```





包含xml文件https://github.com/github/codeql/issues/3887



```
codeql database init --source-root=<src> --language java <db>
codeql database trace-command --working-dir=<src> <db> <java command>
codeql database index-files --language xml --include-extension .xml --working-dir=<src> <db>
codeql database finalize <db>
```

将上面的命令拆分为如下4条命令，在index-files中将xml文件添加到CodeQL的数据库中CodeQL将XML文件包含到CodeQL数据库

第二种方案是在codeql-cli/java/tools/pre-finalize.cmd文件中插入--include "**/resources/**/*.xml"



2、更新数据库

```
codeql database upgrade database/javasec
```



参考：https://help.semmle.com/lgtm-enterprise/admin/help/prepare-database-upload.html



### 编译与非编译

对于编译型语言来说，需要在创建索引数据库的时候增加编译的功能，主要是针对java，对于非编译性的语言来说，直接扫描吧

对于go来说，可编译也可不编译



## 基础查询



### 过滤 Method

#### 根据Method name查询

```
import java

from Method method
where method.hasName("toObject")
select method
```

把这个方法的`class` `name`也查出来

```
import java

from Method method
where method.hasName("toObject")
select method, method.getDeclaringType()
```

#### 根据Method name 和 interface name 查询

比如我想查询`ContentTypeHandler` 的所有子类`toObject`方法

```
import java

from Method method
where method.hasName("toObject") and method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler")
select method
```



过滤 方法调用

### MethodAccess

一般是先查`method`，与`MethodAccess.getMethod()` 进行比较。

比如查`ContentTypeHandler` 的 `toObject()` 方法的调用。

```
import java

from MethodAccess call, Method method
where method.hasName("toObject") and method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") and call.getMethod() = method
select call
```

上面这种查询方式不行，只能查到`JsonLibHandler` 这样显式定义的。

怎么改进呢？

也可以使用`getAnAncestor()` 或者`getASupertype()*`

```
import java

from MethodAccess call, Method method
where method.hasName("toObject") and method.getDeclaringType().getAnAncestor().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") and call.getMethod() = method
select call
```





# 数据流跟踪

数据流分析要继承`DataFlow::Configuration` 这个类，然后重载`isSource` 和`isSink` 方法



```
class MyConfig extends DataFlow::Configuration {
  MyConfig() { this = "Myconfig" }
  override predicate isSource(DataFlow::Node source) {
    ....
    
  }

    override predicate isSink(DataFlow::Node sink) {
    ....
    
  }
}
```



# 污点跟踪

污点跟踪分析要继承`TaintTracking::Configuration` 这个类，然后重载`isSource` 和`isSink` 方法

```
class VulConfig extends TaintTracking::Configuration {
VulConfig() { this = "myConfig" }

override predicate isSource(DataFlow::Node source) {

}

override predicate isSink(DataFlow::Node sink) {

}
}

from VulConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "source are"
```



# 白盒扫描

ql库集成了许多常见的安全漏洞，可以直接拿来扫描项目源码

https://codeql.github.com/codeql-query-help/java/



下面是写好的

 java
1、zip slip（zip解压覆盖任意文件）

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-022/ZipSlip.ql

2、命令注入

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-078/ExecUnescaped.ql

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-078/ExecTainted.ql

3、cookie安全

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-312/CleartextStorageCookie.ql

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-614/InsecureCookie.ql

4、XSS

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-079/XSS.ql

5、依赖漏洞

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-1104/MavenPomDependsOnBintray.ql

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-829/InsecureDependencyResolution.ql

6、反序列化

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql

7、http头注入

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-113/NettyResponseSplitting.ql

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-113/ResponseSplitting.ql

8、url跳转

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-601/UrlRedirect.ql

9、ldap注入

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-090/LdapInjection.ql

10、sql注入

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-089/SqlTainted.ql

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-089/SqlUnescaped.ql

11、file权限&目录注入

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-732/ReadingFromWorldWritableFile.ql

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-022/TaintedPath.ql

12、xml注入

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-611/XXE.ql

13、SSL校验

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-297/UnsafeHostnameVerification.ql

14、弱加密

https://github.com/github/codeql/java/ql/src/Security/CWE/CWE-327/BrokenCryptoAlgorithm.ql

15、随机数种子可预测

https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-335/PredictableSeed.ql


codeql analyze命令可以执行单个ql文件，目录下所有ql文件，和查询suite(.qls)

 

白盒扫描使用如下命令（执行所有漏洞类查询）

codeql database analyze source_database_name qllib/java/ql/src/codeql-suites/java-security-extended.qls --format=csv --output=java-results.csv

如果是自己写可用于analyze的必须按规范写，包含元数据@kind,如下这种

```
/**
 * @name Incomplete regular expression for hostnames
 * @description Matching a URL or hostname against a regular expression that contains an unescaped
 *              dot as part of the hostname might match more hostnames than expected.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.8
 * @precision high
 * @id go/incomplete-hostname-regexp
 * @tags correctness
 *       security
 *       external/cwe/cwe-20
 */
```













# 文章推荐



- https://github.com/SummerSec/learning-codeql
- https://www.anquanke.com/post/id/203674
- https://xz.aliyun.com/t/7482
- https://www.freebuf.com/articles/web/283795.html



