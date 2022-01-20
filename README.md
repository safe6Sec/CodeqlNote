# CodeqlNote
记录学习Codeql的笔记，国内资料真的挺少。摘抄各种大佬文章随便记的，比较乱,抽空整理。



**该笔记还在整理中，对codeql感兴趣的师傅推荐直接看文末我收集的一些文章！！！**







# codeql

1. 这东西本质就是写各种过滤条件、各种数据流跟踪，给我的感觉就是在写面向对象的sql一样，所以在学习之前最好掌握面向对象思想，一门面向对象的编程语言，sql语句编写。

2. codeql工作原理主要是，利用分析引擎分析代码之间的关系，生成一个代码数据库。然后我们直接写ql就可以进行各种查询，如找某个方法或者某个类，找方法引用，跟踪某个参数的传递等等用法。
3. codeql里面的谓词其实就是把各种过滤条件封装成方法。
4. java里面是万物皆对象，我觉得codeql是万物皆表达式。
5. lgtm除了用来下数据库还可以用来搜索ql
6. 这个目录/ql/java/ql/src/Security放着一些官方的规则(java)，可直接用。
7. 这个/ql/java/ql/src/experimental/Security目录下，一些还在实验中的规则(java)。



# 相关下载
文档： https://codeql.github.com/docs/codeql-cli/    
二进制：https://github.com/github/codeql-cli-binaries     
现成项目：https://github.com/github/vscode-codeql-starter  

数据库下载，在线查询，规则搜索：https://lgtm.com/


# 生成数据库

**ps：生成数据库之前，先保证被分析程序可以正常跑起来。**    
第一步、创建索引代码数据库。得有数据库才能开始查询。

```
codeql database create <database> --language=<language-identifier>
```
支持的语言及language对应关系如下


| Language              | Identity   |
| --------------------- | ---------- |
| C/C++                 | cpp        |
| C#                    | csharp     |
| Go                    | go         |
| Java                  | java       |
| javascript/Typescript | javascript |
| Python                | python     |
| Ruby                  | Ruby       |



1、生成代码扫描数据库(java)

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



# 基础查询



### 过滤 Method

#### 根据Method name查询

```java
import java

from Method method
where method.hasName("toObject")
select method
```

把这个方法的`class` `name`也查出来

```java
import java

from Method method
where method.hasName("toObject")
select method, method.getDeclaringType()
```

#### 根据Method name 和 interface name 查询

比如我想查询`ContentTypeHandler` 的所有子类`toObject`方法

```java
import java

from Method method
where method.hasName("toObject") and method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler")
select method
```

#### Call和Callable
Callable表示可调用的方法或构造器的集合。   

Call表示调用Callable的这个过程（方法调用，构造器调用等等）    




### MethodAccess
过滤 方法调用   

一般是先查`method`，与`MethodAccess.getMethod()` 进行比较。

比如查`ContentTypeHandler` 的 `toObject()` 方法的调用。

```java
import java

from MethodAccess call, Method method
where method.hasName("toObject") and method.getDeclaringType().getASupertype().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") and call.getMethod() = method
select call
```

上面这种查询方式不行，只能查到`JsonLibHandler` 这样显式定义的。

怎么改进呢？

也可以使用`getAnAncestor()` 或者`getASupertype()*`

```java
import java

from MethodAccess call, Method method
where method.hasName("toObject") and method.getDeclaringType().getAnAncestor().hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler") and call.getMethod() = method
select call
```
### 过滤构造方法
new File的参数为我们的sink点，所以构造ql
```
class FileContruct extends ClassInstanceExpr{
    FileContruct(){
        this.getConstructor().getDeclaringType*().hasQualifiedName("java.io", "File")
    }
}
```


# codeql java规则目录


一些官方规则，可直接用。
```
-java

--ql

---src

----Security(正式运行的规则)

----experimental(还在实验中的规则)

---lib

----semmle

-----code

------java(这个下面都是框架相关的内容)
```



# 数据流跟踪

Local Data Flow分析SPEL

本地数据流
本地数据流是单个方法(一旦变量跳出该方法即为数据流断开)或可调用对象中的数据流。本地数据流通常比全局数据流更容易、更快、更精确。

```
import java
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.dataflow.TaintTracking
from Call call,Callable parseExpression,SpringRequestMappingMethod route
where
    call.getCallee() = parseExpression and 
    parseExpression.getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
    parseExpression.hasName("parseExpression") and 
   TaintTracking::localTaint(DataFlow::parameterNode(route.getARequestParameter()),DataFlow::exprNode(call.getArgument(0))) 
select route.getARequestParameter(),call
```



全局数据流分析要继承`DataFlow::Configuration` 这个类，然后重载`isSource` 和`isSink` 方法

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

# 数据流断的原因
- 外部的方法，因为没有编译到数据库中，这个是最常见的，基本上市面上的扫描器都存在这个问题，说起来复杂，原因大概是因为构建数据流会随着扫描AST的复杂程度递增导致数据库过大，最后大家在时间和易用性上做了平衡，选择了编译直接依赖的内容进行查询，从而导致这个问题的存在。

- 复杂的字符串拼接,例如append，一些其他的字符串赋值，这个一般出场都是空的，要自己去搞，当然会有一些类似fortify的自带了部分场景的连接，不过有的时候要自己去排查

- 强制类型转换

- 动态特性，例如class.ForName。codeQL有很好的反射类支持这个，对比fortify，你就知道什么是好，什么是不好。Fortify的类太简单了，你去看看codeQL官方手册里的类，简直对比下来就是指数级的，哪怕你看一眼 soot，都比fortify好。


## isAddtionalStep技巧
isAddtionalStep使用就用最简单的二分法来定位，先前移sink，然后检测出来的话就移动到后面，直到找到哪个断开的地方。
冷知识：数据流是可以混用的，例如我们的sink又可以是一个hasFlow表达式   

上面两点来自xsser师傅文章


# 污点跟踪



全局污点跟踪分析要继承`TaintTracking::Configuration` 这个类，然后重载`isSource` 和`isSink` 方法

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

```
codeql database analyze source_database_name qllib/java/ql/src/codeql-suites/java-security-extended.qls --format=csv --output=java-results.csv
```

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






# Chrome书签
自己学习codeql 看过的一些文章

- [CodeQL从入门到放弃 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/283795.html)
- [使用codeql挖掘fastjson利用链 - 先知社区](https://xz.aliyun.com/t/7482)
- [CodeQL documentation](https://codeql.github.com/docs/)
- https://www.4hou.com/search-post?page=4&keywords=codeql
- [代码分析平台CodeQL学习手记（十七） - 嘶吼 RoarTalk – 回归最本质的信息安全,互联网安全新媒体,4hou.com](https://www.4hou.com/posts/o6wX)
- [Query console - LGTM](https://lgtm.com/query/lang:java/)
- [使用codeql 挖掘 ofcms - 安全客，安全资讯平台](https://www.anquanke.com/post/id/203674)
- [haby0/mark: notes](https://github.com/haby0/mark)
- [codeql学习——污点分析 - 先知社区](https://xz.aliyun.com/t/7789)
- [codeql学习笔记 - 知乎](https://zhuanlan.zhihu.com/p/354275826)
- [github/vscode-codeql-starter: Starter workspace to use with the CodeQL extension for Visual Studio Code.](https://github.com/github/vscode-codeql-starter)
- [codeql学习——污点分析 - 先知社区](https://xz.aliyun.com/t/7789#toc-0)
- [CodeQL for Golang Practise(3)](http://f4bb1t.com/post/2020/12/16/codeql-for-golang-practise3/)
- [CodeQL静态代码扫描之实现关联接口、入参、和危险方法并自动化构造payload及抽象类探究](https://mp.weixin.qq.com/s/Rqo12z9mapwlj6wGHZ1zZA)
- [Codeql分析Vulnerability-GoApp - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/253491.html)
- [codeql反序列化分析](https://github.com/githubsatelliteworkshops/codeql)
- [[原创\]58集团白盒代码审计系统建设实践2：深入理解SAST-业务安全-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-266995.htm#msg_header_h1_4)
- [楼兰#CodeQL](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzg4ODU4ODYzOQ==&action=getalbum&album_id=1970201600723910658&scene=173&from_msgid=2247484983&from_itemidx=1&count=3&nolastread=1#wechat_redirect)
- [CodeQL学习笔记 | Gamous'Site](http://blog.gamous.cn/post/codeql/)
- [language:go - Search - LGTM](https://lgtm.com/search?q=language%3Ago&t=rules)
- [CodeQL 和代码扫描简介 - GeekMasher 的博客](https://geekmasher.dev/posts/sast/codeql-introduction)
- [CVE-2018-11776: 如何使用CodeQL发现5个 Apache Struts RCEs](https://mp.weixin.qq.com/s/LmOFGAhqAKiO8VDQW4vvLg)
- [CodeQL静态代码扫描规则编写之RemoteFlowSource](https://mp.weixin.qq.com/s/jVZ3Op8FYBmiFAV3p0li3w)
- [CodeQL静态代码扫描之抽象类探究](https://mp.weixin.qq.com/s/KQso2nvWx737smunUHwXag)
- [Codeql规则编写入门](https://mp.weixin.qq.com/s/sAUSgRAohFlmzwSkkWjp9Q)
- [About LGTM - Help - LGTM](https://lgtm.com/help/lgtm/about-lgtm)
- [LGTM help & documentation](https://help.semmle.com/home/help/home.html)
- [Capture the flag | GitHub Security Lab](https://securitylab.github.com/ctf/)
- [CodeQL笔记 | LFYSec](https://lfysec.top/2020/06/03/CodeQL笔记/)
- [CodeQL学习——CodeQl数据流分析 - bamb00 - 博客园](https://www.cnblogs.com/goodhacker/p/13583650.html)
- [分类: codeql - 食兔人的博客](https://blog.ycdxsb.cn/categories/research/codeql/)
- [CodeQL - butter-fly](https://yourbutterfly.github.io/note-site/module/semmle-ql/codeql/)
- [表达式](https://www.4hou.com/posts/lM11)
- [mark/CodeQL-数据流在Java中的使用.md at master · haby0/mark](https://github.com/haby0/mark/blob/master/articles/2021/CodeQL-数据流在Java中的使用.md)
- [github/securitylab: Resources related to GitHub Security Lab](https://github.com/github/securitylab)
- [CodeQL从0到1（内附Shiro检测demo） - 安全客，安全资讯平台](https://www.anquanke.com/post/id/255721)
- [codeql挖掘React应用的XSS实践 | Image's blog](https://hexo.imagemlt.xyz/post/javascript-codeql-learning/)
- [SummerSec/learning-codeql: CodeQL Java 全网最全的中文学习资料](https://github.com/SummerSec/learning-codeql)
- [CodeQL query help for Go — CodeQL query help documentation](https://codeql.github.com/codeql-query-help/go/#)
- [codeql使用指南_zzzzfeng的博客-CSDN博客_codeql使用](https://blog.csdn.net/haoren_xhf/article/details/115064677)
- [Apache Dubbo：条条大路通RCE | GitHub 安全实验室](https://securitylab.github.com/research/apache-dubbo/)
- [如何用CodeQL数据流复现 apache kylin命令执行漏洞 - 先知社区](https://xz.aliyun.com/t/8240)
- [如何利用CodeQL挖掘CVE-2020-10199 - 安全客，安全资讯平台](https://www.anquanke.com/post/id/202987)
- [南大软件分析课程](https://space.bilibili.com/2919428?share_medium=iphone&share_plat=ios&share_session_id=6851D997-0AC6-4C67-B858-BD1E6258C548&share_source=COPY&share_tag=s_i&timestamp=1639480132&unique_k=8wQBAkV)
- [各种语言危险sink](https://github.com/haby0/sec-note)
- [利用CodeQL分析并挖掘Log4j漏洞](https://mp.weixin.qq.com/s/JYco8DysQNszMohH6zJEGw)
- [几张图结构看懂CodeQL数据流](https://mp.weixin.qq.com/s/3mlRedFwPz31Rwe7VDBAuA)
- [Firebasky师傅的笔记](https://github.com/Firebasky/CodeqlLearn)
- [凡人老哥codeql学习资料](https://github.com/SummerSec/learning-codeql)
- [fynch3r师傅的笔记](https://fynch3r.github.io/tags/CodeQL/)
- [CodeQL 目录、框架和一些有趣的东西](https://mp.weixin.qq.com/s/zSI157qJXYivSvyxHzXALQ)







