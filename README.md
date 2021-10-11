# CodeqlNote
记录学习Codeql的笔记，国内资料真的挺少。







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



### Method

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







# 文章推荐



- https://github.com/SummerSec/learning-codeql
- https://www.anquanke.com/post/id/203674
- https://xz.aliyun.com/t/7482
- https://www.freebuf.com/articles/web/283795.html



