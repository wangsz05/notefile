# 说明
此篇主要记录在Java 中使用js 的风险，以及使用sandbox来解决可能出现的rce问题。

# 1、ScriptEngine的使用
从JDK6开始，java就嵌入了对脚本的支持，这里的脚本指的是但非局限于JS这样的非java语言，当时使用的脚本执行引擎是基于Mozilla 的Rhino。该引擎的特性允许开发人员将 JavaScript 代码嵌入到 Java 中，甚至从嵌入的 JavaScript 中调用 Java。此外，它还提供了使用jrunscript从命令行运行 JavaScript 的能力。
**Java ScriptEngine优缺点：**
**优点**：可以执行完整的JS方法，并且获取返回值；在虚拟的Context中执行，无法调用系统操作和IO操作，非常安全；可以有多种优化方式，可以预编译，编译后可以复用，效率接近原生Java；所有实现ScriptEngine接口的语言都可以使用，并不仅限于JS，如Groovy，Ruby等语言都可以动态执行。
**缺点**：无法调用系统和IO操作 ，也不能使用相关js库，只能使用js的标准语法。更新：可以使用scriptengine.put()将Java原生Object传入Context，从而拓展实现调用系统和IO等操作。
## 1.1 JavaScript 引擎
从JDK 8开始，Nashorn取代Rhino成为Java的嵌入式JavaScript引擎。
Nashorn完全支持ECMAScript 5.1规范以及一些扩展。它使用基于JSR 292的新语言特性，其中包含在JDK 7中引入的invokedynamic，将JavaScript编译成Java字节码。
nashorn首先编译javascript代码为java字节码，然后运行在jvm上，底层也是使用invokedynamic命令来执行，所以运行速度很给力。
**Nashorn是一个纯编译的JavaScript引擎**。
它没有用Java实现的JavaScript解释器，而只有把JavaScript编译为Java字节码再交由JVM执行这一种流程，跟Rhino的编译流程类似。
```java 
[ JavaScript源码 ] -> ( 语法分析器 Parser ) -> [ 抽象语法树（AST） ir ] -> ( 编译优化 Compiler ) -> [ 优化后的AST + Java Class文件（包含Java字节码） ] -> JVM加载和执行生成的字节码 -> [ 运行结果 ]
```
只从JVM以上的层面看，Nashorn是一种单层的纯编译型JavaScript实现。所有JavaScript代码在首次实际执行前都会被编译为Java字节码交由JVM执行。（当然JVM自身可能是混合执行模式的，例如HotSpot VM与J9 VM。所以Nashorn在实际运行中可能需要一定预热才会达到最高速度）

验证过程如下：
下属通过代码的方式，验证当前Jdk1.8 使用的js引擎信息。
在代码中定义了默认的js引擎
 ScriptEngine engine = manager.getEngineByName("javascript");
通过运行该默认的引擎报错信息可以看到，实际上用的是nashorn。
![](https://img2022.cnblogs.com/blog/2738582/202205/2738582-20220514174014044-2132517164.png)
![image.png](http://moonsec.top/articlepic/7a17bb3d62bcd2d2c53e17b7cc3041ed.png)

## 1.2 java代码中使用 nashorn
下述为简单的nashron的使用过程
demo如下:
```java
  public static void main(String args[]) throws ScriptException, IOException, NoSuchMethodException {
        ScriptEngineManager manager = new ScriptEngineManager();
        // 得到javascript脚本引擎
        ScriptEngine engine = manager.getEngineByName("javascript");

        //一段JavaScript脚本语言代码
        String str ="var user={name:'夏洛',age:18,schools:['北京大学','清华大学']};";
        str +="print(user.name);"; //写出println(user.name); 会报错即多个ln会报错，不知道为啥？
        //用引擎执行脚本语言代码
        engine.eval(str);//eval() 获取返回值

        String scriptText = "function greet(name) { print('Hello, ' + name); } ";
            Object temp = engine.eval(scriptText);
            System.out.println(temp);

        //向script方法传入值
	//获取接口
        Invocable invocable = (Invocable) engine;
        invocable.invokeFunction("greet", "Alex");
    }
```
程序运行的结果如下：
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/5d8a1d6807890f57dbe794dfcd574769.png)
从程序的运行结果可以看出来，engine.eval(str) 方法，通过eval方法获取返回值;


PS： Java虚拟机支持脚本的意义在于实现函数式的编程，即脚本中最重要的便是方法。一些脚本引擎允许使用者单独调用脚本中的某个方法，支持此操作的脚本引擎可以通过实现javax.script.Invocable接口，支持顶层方法或者某对象中成员方法的调用。使用方法调用时最好先检查脚本引擎是否实现了Invocable接口，JavaSE中的JavaScript引擎已实现了Invocable接口。 

下个断点，跟踪下流程，看看engine.eval(str)到底干了啥：
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/b2010c7c337fdd663018becc7b61b9c9.png)
1、可以发现eval在前段部分是通过各类的compile方法来编译该js脚本。
2、然后CompilationPhase类中，调用transform方法中，调用 newFunctionNode = CompilationPhase.transformFunction(newFunctionNode, codegen);这款编译器的内容不懂，在网络上找到了一个大神相关的说明，具体可以参考：https://hllvm-group.iteye.com/group/topic/37596
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/4a569c7281839e5d3be975c5c6cb1ca4.png)
3、在IntDeque中pop出来对应的元素接口获得eval的结果。
## 1.3 function功能调用
通过实际的调试可知，在实际过程中，Java的eval只是对function初始化，并没有执行调用
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/8c5706fd0a4a26cd4335fed8ed1e5e74.png)
如果想向script中传入值，需要调用Invocable ，取得调用接口，并通过invokeFunction方法传入值。
Invocable 由脚本引擎实现的可选接口，其方法允许调用以前执行的脚本中的过程。

## 1.4 在JavaScript中调用Java的方法
在 JavaScript 中调用 Java 方法很简单。首先我们定义一个静态的 Java 方法：
```Java
static String fun1(String name) {
    System.out.format("Hi there from Java, %s", name);
    return "greetings from java";
}

```
JavaScript 可通过 Java.type API 来引用 Java 类。这跟在 Java 类中引入其他类是类似的。当定义了 Java 类型后我们可直接调用其静态方法 fun1() 并打印结果到 sout。因为方法是静态的，所以我们无需创建类实例。
```Java
var MyJavaClass = Java.type('my.package.MyJavaClass');
var result = MyJavaClass.fun1('John Doe');
print(result);
```

# 2、不安全的调用方法
在实际的使用中，如果对前台传入的js要执行的脚步没有做好校验，则任意出现安全问题。
demo如下：
```Java
public static void main(String args[]) throws ScriptException, IOException {
        ScriptEngineManager manager = new ScriptEngineManager();
        // 得到javascript脚本引擎
        ScriptEngine engine = manager.getEngineByName("javascript");
        String rce1 = "new java.lang.ProcessBuilder('cmd ',' /c  notepad.exe').start()";

        try {
            engine.eval(rce1);
        } catch (ScriptException e) {
            err.println(e);
        }
}
```
执行的结果：
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/c297eabb199ebee2f057d2696b18de68.png)
出发对应的rce。

# 3、nashorn的sandbox的使用
java提供脚本支持，这给我们业务提供了便利的同时，也给我们的服务带来了更大的风险，因为如果我们的业务需求是提供执行脚本的接口，那么JS脚本就是由客户端输入，这存在很多的不确定性，存在安全隐患，比如：

js代码存在死循环
js代码可以操作宿主机上面的功能，删除机器上的文件
js执行占用过多的java资源
这个时候sandbox就应运而生了，sandbox的作用就是将JS脚本执行的环境独立出来，达到对java类的访问限制以及对Nashorn引擎的资源限制的目的。

对应的demo如下：
```Java
   public static void main(String args[]) throws ScriptException, IOException {
        String jsfile1 = "function greet(name) { print('Hello, ' + name); } ";
        NashornSandbox sandbox = NashornSandboxes.create();
        sandbox.setMaxCPUTime(100);// 设置脚本执行允许的最大CPU时间（以毫秒为单位），超过则会报异常,防止死循环脚本
        sandbox.setMaxMemory(1024 * 1024); //设置JS执行程序线程可以分配的最大内存（以字节为单位），超过会报ScriptMemoryAbuseException错误
        sandbox.allowNoBraces(false); // 是否允许使用大括号
        sandbox.allowLoadFunctions(true); // 是否允许nashorn加载全局函数
        sandbox.setMaxPreparedStatements(30); // because preparing scripts for execution is expensive // LRU初缓存的初始化大小，默认为0
        sandbox.setExecutor(Executors.newSingleThreadExecutor());// 指定执行程序服务，该服务用于在CPU时间运行脚本
        out.println(sandbox.eval(jsfile1));
    }

```
对应的执行结果如下：

![image.png](http://moonsec.top/articlepic/f25c4e64262dc096b5a95ddc77859048.png)
不过，提供了白名单，可以设置白名单
通过白名单执行成功。
![image.png](http://moonsec.top/articlepic/5c102834614f30c05a9879b0f8cb1db5.png)

因此在设置白名单时候需要考虑安全问题。
# 调试代码的路径为：
https://github.com/wangsz05/LearnDemo/tree/master/ScriptEngineDemo
# 参考：
1、https://blog.csdn.net/qq_48234103/article/details/123294740