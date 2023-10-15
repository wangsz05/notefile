# # arthas 的原理分析

## 1、Arthas 原理概览

Arthas 是基于 **ASM** 和 **Java Agent** 技术实现的 Java 诊断利器。
① **ASM** 是指一个 Java 字节码操作框架，用于动态生成或者增强 class。
② **采用 Attach API 方式的 Java Agent** 是指在 JVM 启动后通过 Attach API 执行 agentmian 方法，利用 **Instrumentation API** 的 debug 和 profiler 能力。

Arthas 除了利用 JDK 自带的工具，例如查看堆内存 jmap、查看线程 jstack 等。Arthas 整体模块的调用图如下：

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/21744606-8d7be7767bf28577.png)

# 2 核心机制

## 2.1 Java Agent

### 2.1.1 Java Agent 的加载方式

Java agent是一种特殊的Java程序（Jar文件），它是Instrumentation的客户端。与普通Java程序通过main方法启动不同，agent并不是一个可以单独启动的程序，而必须依附在一个Java应用程序（JVM）上，与它运行在同一个进程中，通过Instrumentation API与虚拟机交互。

Java agent与Instrumentation密不可分，二者也需要在一起使用。因为Instrumentation的实例会作为参数注入到Java agent的启动方法中。

Java Agent 有 2 种加载方式，1.利用启动参数 -javaagent 启动时加载方式；2.Attach API 运行时的加载方式。



```java
#加载方式1：JVM 启动时候加载，通过 javaagent 启动参数 java -javaagent:myagent.jar MyMain。该种方式需要程序 main 方法执行之前执行 agent 中的 premain 方法
 public static void premain(String agentArgs)
 public static void premain(String agentArgument, Instrumentation instrumentation) throws Exception
#加载方式2：JVM 运行时 Attach API 加载。该方式会在 agent 加载以后执行 agentmain 方法
 public static void agentmain(String agentArgs)
 public static void agentmain(String agentArgument, Instrumentation instrumentation) throws Exception
```

**方式1：利用启动参数 -javaagent 启动时的加载方式**
`premain` 方法是在启动时，类加载前定义类的 `TransFormer`，在类加载的时候更新对应的类的字节码。

> premain 方法的执行步骤如下：
> ① 创建 `InstrumentationImpl` 对象
> ② 监听 `ClassFileLoadHook` 事件
> ③ 调用 `InstrumentationImpl` 的 `loadClassAndCallPremain` 方法，最终调用 javaagent 里 MANIFEST.MF 里指定的 `Premain-Class` 类的 `premain` 方法

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/08a3088a6ce0610743e856f8201765ee.png)

**方式2：Attach API 运行时的加载方式**
Attach API 在运行时进行类的字节码的修改，关键是注册类的 TransFormer、调用 retransformClasses 函数重加载类。

> agentmain 方法的执行步骤如下：
> ① 创建 `InstrumentationImpl` 对象
> ② 监听 `ClassFileLoadHook` 事件
> ③ 调用 `InstrumentationImpl` 的 `loadClassAndCallAgentmain` 方法，最终调用 javaagent 里 MANIFEST.MF 里指定的 `Agentmain-Class` 类的 `agentmain` 方法

![img](https://upload-images.jianshu.io/upload_images/21744606-46108c7a77042af9.png?imageMogr2/auto-orient/strip|imageView2/2/w/1013/format/webp)



### 2.1.2 Java Instrumentation 介绍

Instrumentation 是一个 JVM 接口，该接口提供了**一组查看和操作 Java 类的方法，例如修改类的字节码、向 classLoader 的 classpath 下加入 jar 文件等**。开发者可以通过 Java 语言来操作和监控 JVM 内部的状态，进而实现 Java 程序的监控分析。

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/9eb0e3cdbb01c01e54c8f308f582b086.png)

Instrumentation是Java提供的一个来自JVM的接口，该接口提供了一系列查看和操作Java类定义的方法，例如修改类的字节码、向classLoader的classpath下加入jar文件等。使得开发者可以通过Java语言来操作和监控JVM内部的一些状态，进而实现Java程序的监控分析，甚至实现一些特殊功能（如AOP、热部署）。

**Instrumentation 关键的源码如下**：

```java
public interface Instrumentation {
    /**
     * 注册一个Transformer，从此之后的类加载都会被Transformer拦截。
     * Transformer可以直接对类的字节码byte[]进行修改
     */
    void addTransformer(ClassFileTransformer transformer);
    
    /**
     * 对JVM已经加载的类重新触发类加载。使用的就是上面注册的Transformer。
     * retransformation可以修改方法体，但是不能变更方法签名、增加和删除方法/类的成员属性
     */
    void retransformClasses(Class<?>... classes) throws UnmodifiableClassException;
    
    /**
     * 获取一个对象的大小
     */
    long getObjectSize(Object objectToSize);
    
    /**
     * 将一个jar加入到bootstrap classloader的 classpath里
     */
    void appendToBootstrapClassLoaderSearch(JarFile jarfile);
    
    /**
     * 获取当前被JVM加载的所有类对象
     */
    Class[] getAllLoadedClasses();
}
```

上述最常用的方法就是 `addTransformer(ClassFileTransformer transformer)`。该方法可以在类加载时做拦截，对输入的类的字节码进行修改，其参数是一个 ClassFileTransformer 接口，定义如下：



```java
/**
 * 传入参数表示一个即将被加载的类，包括了classloader，classname和字节码byte[]
 * 返回值为需要被修改后的字节码byte[]
 */
byte[]
transform(  ClassLoader         loader,
            String              className,
            Class<?>            classBeingRedefined,
            ProtectionDomain    protectionDomain,
            byte[]              classfileBuffer)  throws IllegalClassFormatException;
```

**Instrumentation 实现热修改类的样例**
**步骤 1**：instrumentationAgent.jar 实现 `premain` 方法。

```java
public class InstrumentationExample {
    public static void premain(String args, Instrumentation inst) {
        // Instrumentation提供的addTransformer方法，在类加载时会回调ClassFileTransformer接口
        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer)
                                    throws IllegalClassFormatException {
                // 开发者在此自定义做字节码操作，将传入的字节码修改后返回
                // 通常这里需要字节码操作框架
                // ......
                return transformResult;
            }
        });
    }
}
```

**步骤 2**：Attach API 的程序是一个独立的 java 程序即 JVM 独立进程，需要通过 JVM 的 `attach` 接口与目标进程通信。

```csharp
// VirtualMachine等相关Class位于JDK的tools.jar
VirtualMachine vm = VirtualMachine.attach("27082");  // 27082表示目标JVM进程pid
try {
    vm.loadAgent(".../instrumentationAgent.jar");    // 指定instrumentationAgent的jar包路径，发送给目标进程
} finally {
    vm.detach();
}
```

## 2.2 ASM

[ASM 是一个 Java 字节码操作框架](https://links.jianshu.com/go?to=https%3A%2F%2Fzhuanlan.zhihu.com%2Fp%2F94498015)，用于动态生成或者增强 class。[Arthas 的 watch 是基于 ASM 实现的](https://links.jianshu.com/go?to=https%3A%2F%2Fzhuanlan.zhihu.com%2Fp%2F115127052)

**ASM 的工作步骤**：
① 通过 ClassReader 读取编译好的 .class 文件
② 通过访问者模式（Visitor）对字节码进行修改，常见的 Visitor 类有：对方法进行修改的MethodVisitor、对变量进行修改的 FieldVisitor 等
③ 通过 ClassWriter 重新构建编译修改后的字节码文件、或者将修改后的字节码文件输出到文件中

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/21744606-c85f5bc6d050b096.png)



#### [**6.2.1 IDE提供的HotSwap**](https://mp.weixin.qq.com/s?__biz=MzUzMTA2NTU2Ng==&mid=2247487551&idx=1&sn=18f64ba49f3f0f9d8be9d1fdef8857d9&scene=21#wechat_redirect)

使用eclipse或IntelliJ IDEA通过debug模式启动时，默认会开启一项HotSwap功能。用户可以在IDE里修改代码时，直接替换到目标程序的类里。不过这个功能只允许修改方法体，而不允许对方法进行增删改。

该功能的实现与debug有关。debug其实也是通过JVMTI agent来实现的，JVITI agent会在debug连接时加载到debugee的JVM中。debuger（IDE）通过JDI（Java debug interface）与debugee（目标Java程序）通过进程通讯来设置断点、获取调试信息。除了这些debug的功能之外，JDI还有一项redefineClass的方法，可以直接修改一个类的字节码。没错，它其实就是暴露了JVMTI的bytecode instrument功能，而IDE作为debugger，也顺带实现了这种HotSwap功能。

原理示意图如下，顺带着也把Java debug的原理也画了出来，毕竟知识都是相通的：）

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/83a6c3992ecf2588acf2242d46c26251.png)

IDE提供的HotSwap

由于是直接使用的JVM的原生的功能，其效果当然也一样：只能修改方法体，否则会弹出警告。例如eclipse会弹出””Hot Code Replace Failed”。不过优点在于简单实用，无需安装。

对了，如果你经常在生产环境debug的话，请在debug连接时不要修改本地代码，因为如果你只修改了方法体，那么你的本地代码修改能够直接被hotswap到线上去 ：）