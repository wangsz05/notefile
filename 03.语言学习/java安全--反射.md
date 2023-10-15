# java安全---反射之有无参构建器或公私有方法

# 1、什么是反射？

反射是Java的特征之一，是一种间接操作目标对象的机制，核心是JVM在运行状态的时候才动态加载类，对于任意一个类都能够知道这个类所有的属性和方法，并且对于任意一个对象，都能够调用它的方法/访问属性。

这种动态获取信息以及动态调用对象方法的功能成为Java语言的反射机制。通过使用反射我们不仅可以获取到任何类的成员方法(Methods)、成员变量(Fields)、构造方法(Constructors)等信息，还可以动态创建Java类实例、调用任意的类方法、修改任意的类成员变量值等。

<p>正常情况下，如果我们要调用一个对象的方法，或者访问一个对象的字段，通常会传入对象实例：</p>

```java  
// Main.java
import com.itranswarp.learnjava.Person;
public class Main {
    String getFullName(Person p) {
        return p.getFirstName() + "" + p.getLastName();
    }
}

```

<p>但是，如果不能获得<code>Person</code>类，只有一个<code>Object</code>实例，比如这样：</p>

```java
String getFullName(Object obj) {
    return ???
}
```


<p>怎么办？有童鞋会说：强制转型啊！</p>

```java
String getFullName(Object obj) {
    Person p = (Person) obj;
    return p.getFirstName() +" " + p.getLastName();
}
```

<p>强制转型的时候，你会发现一个问题：编译上面的代码，仍然需要引用<code>Person</code>类。不然，去掉<code>import</code>语句，你看能不能编译通过？</p>
<p>所以，反射是为了解决在运行期，对某个实例一无所知的情况下，如何调用其方法。</p>


<p>除了<code>int</code>等基本类型外，Java的其他类型全部都是<code>class</code>（包括<code>interface</code>）。例如：</p>
<ul>
<li><code>String</code></li>
<li><code>Object</code></li>
<li><code>Runnable</code></li>
<li><code>Exception</code></li>
<li>...</li>
</ul>
<p>仔细思考，我们可以得出结论：<code>class</code>（包括<code>interface</code>）的本质是数据类型（<code>Type</code>）。无继承关系的数据类型无法赋值：</p>

```java
Number n = new Double(123.456); // OK
String s = new Double(123.456); // compile error!

```

<p>而<code>class</code>是由JVM在执行过程中动态加载的。JVM在第一次读取到一种<code>class</code>类型时，将其加载进内存。</p>

```java
 public final class Class {
    private Class() {}
}
```


<p>以<code>String</code>类为例，当JVM加载<code>String</code>类时，它首先读取<code>String.class</code>文件到内存，然后，为<code>String</code>类创建一个<code>Class</code>实例并关联起来：</p>

Class cls = new Class(String);

<p>这个<code>Class</code>实例是JVM内部创建的，如果我们查看JDK源码，可以发现<code>Class</code>类的构造方法是<code>private</code>，只有JVM能创建<code>Class</code>实例，我们自己的Java程序是无法创建<code>Class</code>实例的。</p>
<B>所以，JVM持有的每个<code>Class</code>实例都指向一个数据类型（<code>class</code>或<code>interface</code>）：</B>

<p>由于JVM为每个加载的<code>class</code>创建了对应的<code>Class</code>实例，并在实例中保存了该<code>class</code>的所有信息，包括类名、包名、父类、实现的接口、所有方法、字段等. 因此，如果获取了某个<code>Class</code>实例，我们就可以通过这个<code>Class</code>实例获取到该实例对应的<code>class</code>的所有信息。</p>

<B>这种通过<code>Class</code>实例获取<code>class</code>信息的方法称为反射（Reflection）。</B>

<p>如何获取一个<code>class</code>的<code>Class</code>实例？有三个方法：</p>
<p>方法一：直接通过一个<code>class</code>的静态变量<code>class</code>获取：</p>

java  Class cls = String.class;

<p>方法二：如果我们有一个实例变量，可以通过该实例变量提供的<code>getClass()</code>方法获取：</p>

String s = "Hello";
Class cls = s.getClass();

<p>方法三：如果知道一个<code>class</code>的完整类名，可以通过静态方法<code>Class.forName()</code>获取：</p>

Class cls = Class.forName("java.lang.String);
<p>因为反射的目的是为了获得某个实例的信息。因此，当我们拿到某个<code>Object</code>实例时，我们可以通过反射获取该<code>Object</code>的<code>class</code>信息：</p>

```java
void printObjectInfo(Object obj) {
    Class cls = obj.getClass();
}
```



## 1.1、  java反射机制流程图

​	java文件加载到使用的过程：

![image-20230108152259663](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20230108152259663.png)

我们创建了一个类文件`People.java`，经过javac编译之后，就会形成class文件，同时jvm内存会查找生成的class文件读入内存和经过ClassLoader加载，同时会自动创建生成一个Class对象，里面拥有其获取成员变量Field，成员方法Method和构造方法Constructor等方法。最后就是我们平时new创建对象。



# 2、反射的方式详解

　　Java安全可以从反序列化漏洞开始说起，反序列化漏洞⼜可以从反射开始说起。反射是⼤多数语⾔⾥都必不可少的组成部分，对象可以通过反射获取他的类，类可以通过反射拿到所有⽅法（包括私有），拿到的⽅法可以调⽤，总之通过“反射”，我们可以将Java这种静态语⾔附加上动态特性。

　　java 动态特性：“⼀段代码，改变其中的变量，将会导致这段代码产⽣功能性的变化”，称之为动态特性，⽐如，这样⼀段代码，在你不知道传⼊的参数值的时候，你是不知道他的作⽤是什么的：

```java
public void execute(String className, String methodName) throws Exception {

 Class clazz = Class.forName(className);

 clazz.getMethod(methodName).invoke(clazz.newInstance());

}
```

**上⾯的例⼦中，演示了⼏个在反射⾥极为重要的⽅法：**

- 获取类的⽅法： forName

- 实例化类对象的⽅法： newInstance

- 获取函数的⽅法： getMethod

- 执⾏函数的⽅法： invoke

基本上，这⼏个⽅法包揽了Java安全⾥各种和反射有关的Payload。

## 2.1 forName() 

forName 不是获取“类”的唯⼀途径，通常来说我们有如下三种⽅式获取⼀个“类”，也就是 `java.lang.Class `对象：

- obj.getClass() 如果上下⽂中存在某个类的实例 obj ，那么我们可以直接通过obj.getClass() 来获取它的类

- Test.class 如果你已经加载了某个类，只是想获取到它的 java.lang.Class 对象，那么就直接拿它的 class 属性即可。这个⽅法其实不于反射。

- Class.forName()如果你知道某个类的名字，想获取到这个类，就可以使⽤ `forName`来获取

在安全研究中，我们使⽤反射的⼀⼤⽬的，就是绕过某些沙盒。⽐如，上下⽂中如果只有Integer类型的数字，我们如何获取到可以执⾏命令的Runtime类呢？也许可以这样（伪代码）：` "1".getClass().forName("java.lang.Runtime")`

forName有两个函数重载：

- Class<?> forName(String name)

- Class<?> forName(String name, boolean initialize, ClassLoader loader)

第⼀个就是我们最常⻅的获取class的⽅式，其实可以理解为第⼆种⽅式的⼀个封装：

```java
Class.forName(className)
// 等于
Class.forName(className, true, currentLoader)
```

### 2.1.1 Class.forName() 参数说明

`Class.forName(className, true, currentLoader)`

默认情况下， forName 的第⼀个参数是类名；第⼆个参数表示是否初始化；第三个参数就是 ClassLoader 。

ClassLoader 是什么呢？它就是⼀个“加载器”，告诉Java虚拟机如何加载这个类。Java默认的 ClassLoader 就是根据类名来加载类，这个类名是类完整路径，如 `java.lang.Runtime` 。

**第⼆个参数 initialize 说明：**

使⽤功能”.class”来创建Class对象的引⽤时，不会⾃动初始化该Class对象，使⽤forName()会⾃动初始化该Class对象

![image-20230108153727862](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20230108153727862.png)

图中有说“构造函数，初始化时执⾏”，其实在 forName 的时候，构造函数并不会执⾏，即使我们设置 initialize=true 。

那么这个初始化究竟指什么呢？

可以将这个“初始化”理解为类的初始化。我们先来看看如下这个类：

```java
public class TrainPrint {
 {
 System.out.printf("Empty block initial %s\n", this.getClass());
 }
 static {
 System.out.printf("Static initial %s\n", TrainPrint.class);
 }
 public TrainPrint() {
 System.out.printf("Initial %s\n", this.getClass());
 }
}
```

上述的三个“初始化”⽅法有什么区别，调⽤顺序是什么，在安全上

有什么价值？

其实你运⾏⼀下就知道了，⾸先调⽤的是 static {} ，其次是 {} ，最后是构造函数。

其中， static {} 就是在“类初始化”的时候调⽤的，⽽ {} 中的代码会放在构造函数的 super() 后⾯，

但在当前构造函数内容的前⾯。

所以说， forName 中的 initialize=true 其实就是告诉Java虚拟机是否执⾏”类初始化“。

那么，假设我们有如下函数，其中函数的参数name可控：

```java
public void ref(String name) throws Exception {
 Class.forName(name);
}
```

我们就可以编写⼀个恶意类，将恶意代码放置在 static {} 中，从⽽执⾏.

###  2.2   getMethod 方法和 invoke 反射调用

在正常情况下，除了系统类，如果我们想拿到一个类，需要先 import 才能使用。而使用forName就不需要，这样对于我们的攻击者来说就十分有利，我们可以加载任意类。

另外，我们经常在一些源码里看到，类名的部分包含 `$` 符号，比如fastjson在 checkAutoType 时候就会先将 `$` 替换成` `. ：https://github.com/alibaba/fastjson/blob/fcc9c2a/src/main/java/com/alibaba/fastjson/parser/ParserConfifig.java#L1038。 `$` 的作用是查找内部类。

Java的普通类 C1 中支持编写内部类 C2 ，而在编译的时候，会生成两个文件： C1.class 和

`C1$C2.class` ，我们可以把他们看作两个无关的类，通过 `Class.forName("C1$C2")` 即可加载这个内部类。获得类以后，我们可以继续使用反射来获取这个类中的属性、方法，也可以实例化这个类，并调用方法.

`class.newInstance() `的作用就是调用这个类的无参构造函数，这个比较好理解。不过，我们有时候

在写漏洞利用方法的时候，会发现使用 newInstance 总是不成功，这时候原因可能是：

- 你使用的类没有无参构造函数

- 你使用的类构造函数是私有的

最最最常见的情况就是 java.lang.Runtime ，这个类在我们构造命令执行Payload的时候很常见，但

我们不能直接这样来执行命令：

```java
Class clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec", String.class).invoke(clazz.newInstance(), "id");
```

原因是 Runtime 类的构造方法是私有的。

有同学就比较好奇，为什么会有类的构造方法是私有的，难道他不想让用户使用这个类吗？这其实涉及到很常见的设计模式：“单例模式”。（有时候工厂模式也会写成类似）

比如，对于Web应用来说，数据库连接只需要建立一次，而不是每次用到数据库的时候再新建立一个连接，此时作为开发者你就可以将数据库连接使用的类的构造函数设置为私有，然后编写一个静态方法来获取：

```java
public class TrainDB {
private static TrainDB instance = new TrainDB();
public static TrainDB getInstance() {
return instance;
}
private TrainDB() {
// 建立连接的代码...
}
}
```

这样，只有类初始化的时候会执行一次构造函数，后面只能通过 getInstance 获取这个对象，避免建

立多个数据库连接。

回到正题，Runtime类就是单例模式，我们只能通过 Runtime.getRuntime() 来获取到 Runtime 对

象。我们将上述Payload进行修改即可正常执行命令了：

```java
Class clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec",String.class).invoke(clazz.getMethod("getRuntime").invoke(clazz),"calc.exe");
```

这里用到了 getMethod 和 invoke 方法。

getMethod 的作用是通过反射获取一个类的某个特定的公有方法。而学过Java的同学应该清楚，Java中支持类的重载，我们不能仅通过函数名来确定一个函数。所以，在调用 getMethod 的时候，我们需要传给他你需要获取的函数的参数类型列表。

比如这里的 Runtime.exec 方法有6个重载：

![image-20230108164433228](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20230108164433228.png)

我们使用最简单的，也就是第一个，它只有一个参数，类型是String，所以我们使用

getMethod("exec", String.class) 来获取 Runtime.exec 方法。

invoke 的作用是执行方法，它的第一个参数是：

- 如果这个方法是一个普通方法，那么第一个参数是类对象

- 如果这个方法是一个静态方法，那么第一个参数是类

这也比较好理解了，我们正常执行方法是 [1].method([2], [3], [4]...) ，其实在反射里就是method.invoke([1], [2], [3], [4]...) 。

所以我们将上述命令执行的Payload分解一下就是：

```java
Class clazz = Class.forName("java.lang.Runtime");
Method execMethod = clazz.getMethod("exec", String.class);
Method getRuntimeMethod = clazz.getMethod("getRuntime");
Object runtime = getRuntimeMethod.invoke(clazz);
execMethod.invoke(runtime, "calc.exe");
```

### 2.2.1 invoke()的说明

invoke()的使用场景主要在 使用的类无法调用`class.newInstance() `方法，主要是如下两类：

- 你使用的类没有无参构造函数

- 你使用的类构造函数是私有的

咱们借助 java.lang.Runtime ，这个类在我们构造命令执行Payload的时候很常见，但我们不能直接这样来执行命令：

```
Class clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec", String.class).invoke(clazz.newInstance(), "id")
```

因为Runtime 默认构造方法为私有方法，直接调用会报错

![image-20230108175501297](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20230108175501297.png)

咱们只能通过如下的invoke的方式调用：

```java
Class clazz = Class.forName("java.lang.Runtime");
Method execMethod = clazz.getMethod("exec", String.class);
Method getRuntimeMethod = clazz.getMethod("getRuntime");
Object runtime = getRuntimeMethod.invoke(clazz);
execMethod.invoke(runtime, "calc.exe");
```

PS：method.invoke(owner, args)：执行该Method.invoke方法的参数是执行这个方法的对象owner，和参数数组args，可以这么理解：owner对象中带有参数args的method方法(owner这个对象为method的父类对象)。返回值是Object，也既是该方法的返回值。

上述的代码：`Object runtime = getRuntimeMethod.invoke(clazz);`	实际上相当于实例化了getRuntime的方法，由于该方法不存在参数，所以不需要带参数项。

下述方法主要对比invoke的方法内容：

![image-20230108172935242](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20230108172935242.png)

对比java的源码：getMethod 返回该getRuntime（）的方法，如果加上invoke，则相当于调用了该getRuntime的方法，通过源码可以看出，返回的是Runtime实例。

![image-20230108173736950](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20230108173736950.png)

#  3、无参构或私有方法下的反射调用

简单的命令执行Payload，但遗留下来两个问题：

- 如果一个类没有无参构造方法，也没有类似单例模式里的静态方法，我们怎样通过反射实例化该类呢？

- 如果一个方法或构造方法是私有方法，我们是否能执行它呢？

第一个问题，我们需要用到一个新的反射方法 getConstructor 。

## 3.1 getConstructor 方法

使用方式：getConstructor获取有参数构造函数 然后newInstance执行有参数的构造函数

使用demo

```java
package demo2;
public class Person {
    private int age;
    private String name;
 
    public Person( String name,int age) {
        this.age = age;
        this.name = name;
        System.out.println("构造函数Person(有参数)执行");
    }
 
    public Person() {
        System.out.println("构造函数Person(无参数)执行");
    }
    
}
```

```java
package Main;
 
import java.lang.reflect.Constructor;
 
public class Main {
    public static void main(String[] args)  throws Exception{
 
        //当我不想 newInstance初始化的时候执行空参数的构造函数的时候
        //可以通过字节码文件对象方式 getConstructor(paramterTypes) 获取到该构造函数
        String classname="demo2.Person";
        //寻找名称的类文件，加载进内存 产生class对象
        Class cl=Class.forName(classname);
        //获取到Person(String name,int age) 构造函数
        Constructor con=cl.getConstructor(String.class,int.class);
 
        //通过构造器对象 newInstance 方法对对象进行初始化 有参数构造函数
        Object obj=con.newInstance("神奇的我",12);
    }
}
```

运行结果

![image-20230108205524350](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20230108205524350.png)



## 3.2 getConstructor 反射方式利用

getConstructor 和 getMethod 类似， getConstructor 接收的参数是构造函数列表类型，因为构造函数也支持重载，所以必须用参数列表类型才能唯一确定一个构造函数。获取到构造函数后，我们使用 newInstance 来执行。

比如，我们常用的另一种执行命令的方式ProcessBuilder，正常执行命令的方式如下：

```java
 ProcessBuilder processBuilder = new ProcessBuilder();
 processBuilder.command("notepad.exe");
 Process process = processBuilder.start();
```

ProcessBuilder有两个构造函数：

- public ProcessBuilder(List<String> command)

- public ProcessBuilder(String... command)

我们使用反射来获取其构造函数，然后调用start() 来执行命令：

```java
Class clazz = Class.forName("java.lang.ProcessBuilder");
((ProcessBuilder)clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe"))).start();
```

上面用到了第一个形式的构造函数，所以我在 getConstructor 的时候传入的是 List.class 。

但是，我们看到，前面这个Payload用到了Java里的强制类型转换，有时候我们利用漏洞的时候（在表达式上下文中）是没有这种语法的。所以，我们仍需利用反射来完成这一步。

也可以利用前面的invoke方法：

```java
Class clazz = Class.forName("java.lang.ProcessBuilder");
clazz.getMethod("start").invoke(clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe")));
```

通过 getMethod("start") 获取到start方法，然后 invoke 执行， invoke 的第一个参数就是ProcessBuilder Object了。

那么，如果我们要使用 public ProcessBuilder(String... command) 这个构造函数，需要怎样用反射执行呢？

这又涉及到Java里的可变长参数（varargs）了。正如其他语言一样，Java也支持可变长参数，就是当你定义函数的时候不确定参数数量的时候，可以使用 ... 这样的语法来表示“这个函数的参数个数是可变的”。

对于可变长参数，Java其实在编译的时候会编译成一个数组，也就是说，如下这两种写法在底层是等价的（也就不能重载）：

```
public void hello(String[] names) {}
public void hello(String...names) {}
```

也由此，如果我们有一个数组，想传给hello函数，只需直接传即可：

```
String[] names = {"hello", "world"};
hello(names);
```

那么对于反射来说，如果要获取的目标函数里包含可变长参数，其实我们认为它是数组就行了。

所以，我们将字符串数组的类 String[].class 传给 getConstructor ，获取 ProcessBuilder 的第二种构造函数：

```
Class clazz = Class.forName("java.lang.ProcessBuilder");
clazz.getConstructor(String[].class)
```

在调用 newInstance 的时候，因为这个函数本身接收的是一个可变长参数，我们传给

ProcessBuilder 的也是一个可变长参数，二者叠加为一个二维数组，所以整个Payload如下：

```java
Class clazz = Class.forName("java.lang.ProcessBuilder");
((ProcessBuilder)clazz.getConstructor(String[].class).newInstance(new String[][]{{"calc.exe"}})).start();
```

## 3.3 私有方法执行

这就涉及到 getDeclared 系列的反射了，与普通的 getMethod 、 getConstructor 区别是：

- getMethod 系列方法获取的是当前类中所有公共方法，包括从父类继承的方法
- getDeclaredMethod 系列方法获取的是当前类中“声明”的方法，是实在写在这个类里的，包括私有的方法，但从父类里继承来的就不包含了.

getDeclaredMethod 的具体用法和 getMethod 类似， getDeclaredConstructor 的具体用法和getConstructor 类似。

举个例子，前文我们说过Runtime这个类的构造函数是私有的，我们需要用 Runtime.getRuntime() 来获取对象。其实现在我们也可以直接用 getDeclaredConstructor 来获取这个私有的构造方法来实例化对象，进而执行命令

```java
Class clazz = Class.forName("java.lang.Runtime");
Constructor m = clazz.getDeclaredConstructor();
m.setAccessible(true);
clazz.getMethod("exec", String.class).invoke(m.newInstance(), "calc.exe");
```

可见，这里使用了一个方法 setAccessible ，这个是必须的。我们在获取到一个私有方法后，必须用setAccessible 修改它的作用域，否则仍然不能调用。




# 参考
1、https://www.liaoxuefeng.com/wiki/1252599548343744/1255945147512512

2、[phith0n/JavaThings: Share Things Related to Java - Java安全漫谈笔记相关内容 (github.com)](https://github.com/phith0n/JavaThings)



