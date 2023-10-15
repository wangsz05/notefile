# 说明
此文章来记录自己的学习过程

# 1、前言
1、前面分析了[CC1](https://moonsec.top/articles/79)，但是发现在CC1的利用链中是有版本的限制的。在**JDK1.8 8u71**版本以后，对AnnotationInvocationHandler的readobject进行了改写。导致高版本中利用链无法使用。
这就有了其他的利用链，在CC2链里面并不是使用 AnnotationInvocationHandler来构造，而是使用**javassist**和**PriorityQueue**来构造利用链。
2、CC2链中使用的是commons-collections-4.0版本，但是CC1在commons-collections-4.0版本中其实能使用，但是commons-collections-4.0版本删除了lazyMap的decode方法，这时候我们可以使用lazyMap方法来代替。但是这里产生了一个疑问，为什么CC2链中使用commons-collections-4.03.2.1-3.1版本不能去使用，使用的是commons-collections-4.04.0的版本？在中间查阅了一些资料，发现在3.1-3.2.1版本中TransformingComparator并没有去实现Serializable接口,也就是说这是不可以被序列化的。所以在利用链上就不能使用他去构造。
利用链的过程如下：

```txt
Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				...
					TransformingComparator.compare()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.exec()

```
下面就来学习一下需要用到的基础知识。
# 2、前置知识
## 2.1 Java安全之Javassist动态编程
### 2.1.1 Javassist 介绍
Java 字节码以二进制的形式存储在 class 文件中，每一个 class 文件包含一个 Java 类或接口。Javaassist 就是一个用来处理 Java 字节码的类库。
Javassist是一个开源的分析、编辑和创建Java字节码的类库。

### 2.1.2 Javassist使用
这里主要讲一下主要的几个类：
**ClassPool**
ClassPool：一个基于哈希表（Hashtable）实现的CtClass对象容器，其中键名是类名称，值是表示该类的CtClass对象（Hashtable和Hashmap类似都是实现map接口，hashmap可以接收null的值，但是Hashtable不行）。
**ClassPool** 是一个存储 CtClass 的 Hash 表，类的名称作为 Hash 表的 key。ClassPool 的 get() 函数用于从 Hash 表中查找 key 对应的 CtClass 对象。如果没有找到，get() 函数会创建并返回一个新的 CtClass 对象，这个新对象会保存在 Hash 表中。
使用的例子如下：
```java 
ClassPool pool = ClassPool.getDefault();
CtClass cc = pool.get("com.Test1");
cc.setSuperclass(pool.get("com.Test2"));
cc.writeFile();
```


- getDefault()方法返回了默认的类池（默认的类池搜索系统搜索路径，通常包括平台库、扩展库以及由-classpath选项或CLASSPATH环境变量指定的搜索路径）

- get() 方法来ClassPool中获得一个com.Test1类的CtClass对象的引用，并将其赋值给变量 cc

- setSuperclass方法将com.Test1的父类被设置为com.Test2

- writeFile() 方法会将修改后的CtClass对象转换成类文件并写到本地磁盘
**常用方法：**
```java
static ClassPool	getDefault()
	返回默认的类池。
ClassPath	insertClassPath(java.lang.String pathname)	
	在搜索路径的开头插入目录或jar（或zip）文件。
ClassPath	insertClassPath(ClassPath cp)	
	ClassPath在搜索路径的开头插入一个对象。
java.lang.ClassLoader	getClassLoader()	
	获取类加载器toClass()，getAnnotations()在 CtClass等
CtClass	get(java.lang.String classname)	
	从源中读取类文件，并返回对CtClass 表示该类文件的对象的引用。
ClassPath	appendClassPath(ClassPath cp)	
	将ClassPath对象附加到搜索路径的末尾。
CtClass	makeClass(java.lang.String classname)
	创建一个新的public类
```
**CtClass**
CtClass表示类，一个CtClass(编译时类）对象可以处理一个class文件，这些CtClass对象可以从ClassPoold的一些方法获得。

常用方法：#
```java
void	setSuperclass(CtClass clazz)
	更改超类，除非此对象表示接口。
java.lang.Class<?>	toClass(java.lang.invoke.MethodHandles.Lookup lookup)	
	将此类转换为java.lang.Class对象。
byte[]	toBytecode()	
	将该类转换为类文件。
void	writeFile()	
	将由此CtClass 对象表示的类文件写入当前目录。
void	writeFile(java.lang.String directoryName)	
	将由此CtClass 对象表示的类文件写入本地磁盘。
CtConstructor	makeClassInitializer()	
	制作一个空的类初始化程序（静态构造函数）。
```
**CtMethod**
CtMethod：表示类中的方法。

CtConstructor#
CtConstructor的实例表示一个构造函数。它可能代表一个静态构造函数（类初始化器）。

常用方法#
```java
void	setBody(java.lang.String src)	
	设置构造函数主体。
void	setBody(CtConstructor src, ClassMap map)	
	从另一个构造函数复制一个构造函数主体。
CtMethod	toMethod(java.lang.String name, CtClass declaring)	
	复制此构造函数并将其转换为方法。
```
**ClassClassPath**
该类作用是用于通过 getResourceAsStream（） 在 java.lang.Class 中获取类文件的搜索路径。

构造方法：

```java
ClassClassPath(java.lang.Class<?> c)	
	创建一个搜索路径。
```
常见方法：#
```java
java.net.URL	find (java.lang.String classname)	
	获取指定类文件的URL。
java.io.InputStream	openClassfile(java.lang.String classname)	
	通过获取类文getResourceAsStream()。
```
在默认系统搜索路径获取ClassPool对象。

如果需要修改类搜索的路径需要使用insertClassPath方法进行修改。

pool.insertClassPath(new ClassClassPath(this.getClass()));
将本类所在的路径插入到搜索路径中
**toBytecode**

```java
package com.demo;

import javassist.*;


import java.io.IOException;
import java.util.Arrays;

public class testssit {
    public static void main(String[] args) throws NotFoundException, CannotCompileException, IOException {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(demo.class.getClass()));
        CtClass ctClass = pool.get("com.demo.test");
        ctClass.setSuperclass(pool.get("com.demo.test"));
//        System.out.println(ctClass);
        byte[] bytes = ctClass.toBytecode();
        String s = Arrays.toString(bytes);
        System.out.println(s);
    }

}

```
![image.png](http://moonsec.top/articlepic/c66a0884037408a529ccdb04863082c0.png)
**toClass**
toClass 的使用demo
```java

import javassist.*;

public class testInsert {
    public static void main(String[] args) throws NotFoundException, CannotCompileException, InstantiationException, IllegalAccessException {
        ClassPool cp = ClassPool.getDefault();
        CtClass cc  = cp.get("javaAssist.hello1");
        CtMethod cm = cc.getDeclaredMethod("say");
        cm.insertBefore("{ System.out.println(\"Hello.say():\"); }");
        Class c = cc.toClass();
        hello1 h = (hello1)c.newInstance();
        h.say();
    }
}

```
![image.png](http://moonsec.top/articlepic/6ceaced407087a5ffb98d6bc1360af08.png)

再介绍几个方法：

makeClass()和makeInterface()

//创建名为Evil的类
CtClass test = pool.makeClass("Evil");

//创建名为Evil的接口
CtClass test = pool.makeInterface("Evil");
makeClassInitializer()

#创建一个空的类初始化器（静态构造函数）
CtConstructor constructor = test.makeClassInitializer();

### 2.1.3 ClassLoader
ClassLoader是Java的类加载器，负责将字节码转化成内存中的Java类，

我们这里可以利用类加载器的defineClass方法来加载我们的字节码。
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import javassist.*;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class CommmonsCollections2 {

    public static void main(String[] args) throws IOException, ClassNotFoundException, CannotCompileException, NotFoundException, InvocationTargetException, IllegalAccessException, InstantiationException, NoSuchMethodException {

        ClassPool pool = ClassPool.getDefault();
        CtClass test = pool.makeClass("Evil");
        test.setSuperclass(pool.get("Test"));
        test.writeFile("./");
        byte[] bytes = test.toBytecode();
        Class clas = Class.forName("java.lang.ClassLoader");
        Method defineclass = clas.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineclass.setAccessible(true);
        Class claz = (Class) defineclass.invoke(ClassLoader.getSystemClassLoader(),"Evil",bytes,0,bytes.length);
        Test e = (Test) claz.newInstance();
        e.hello();
    }
}

```

```java
public class Test {

    public static void main(String[] args) {

    }
    public void hello(){
        System.out.println("hello Test");
    }
}

```
**注：后面有用**

这里需要注意的是，ClassLoader#defineClass返回的类并不会初始化，只有这个对象显式地调用其构造函数初始化代码才能被执行，所以我们需要想办法调用返回的类的构造函数才能执行命令。







# 参考
1、https://www.freebuf.com/vuls/326296.html
2、https://www.cnblogs.com/nice0e3/p/13811335.html