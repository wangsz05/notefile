# 说明
此篇通过getter 和 setter方法角度来了解fastjson反序列化过程。
# 1、反序列化介绍
说到Java的序列化，大多数人都知道使用ObjectOutputStream将对象写成二进制流，再使用ObjectInputStream将二进制流写成文件实现序列化和反序列化。今天这篇文章将深入分析一下序列化。

## 1.1 Serializable
通常我们序列化一个对象的目的是为了可以再序列化回来，使用场景有很多，比如说：
- 把对象保存到文件中，然后可以再恢复
- 使用网络IO传递一个对象
- 因为memcache不支持存储对象，把对象序列化后存到memcache中，用的时候再序列化回来
总之序列化的使用场景有很多。
首先，只有实现了Serializable和Externalizable接口的类的对象才能被序列化。
## 1.2 不实现Serializable接口序列化报错
可能很多人都知道Serializable接口而不知道Externalizable接口，所以这里先来介绍一下Serializable接口，Externalizable接口最后再介绍。
我们通常一个类的对象需要被序列化，我们会实现Serializable接口，如果不实现Serializable接口则会抛出异常：
```Java
java.io.NotSerializableException
```
## 1.3 序列化反序列化的注意事项
当我们将一个二进制流反序列化的时候有一些是需要注意的，否则反序列化会失败
- 1.反序列化后对象的全类名（包名+类名）需要和序列化之前对象的全类名一致
- 2.反序列化后对象的serialVersionUID需要和和序列化之前对象的serialVersionUID一致

先来解释一下第一点：序列化后的二进制流中会存储对象的全类名，如果反序列化的时候目标对象的全类名和二进制流中的全类名信息不匹配的话会抛出异常：
```Java
java.lang.ClassCastException
```
demo：
```Java
@Test
public void testDiffPackage() throws Exception {
    //序列化User对象到file
    File file = new File("E:/User.txt");
    ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(file));
    outputStream.writeObject(new User("lebron","123456"));

    //反序列化文件到另一个包里的User
    ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(file));
    com.lebron.serializable.otherpackage.User user = (com.lebron.serializable.otherpackage.User)inputStream.readObject();
    //由于篇幅原因，没有关闭流
}

```
由于两个user对象不一致，会抛出如下的异常
```Java
java.lang.ClassCastException
```
再来解释一下第二点：当我们的类实现Serializable接口的时候，会提示我们添加一个成员变量serialVersionUID，我们可以给serialVersionUID设置一个默认值
```Java
private static final long serialVersionUID = 1L;
```
这个serialVersionUID用来标识这个类的版本，和全类名一样这个serialVersionUID在序列化的时候也会被添加到二进制流中，反序列化的时候如果目标对象的serialVersionUID和二进制流中的serialVersionUID不匹配的话会抛出异常:
```Java
java.io.InvalidClassException
```
我们可以将User对象序列化到文件之后，再修改User类的serialVersionUID，然后反序列化User对象就会出现上面的异常。
## 1.4 serialVersionUID
实现了Serializable接口的类如果我们不显示的指定serialVersionUID的话，那么会基于类的属性方法等参数生成一个默认的serialVersionUID，如果类的属性或方法有所改动，那么这个默认的serialVersionUID也会随之改动。
所以如果我们不显示的指定serialVersionUID的话，只要类有所改动serialVersionUID就会变化，从而导致反序列化失败。
对于serialVersionUID的显示赋值，一般情况下直接设置成1L就行了，当然了也可以使用IDE帮我们自动生成的serialVersionUID作为默认值。

## 1.5 transient修饰符
transient的作用是标记目标类的属性，使得该属性不参与序列化和反序列化的过程。

下面一段代码演示一下transient修饰符的作用
```Java
//目标类
public class User implements Serializable {

    private static final long serialVersionUID = 1L;
    private String name;
    private transient String password;
    ...
}

```
```Java
@Test
public void testTransient() throws Exception {
    File file = new File("e:/user.txt");
    ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(file));
    outputStream.writeObject(new User("lebron", "123"));

    ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(file));
    User user = (User) inputStream.readObject();
    System.out.println(user);
    //由于篇幅原因，没有关闭流
}
```
User类的password属性被transient修饰时的返回值

```Java
User [name=lebron, password=null]
```
User类的password属性没有被transient修饰时的返回值
```Java
User [name=lebron, password=123]
```
通过上面一段测试代码可以得出结论：序列化反序列化会忽略transient修饰的属性

## 1.6 static修饰符
static修饰符修饰的属性也不会参与序列化和反序列化。

有时候我们反序列化后生成的对象中的静态成员变量的值和序列化之前是一样的，但是这并不是通过反序列化得到的，而是因为静态成员变量时类的属性，反序列化后的对象也是这个目标类，所以这个静态成员变量会和序列化之前的值一样。

## 1.7 默认方法writeObject和readObject
```java
 * private void writeObject(java.io.ObjectOutputStream out)
 *     throws IOException
 * private void readObject(java.io.ObjectInputStream in)
 *     throws IOException, ClassNotFoundException;
```
通过翻看Serializable接口的注释，我们可以看到这两个方法，这两个方法下面有大量的注释，这里就不贴出来了，有兴趣的可以自己去看一下，这里解释一下这两个方法。
先来看一下ObjectStreamClass类的源码：
```java
if (externalizable) {
    cons = getExternalizableConstructor(cl);
} else {
    cons = getSerializableConstructor(cl);
    writeObjectMethod = getPrivateMethod(cl, "writeObject",
        new Class<?>[] { ObjectOutputStream.class },
        Void.TYPE);
    readObjectMethod = getPrivateMethod(cl, "readObject",
        new Class<?>[] { ObjectInputStream.class },
        Void.TYPE);
    readObjectNoDataMethod = getPrivateMethod(
        cl, "readObjectNoData", null, Void.TYPE);
    hasWriteObjectData = (writeObjectMethod != null);
}
```
从上面这段源码中可以看出，在序列化（反序列化）的时候，ObjectOutputStream（ObjectInputStream）会寻找目标类中的私有的writeObject（readObject）方法，赋值给变量writeObjectMethod（readObjectMethod）。

下面再来看两段源码：

ObjectStreamClass类中的一个判断方法
```java
boolean hasWriteObjectMethod() {
    requireInitialized();
    return (writeObjectMethod != null);
}
```
ObjectOutputStream中的最终序列化对象的方法
```java
private void writeSerialData(Object obj, ObjectStreamClass desc)
    throws IOException
{
    ObjectStreamClass.ClassDataSlot[] slots = desc.getClassDataLayout();
    for (int i = 0; i < slots.length; i++) {
        ObjectStreamClass slotDesc = slots[i].desc;
        if (slotDesc.hasWriteObjectMethod()) {
            ...
            slotDesc.invokeWriteObject(obj, this);
            ...
        } else {
            defaultWriteFields(obj, slotDesc);
        }
    }
}
```
通过上面这两段代码可以知道，如果writeObjectMethod != null（目标类中定义了私有的writeObject方法），那么将调用目标类中的writeObject方法，如果如果writeObjectMethod == null，那么将调用默认的defaultWriteFields方法来读取目标类中的属性。

readObject的调用逻辑和writeObject一样。

总结一下，如果目标类中没有定义私有的writeObject或readObject方法，那么序列化和反序列化的时候将调用默认的方法来根据目标类中的属性来进行序列化和反序列化，而**如果目标类中定义了私有的writeObject或readObject方法，那么序列化和反序列化的时候将调用目标类指定的writeObject或readObject方法来实现**。
## 1.7 默认方法readResolve

readResolve方法和writeObject、readObject方法的实现过程不太一样，但是原理类似，也是可以在目标类中定义一个私有的readResolve方法，然后再反序列化的时候会被调用到。
通过下面的案例我们来看一下readObject方法和readResolve方法被调用的顺序：

```java
public class User implements Serializable {

    private static final long serialVersionUID = 1L;
    private String name;
    private String password;

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        System.out.println("readObject");
    }

    private Object readResolve() {
        System.out.println("readResolve");
        return new User(name, password);
    }
    ...
}
```
可以看出readResolve方法会在readObject之后调用，所以反序列化的时候readResolve方法会覆盖掉readObject方法的修改。
写个测试的Demo
User类：
```java




import lombok.Getter;
import lombok.Setter;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

@Getter
@Setter
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private transient String password;

    public User(String lebron, String s) {
        this.name = lebron;
        this.password = s;
    }
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        System.out.println("readObject");
    }
    private Object readResolve() {
        System.out.println("readResolve");
        return new User("name1", "passwd1");
    }
}

```
Test类
```java
import java.io.*;

public class TestUser {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        File file = new File("e:/user.txt");
        ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(file));
        outputStream.writeObject(new User("lebron", "123"));

        ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(file));
        User user = (User) inputStream.readObject();
        System.out.println(user.getName() +" : "+ user.getPassword());
    }
}

```
对应的输出，可以看到输出的结果在反序列的过程中，通过readResolve 方法复写了readobject的返回类。

![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/6d697b8a8c537186b650e07fccf762de.png)
正常的情况下应该是返回：  outputStream.writeObject(new User("lebron", "123"));

**PS：readResolve 方法和readObject 方法仅在反序列化的过程中生效，在序列化的过程中并不生效。**
测试下，测试的过程如下，将上述的序列化的文件重新读出来，注释掉readResolve的复写方法
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/6b01dd83ce12e827151c0c51832d0c5c.png)
![image.png](http://moonsec.top/articlepic/08618e81a636bb3792f177eb4d6e86b3.png)
执行结果：
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/718903ec97cfc4cb467c813f434dcb48.png)
输出的内容还是在序列化的过程中的复制的内容。

如果目标类中定义了私有的writeObject或readObject方法，那么序列化和反序列化的时候将通过反射调用目标类指定的writeObject或readObject方法来实现。

至于readResolve同样也是通过反射调用的。从内存中反序列化地"组装"一个新对象时，就会自动调用这个 readResolve方法来返回指定好的对象。从上面结果可以看到它是在readObject之后调用的，因此readResolve可以最终修改反序列化得到的对象。此种设计通常用来保证单例规则，防止序列化导致生成第二个对象的问题。
使用的demo 如下：
```java
public final class MySingleton implements Serializable{
    private MySingleton() { }
    private static final MySingleton INSTANCE = new MySingleton();
    public static MySingleton getInstance() { return INSTANCE; }
    private Object readResolve() throws ObjectStreamException {
       // instead of the object we're on,
       // return the class variable INSTANCE
      return INSTANCE;
   }
}

```


## 1.8 Externalizable接口

这里先来看一下Externalizable接口的源码
```java
public interface Externalizable extends java.io.Serializable {
    /**
     * by calling the methods of DataOutput for its primitive values or
     * calling the writeObject method of ObjectOutput for objects, strings, and arrays.
     */
    void writeExternal(ObjectOutput out) throws IOException;

    /**
     * The object implements the readExternal method to restore its
     * contents by calling the methods of DataInput for primitive
     * types and readObject for objects, strings and arrays.  The
     * readExternal method must read the values in the same sequence
     * and with the same types as were written by writeExternal.
     */
    void readExternal(ObjectInput in) throws IOException, ClassNotFoundException;
}
```
通过源码我们可以得出结论：
- Externalizable接口继承了Serializable接口，所以实现Externalizable接口也能实现序列化和反序列化。
- Externalizable接口中定义了writeExternal和readExternal两个抽象方法，通过注释，可以看出这两个方法其实对应Serializable接口的writeObject和readObject方法。

所以Externalizable接口被设计出来的目的就是为了抽象出writeObject和readObject这两个方法，但是目前这个接口使用的并不多。

# 2 fastjson
## 2.1 fastjson setter方法
fastjson在反序列化时会调用setter方法。不管这个方法你有没有进行设置。
ps对于可见变量fastjson会自动进行setter，对于private设置的变量不可以。
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/36bf1205b1a73995eab207edea58c8fd.png)

## 2.1 fastjson支持使用@type指定反序列化的目标类
fastjson 处理反序列化的方式主要有三种
- 1、Object obj = JSON.parse(jsonstr);
- 2、Object obj = JSON.parseObject(jsonstr, UserFastJson.class);
- 3、Object obj = JSON.parseObject(jsonstr);
测试下 这三个类型返回的区别：
demo：
```java




import lombok.Getter;
import lombok.Setter;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class UserFastJson implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private String password;
    private boolean sex;

    public UserFastJson(String lebron, String s) {
        this.name = lebron;
        this.password = s;
        System.out.println("UserFastJson construct include para");
    }

    public UserFastJson() {


        System.out.println("UserFastJson construct");
    }

    public String getName() {
        System.out.println("in getName");
        return name;
    }

    public void setName(String userName) {
        System.out.println("in setName:" + userName);
        this.name = userName;
    }

    public String getPassword() {
        System.out.println("in getPassword");
        return password;
    }

    public void setPassword(String password) {
        System.out.println("in setPassword:" + password);
        this.password = password;
    }

    public void setSex(boolean sex) {
        System.out.println("in setSex:" + sex);
        this.sex = sex;
    }

    public boolean getSex() {
        System.out.println("in getSex:");
       return sex;
    }

}

```
测试类：
```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class MySerialDemo {
    public static void main(String[] args) {
        String jsonstr = "{\"@type\":\"UserFastJson\",\"password\":\"123456\",\"name\":\"李四\",\"sex\":\"0\"}";
        try {
            System.out.println("===============JSON.parse(jsonstr)=========================");
           Object obj1= JSON.parse(jsonstr);
            System.out.println("===============JSON.parseObject(jsonstr)=========================");
           JSONObject obj2= JSON.parseObject(jsonstr);
            System.out.println("===============JSON.parseObject(jsonstr,UserFastJson.class)=========================");
           UserFastJson obj3= JSON.parseObject(jsonstr,UserFastJson.class);
//            System.out.println(user.getName());
        }catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }
}

```
输出的结果
```txt
===============JSON.parse(jsonstr)=========================
UserFastJson construct
in setPassword:123456
in setName:李四
in setSex:false
===============JSON.parseObject(jsonstr)=========================
UserFastJson construct
in setPassword:123456
in setName:李四
in setSex:false
in getName
in getPassword
in getSex:
===============JSON.parseObject(jsonstr,UserFastJson.class)=========================
UserFastJson construct
in setPassword:123456
in setName:李四
in setSex:false

```
从上述的执行情况可以看出，JSON.parseObject(jsonstr) 和 JSON.parseObject(jsonstr,UserFastJson.class)输出的结果一致，都是执行了构建器以及setter方法。
JSON.parseObject(jsonstr) 处理方式，不仅仅执行了构建器，还执行了所有的setter、getter方法。
**通过上文运行结果，不难发现有2个问题**
- 使用JSON.parse(jsonstr);与JSON.parseObject(jsonstr, UserFastJson.class);两种方式执行后的返回结果完全相同，且UserFastJson类中getter与setter方法调用情况也完全一致，parse(jsonstr)与parseObject(jsonstr, UserFastJson.class)有何关联呢？
- JSON.parseObject(jsonstr);为什么返回值为JSONObject类对象，且将FastJsonTest类中的所有getter与setter都被调用了
**问题一解答**
问题1：parse(jsonstr)与parseObject(jsonstr, UserFastJson.class)有何关联呢？
经过调试可以发现，无论使用JSON.parse(jsonstr);或是JSON.parseObject(jsonstr,UserFastJson.class);方式解析json字符串，程序最终都会调用位于com/alibaba/fastjson/util/JavaBeanInfo.java中的JavaBeanInfo.build()方法来获取并保存目标Java类中的成员变量以及其对应的setter、getter
首先来看下JSON.parse(jsonstr)这种方式，当程序执行到JavaBeanInfo.build()
方法时情景如下图
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/a62b7afbc9a631398c1595cb03590772.png)
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/02c5471e8ed39d9a2096e6f509a7f43f.png)

这两者完全一样，唯一的区别是在JSON.parseObject(jsonstr,UserFastJson.class); 传入了clazz
但是在获取jsonType 的值是都为null
  JSONType jsonType = (JSONType)clazz.getAnnotation(JSONType.class);
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/d8ca2ea49a4c017f90fc886fb600b691.png)
因此他们两个的调用过程是一致的。二者唯一的区别就是获取clazz参数的途径不同。
问题2：JSON.parseObject(jsonstr)为什么返回值为JSONObject类对象，且将FastJsonTest类中的所有getter与setter都被调用了？
JSON.parseObject(jsonstr)返回值为JSONObject类对象，且将FastJsonTest类中的所有getter与setter都被调用。
通过阅读源码可以发现JSON.parseObject(String text)实现如下
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/8d5597022b674f5e5af29d3f452682f1.png)
parseObject(String text)其实就是执行了parse(),随后将返回的Java对象通过JSON.toJSON（）转为
JSONObject对象。
JSON.toJSON（）方法会将目标类中所有getter方法记录下来，见下图
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/8fd35e10f560ca6800fccf1f6db02b0f.png)
总结：
上文例子中，JSON.parse(jsonstr)与JSON.parseObject(jsonstr, UserFastJson.class)可以认为是完全一样的，而parseObject(String text)是在二者的基础上又执行了一次JSON.toJSON（），获取了所有的getter方法。
因此打印的结果为先遍历所有的setter方法，然后再遍历getter方法。
parse(String text)、parseObject(String text)与parseObject(String text, Class<T> clazz)目标类SetterGetter调用情况

parse(String text)	parseObject(String text)	parseObject(String text, Class<T> clazz)
Setter调用情况	全部	全部	全部
Getter调用情况	部分	部分	全部
| -                                                            | parse(String text) | parseObject(String text) | parseObject(String text, Class<T> clazz) |
| ------------------------------------------------------------ | ------------------ | ------------------------ | ---------------------------------------- |
| Setter调用情况                                               | 全部               | 全部                     | 全部                                     |
| Getter调用情况                                               | 部分               | 部分                     | 全部                                     |
| ps：再调用定义private Properties方法的时候才会调getter。     |                    |                          |                                          |
| **此外**，如果目标类中私有变量没有setter方法，但是在反序列化时仍想给这个变量赋值，则需要使用Feature.SupportNonPublicField参数。（在下文中，为TemplatesImpl类中无setter方法的私有变量_tfactory以及_name赋值运用到的就是这个知识点） |                    |                          |                                          |

# 3 漏洞
如果在构建器或者getter setter方法中，存在恶意的方法，则会触发漏洞
```java
  System.err.println("Pwned");
        try {
                String[] cmd = {"calc"};
                java.lang.Runtime.getRuntime().exec(cmd).waitFor();
        } catch ( Exception e ) {
                e.printStackTrace();
        }
```
随意在一个getter or setter中设置恶意类，即可触发漏洞。
![image.png](https://gitee.com/shine05/myblog-gallery/raw/master/img/f6d82328c48f4554fd6cf809bb89b964.png)

## 3.1 漏洞利用
 正常代码中很难找到像Evil这种代码，攻击者要想办法通过现有的POJO类让JVM加载构造的恶意类，整个过程有点类似二进制攻击中的ROP技巧：先绕过fastjson的防御产生反序列化攻击，再通过中间的POJO类完成攻击链，这些POJO类即被称为Gadget。

在网上有很多的漏洞的利用链，此处就不在介绍了。

#参考
1、https://blog.csdn.net/Leon_cx/article/details/81517603
2、https://www.freebuf.com/vuls/228099.html